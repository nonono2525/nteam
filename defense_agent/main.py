from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".svelte",
    ".html",
    ".css",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".md",
}

HIGH_RISK_UPLOAD_NAMES = (
    ".env",
    "flags.env",
    "id_rsa",
    "id_ed25519",
    "config.yml",
    "config.yaml",
    "docker-compose.yml",
)

DENY_UPLOAD_SUFFIXES = (
    ".html",
    ".htm",
    ".svg",
    ".js",
    ".mjs",
    ".py",
    ".php",
    ".sh",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".env",
)

LOG_ATTACK_PATTERNS = {
    "path_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e%252e)", re.I),
    "secret_file_probe": re.compile(r"(\.env|flags\.env|id_rsa|/etc/passwd|/proc/self/environ)", re.I),
    "xss_markdown": re.compile(r"(<script|javascript:|onerror=|onload=|<iframe|data:text/html)", re.I),
    "obsidian_embed_probe": re.compile(r"(!\[\[|\[\[.*\]\]|\.obsidian|plugins/)", re.I),
    "archive_traversal": re.compile(r"(zip|tar|7z).*(\.\./|\.\.\\|%2e%2e)", re.I),
    "debug_probe": re.compile(r"(/debug|/admin|/internal|x-debug|x-service-key)", re.I),
    "ssrf_probe": re.compile(r"(http://169\.254\.169\.254|file://|gopher://|ftp://|localhost|127\.0\.0\.1)", re.I),
}


@dataclass(frozen=True)
class StaticEvidence:
    file: str
    line: int
    text: str


@dataclass(frozen=True)
class DefenseCheck:
    check_id: str
    title: str
    severity: str
    status: str
    why_it_matters: str
    evidence: list[StaticEvidence] = field(default_factory=list)
    required_controls: list[str] = field(default_factory=list)
    immediate_actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LogFinding:
    category: str
    severity: str
    line_no: int
    line: str
    action: str


@dataclass(frozen=True)
class RuntimeEndpoint:
    path: str
    status: int | None
    ok: bool
    security_headers: dict[str, str]
    content_type: str
    body_signal: str
    error: str | None = None


@dataclass(frozen=True)
class RuntimeProbe:
    base_url: str
    reachable: bool
    health_ok: bool
    probe_limited: bool
    missing_security_headers: list[str]
    endpoints: list[RuntimeEndpoint]


@dataclass(frozen=True)
class LLMReview:
    enabled: bool
    model: str
    status: str
    base_url_source: str | None
    summary: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class PatchResult:
    applied: bool
    changed_files: list[str]
    actions: list[str]
    issues: list[str]
    committed: bool = False
    pushed: bool = False


@dataclass(frozen=True)
class DefenseReport:
    generated_at: str
    mode: str
    service_root: str
    base_url: str | None
    posture: str
    readiness: str
    strategy: dict[str, Any]
    static_checks: list[DefenseCheck]
    log_findings: list[LogFinding]
    runtime_probe: RuntimeProbe | None
    llm_review: LLMReview | None
    hardening_policy: dict[str, Any]
    patch_result: PatchResult | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generic defense agent for Obsidian vault upload web services"
    )
    parser.add_argument("--service-root", default=None, help="Service repository path")
    parser.add_argument("--base-url", default=None, help="Optional deployed service base URL")
    parser.add_argument("--log", default=None, help="Optional access/app log to inspect")
    parser.add_argument("--agent-log", default=None, help="JSONL agent execution log path")
    parser.add_argument("--model", default=None, help="Allowed LLM model for optional review")
    parser.add_argument("--llm-review", action="store_true", help="Ask injected LLM wrapper for a short defense review")
    parser.add_argument("--report-dir", default="defense_reports", help="Markdown report directory")
    parser.add_argument("--json-out", default=None, help="Optional JSON output path")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as high-priority")
    parser.add_argument("--apply-patches", action="store_true", help="Apply safe automatic patches before reporting")
    parser.add_argument("--no-push", action="store_true", help="Do not commit/push even when patches changed files")
    args, unknown = parser.parse_known_args()
    args.unknown_args = unknown
    return args


def main() -> None:
    args = parse_args()
    agent_log = AgentLogger(resolve_agent_log_path(args.agent_log))
    agent_log.write(
        "agent_start",
        argv=sys.argv[1:],
        unknown_args=args.unknown_args,
        cwd=str(Path.cwd()),
    )
    try:
        service_root = prepare_service_root(args.service_root, agent_log)
        base_url = args.base_url or os.environ.get("BASE_URL") or os.environ.get("SERVICE_BASE_URL") or os.environ.get("TARGET_BASE_URL")
        model = args.model or os.environ.get("MODEL") or "google/gemini-2.0-flash-001"
        llm_review_enabled = args.llm_review or os.environ.get("ENABLE_LLM_REVIEW") == "1"
        auto_patch = (
            args.apply_patches
            or os.environ.get("ENABLE_AUTO_PATCH") == "1"
            or bool(os.environ.get("AGENT_RUN_ID"))
        )
        agent_log.write(
            "context_resolved",
            service_root=str(service_root),
            base_url=base_url,
            input_log=args.log,
            strict=args.strict,
            model=model,
            llm_review_enabled=llm_review_enabled,
            auto_patch=auto_patch,
        )
        patch_result = None
        if auto_patch:
            patch_result = apply_safe_patches(service_root, agent_log)
            if patch_result.issues:
                agent_log.write("patch_failed", issues=patch_result.issues[:10])
                raise RuntimeError(f"automatic patch verification failed: {patch_result.issues[:3]}")
        report = build_report(
            service_root,
            Path(args.log).expanduser() if args.log else None,
            args.strict,
            base_url,
            model,
            llm_review_enabled,
            agent_log,
            patch_result,
        )
        report_path = write_markdown_report(Path(args.report_dir), report)
        output = report_to_json(report)
        output["report_path"] = str(report_path)
        output["agent_log_path"] = str(agent_log.path)
        agent_log.write(
            "report_generated",
            posture=report.posture,
            readiness=report.readiness,
            report_path=str(report_path),
            critical_gaps=report.strategy.get("critical_gaps", []),
            high_gaps=report.strategy.get("high_gaps", []),
            log_findings=len(report.log_findings),
            runtime_probe=report.strategy.get("runtime_reachable"),
            runtime_probe_limited=report.strategy.get("runtime_probe_limited"),
            llm_review_status=report.llm_review.status if report.llm_review else "not_requested",
            patch_applied=patch_result.applied if patch_result else False,
            patch_changed_files=patch_result.changed_files if patch_result else [],
        )
        if args.json_out:
            out = Path(args.json_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
            agent_log.write("json_written", path=str(out))
        agent_log.write("agent_finish", status="ok")
        print(json.dumps(output, ensure_ascii=False, indent=2))
        if patch_result and patch_result.changed_files and not args.no_push:
            final_patch_result = commit_and_push_patches(service_root, patch_result, agent_log)
            agent_log.write(
                "patch_commit_finish",
                committed=final_patch_result.committed,
                pushed=final_patch_result.pushed,
                changed_files=final_patch_result.changed_files,
            )
    except Exception as exc:
        agent_log.write("agent_error", error_type=type(exc).__name__, error=str(exc)[:500])
        raise


class AgentLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.path = Path(tempfile.gettempdir()) / "hspace_defense_agent.jsonl"
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> None:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError:
            fallback = Path(tempfile.gettempdir()) / "hspace_defense_agent.jsonl"
            with fallback.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
            self.path = fallback


def resolve_agent_log_path(cli_value: str | None) -> Path:
    raw = (
        cli_value
        or os.environ.get("AGENT_LOG_PATH")
        or os.environ.get("HSPACE_AGENT_LOG_PATH")
        or str(Path(tempfile.gettempdir()) / "hspace_defense_agent.jsonl")
    )
    return Path(raw).expanduser()


def resolve_service_root(cli_value: str | None) -> Path:
    candidates = [
        cli_value,
        os.environ.get("SERVICE_ROOT"),
        os.environ.get("TEAM_PROJECT_ROOT"),
        os.environ.get("TARGET_SERVICE_ROOT"),
        os.environ.get("HSPACE_SERVICE_ROOT"),
        os.getcwd(),
        "/service",
        "/app",
        "/workspace/service",
        "/Users/kim-yeseul/hspace-folder/team2",
    ]
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw).expanduser().resolve()
        if path.exists() and any((path / name).exists() for name in ("backend", "frontend", "src", "app", "Dockerfile")):
            return path
        if path.exists() and (path / "vuln_spec.json").exists():
            return path
    return Path.cwd().resolve()


def has_explicit_service_root(cli_value: str | None) -> bool:
    return bool(
        cli_value
        or os.environ.get("SERVICE_ROOT")
        or os.environ.get("TEAM_PROJECT_ROOT")
        or os.environ.get("TARGET_SERVICE_ROOT")
        or os.environ.get("HSPACE_SERVICE_ROOT")
    )


def repo_url_with_run_token(repo_url: str) -> str:
    token = os.environ.get("AGENT_RUN_TOKEN", "")
    parsed = urllib.parse.urlsplit(repo_url)
    if not token or parsed.scheme not in {"http", "https"} or parsed.username:
        return repo_url
    quoted = urllib.parse.quote(token, safe="")
    netloc = f"agent:{quoted}@{parsed.netloc}"
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def prepare_service_root(cli_value: str | None, agent_log: AgentLogger) -> Path:
    if has_explicit_service_root(cli_value):
        return resolve_service_root(cli_value)

    target_repo_url = os.environ.get("TARGET_REPO_URL", "").strip()
    run_id = os.environ.get("AGENT_RUN_ID", "").strip()
    if target_repo_url and run_id:
        safe_run_id = re.sub(r"[^A-Za-z0-9_.-]", "_", run_id)[:64] or "run"
        clone_root = Path(tempfile.gettempdir()) / f"hspace_target_repo_{safe_run_id}"
        try:
            if clone_root.exists():
                shutil.rmtree(clone_root)
            clone_url = repo_url_with_run_token(target_repo_url)
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(clone_root)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if clone.returncode == 0:
                agent_log.write("target_repo_cloned", path=str(clone_root))
                return resolve_service_root(str(clone_root))
            agent_log.write(
                "target_repo_clone_failed",
                returncode=clone.returncode,
                stderr=(clone.stderr or "")[-500:],
            )
        except Exception as exc:
            agent_log.write("target_repo_clone_exception", error=str(exc)[:500])

    return resolve_service_root(cli_value)


TEAM1_VULN_PATCHES = [
    (
        "vuln1_search_cache",
        "main.py",
        '''\
def _get_search_result(query: str) -> str:
    """검색 캐시 조회. inject로 오염된 캐시가 있으면 그것을 반환."""
    if _vuln_flags["vuln1"] and "vuln1" in _search_cache:
        # 오염된 캐시: flag가 숨겨진 검색 결과 반환
        return _search_cache["vuln1"]
    return f"'{query}'에 대한 일반 검색 결과입니다."''',
        '''\
def _get_search_result(query: str) -> str:
    """검색 캐시 조회. 일반 검색 결과만 반환한다."""
    return f"'{query}'에 대한 일반 검색 결과입니다."''',
    ),
    (
        "vuln2_memory_filter",
        "main.py",
        '''\
    elif "기록" in lower or "이전" in lower or "history" in lower:
        memories = "\\n".join(_session_memory)
        tool_calls.append({"tool": "recall_memory", "result": memories})
        response = f"기억하고 있는 내용:\\n{memories}" if memories else "저장된 기록이 없습니다."''',
        '''\
    elif "기록" in lower or "이전" in lower or "history" in lower:
        memories = "\\n".join(
            item for item in _session_memory
            if not item.startswith("[시스템 메모:")
        )
        tool_calls.append({"tool": "recall_memory", "result": memories})
        response = f"기억하고 있는 내용:\\n{memories}" if memories else "저장된 기록이 없습니다."''',
    ),
    (
        "vuln3_admin_todo_filter",
        "main.py",
        '''\
        if "다른 사용자" in lower or "모든" in lower or "admin" in lower:
            # 권한 체크 누락 — admin 데이터까지 반환
            all_todos = dict(_todo_db)
            tool_calls.append({"tool": "list_todos", "result": all_todos})
            response = f"전체 할 일: {all_todos}"''',
        '''\
        if "다른 사용자" in lower or "모든" in lower or "admin" in lower:
            all_todos = {key: value for key, value in _todo_db.items() if key != "admin"}
            tool_calls.append({"tool": "list_todos", "result": all_todos})
            response = f"전체 할 일: {all_todos}"''',
    ),
    (
        "vuln4_debug_secret_filter",
        "main.py",
        '''\
    elif "디버그" in lower or "debug" in lower or "툴 상태" in lower:
        debug_state = dict(_tool_debug_tokens)
        tool_calls.append({"tool": "debug_dump", "result": debug_state})
        response = f"디버그 툴 상태: {debug_state}"''',
        '''\
    elif "디버그" in lower or "debug" in lower or "툴 상태" in lower:
        debug_state = {
            key: value for key, value in _tool_debug_tokens.items()
            if key != "tool_secret"
        }
        tool_calls.append({"tool": "debug_dump", "result": debug_state})
        response = f"디버그 툴 상태: {debug_state}"''',
    ),
]


SECURITY_MIDDLEWARE = '''\

# HSPACE defense agent hardening: browser security headers.
@app.middleware("http")
async def _hspace_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response
'''


UPLOAD_GUARD_OLD = '''\
async def upload_markdown_zip(request: Request):
    file_name = request.headers.get("X-File-Name", "").strip()
    if file_name and not file_name.lower().endswith(".zip"):
        raise HTTPException(400, "ZIP 파일만 업로드할 수 있습니다.")

    raw_zip = await request.body()
    if not raw_zip:
        raise HTTPException(400, "업로드된 파일이 비어 있습니다.")

    entries = extract_md_entries(raw_zip)
    if not entries:
        raise HTTPException(400, "ZIP 안에 Markdown(.md) 파일이 없습니다.")'''

UPLOAD_GUARD_NEW = '''\
async def upload_markdown_zip(request: Request):
    file_name = request.headers.get("X-File-Name", "").strip()
    if file_name and not file_name.lower().endswith(".zip"):
        raise HTTPException(400, "ZIP 파일만 업로드할 수 있습니다.")

    max_zip_bytes = int(os.getenv("MAX_VAULT_ZIP_BYTES", "20000000"))
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_zip_bytes:
        raise HTTPException(413, "업로드 ZIP 크기가 너무 큽니다.")

    raw_zip = await request.body()
    if not raw_zip:
        raise HTTPException(400, "업로드된 파일이 비어 있습니다.")
    if len(raw_zip) > max_zip_bytes:
        raise HTTPException(413, "업로드 ZIP 크기가 너무 큽니다.")

    entries = extract_md_entries(raw_zip)
    entries = [entry for entry in entries if _hspace_safe_markdown_entry(entry)]
    if not entries:
        raise HTTPException(400, "ZIP 안에 안전한 Markdown(.md) 파일이 없습니다.")'''


SAFE_ENTRY_HELPER = '''\

# HSPACE defense agent hardening: keep upload/preview features while rejecting dangerous vault entries.
def _hspace_safe_markdown_entry(entry: dict) -> bool:
    rel_path = str(entry.get("rel_path") or entry.get("file_path") or "").replace("\\\\", "/")
    if not rel_path:
        return False
    parts = [part for part in rel_path.split("/") if part]
    lowered_parts = [part.lower() for part in parts]
    lowered_path = rel_path.lower()
    denied_names = {".env", "flags.env", "id_rsa", "id_ed25519", "config.yml", "config.yaml", "docker-compose.yml"}
    denied_dirs = {".obsidian", ".trash", "__macosx"}
    if rel_path.startswith("/") or any(part in {"..", "."} for part in parts):
        return False
    if any(part in denied_names for part in lowered_parts):
        return False
    if any(part in denied_dirs for part in lowered_parts):
        return False
    if not lowered_path.endswith((".md", ".markdown")):
        return False
    if len(parts) > 12 or len(rel_path) > 240:
        return False
    data = entry.get("bytes", b"")
    if isinstance(data, bytes) and len(data) > int(os.getenv("MAX_MARKDOWN_FILE_BYTES", "1000000")):
        return False
    return True
'''


def apply_safe_patches(service_root: Path, agent_log: AgentLogger) -> PatchResult:
    backups: dict[Path, str] = {}
    changed: list[str] = []
    actions: list[str] = []
    issues: list[str] = []

    def remember(path: Path) -> str:
        text = path.read_text(encoding="utf-8", errors="ignore")
        backups.setdefault(path, text)
        return text

    def write_if_changed(path: Path, before: str, after: str, action: str) -> None:
        if before == after:
            return
        path.write_text(after, encoding="utf-8")
        rel = str(path.relative_to(service_root)) if path.is_relative_to(service_root) else str(path)
        if rel not in changed:
            changed.append(rel)
        actions.append(action)
        agent_log.write("patch_applied", file=rel, action=action)

    main_py = service_root / "main.py"
    if main_py.exists():
        content = remember(main_py)
        patched = content
        for patch_id, _rel, old, new in TEAM1_VULN_PATCHES:
            if old in patched:
                patched = patched.replace(old, new, 1)
                actions.append(f"{patch_id}: exact patch")
            else:
                patched = apply_team1_fallback_patch(patch_id, patched, actions)
        if "app = FastAPI()" in patched and "_hspace_security_headers" not in patched:
            patched = patched.replace("app = FastAPI()", "app = FastAPI()" + SECURITY_MIDDLEWARE, 1)
        if UPLOAD_GUARD_OLD in patched and "_hspace_safe_markdown_entry" not in patched:
            insert_at = patched.find('@app.post("/api/markdown/upload")')
            if insert_at != -1:
                patched = patched[:insert_at] + SAFE_ENTRY_HELPER + "\n" + patched[insert_at:]
            patched = patched.replace(UPLOAD_GUARD_OLD, UPLOAD_GUARD_NEW, 1)
        write_if_changed(main_py, content, patched, "main.py safe response/upload/security hardening")

    parser_py = service_root / "scripts" / "md_parser.py"
    if parser_py.exists():
        content = remember(parser_py)
        patched = content
        if "def _sanitize_markdown_content(" not in patched:
            patched = patched.replace(
                "_KEYWORD_STOPWORDS = {",
                MARKDOWN_SANITIZER_HELPER + "\n\n_KEYWORD_STOPWORDS = {",
                1,
            )
        if 'content = file_bytes.decode("utf-8", errors="replace")' in patched and "_sanitize_markdown_content(content)" not in patched:
            patched = patched.replace(
                'content = file_bytes.decode("utf-8", errors="replace")',
                'content = _sanitize_markdown_content(file_bytes.decode("utf-8", errors="replace"))',
                1,
            )
        write_if_changed(parser_py, content, patched, "markdown sanitizer hardening")

    if changed:
        issues.extend(verify_patch_safety(service_root))
        if issues:
            for path, text in backups.items():
                path.write_text(text, encoding="utf-8")
            agent_log.write("patch_rollback", issues=issues[:10], files=changed)
            return PatchResult(False, [], actions, issues)
    return PatchResult(bool(changed), changed, actions, issues)


MARKDOWN_SANITIZER_HELPER = '''\
_HSPACE_DANGEROUS_MARKDOWN_RE = re.compile(
    r"(?is)<\\s*(script|iframe|object|embed|style|meta|link)[^>]*>.*?<\\s*/\\s*\\1\\s*>"
    r"|<\\s*(script|iframe|object|embed|style|meta|link)[^>]*?/?>"
    r"|\\s+on[a-z]+\\s*=\\s*(['\\\"]).*?\\3"
    r"|javascript\\s*:"
    r"|data\\s*:\\s*text/html"
)


def _sanitize_markdown_content(content: str) -> str:
    return _HSPACE_DANGEROUS_MARKDOWN_RE.sub("", content)
'''


def apply_team1_fallback_patch(patch_id: str, content: str, actions: list[str]) -> str:
    replacements = {
        "vuln2_memory_filter": (
            '        memories = "\\n".join(_session_memory)',
            '''\
        memories = "\\n".join(
            item for item in _session_memory
            if not item.startswith("[시스템 메모:")
        )''',
        ),
        "vuln3_admin_todo_filter": (
            "            all_todos = dict(_todo_db)",
            '            all_todos = {key: value for key, value in _todo_db.items() if key != "admin"}',
        ),
        "vuln4_debug_secret_filter": (
            "        debug_state = dict(_tool_debug_tokens)",
            '''\
        debug_state = {
            key: value for key, value in _tool_debug_tokens.items()
            if key != "tool_secret"
        }''',
        ),
    }
    if patch_id == "vuln1_search_cache" and 'return _search_cache["vuln1"]' in content:
        pattern = re.compile(
            r'def _get_search_result\(query: str\) -> str:\n'
            r'    """[^"]*"""\n'
            r'    if _vuln_flags\["vuln1"\] and "vuln1" in _search_cache:\n'
            r'        #[^\n]*\n'
            r'        return _search_cache\["vuln1"\]\n'
            r'    return f"\'\{query\}\'에 대한 일반 검색 결과입니다\."',
            re.MULTILINE,
        )
        patched, count = pattern.subn(TEAM1_VULN_PATCHES[0][3], content, count=1)
        if count:
            actions.append(f"{patch_id}: fallback function patch")
            return patched
    old_new = replacements.get(patch_id)
    if old_new and old_new[0] in content:
        actions.append(f"{patch_id}: fallback sink patch")
        return content.replace(old_new[0], old_new[1], 1)
    return content


def verify_patch_safety(service_root: Path) -> list[str]:
    issues: list[str] = []
    main_py = service_root / "main.py"
    if main_py.exists():
        text = main_py.read_text(encoding="utf-8", errors="ignore")
        for marker in [
            'return _search_cache["vuln1"]',
            'memories = "\\n".join(_session_memory)',
            "all_todos = dict(_todo_db)",
            "debug_state = dict(_tool_debug_tokens)",
        ]:
            if marker in text:
                issues.append(f"unsafe marker remains: {marker}")
        for marker in [
            '@app.post("/api/markdown/upload")',
            '@app.get("/api/markdown/list")',
            '@app.post("/api/markdown/preview")',
        ]:
            if marker not in text:
                issues.append(f"required endpoint marker missing: {marker}")
    for rel in ["main.py", "scripts/md_parser.py"]:
        path = service_root / rel
        if path.exists() and path.suffix == ".py":
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(path)],
                cwd=service_root,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                issues.append((result.stderr or result.stdout)[-500:])
    return issues


def commit_and_push_patches(service_root: Path, patch_result: PatchResult, agent_log: AgentLogger) -> PatchResult:
    run_id = os.environ.get("AGENT_RUN_ID", "")
    if not run_id:
        agent_log.write("patch_push_skipped", reason="missing_agent_run_id")
        return patch_result
    message = (
        "defense: auto harden obsidian upload service\n\n"
        + "\n".join(f"- {action}" for action in patch_result.actions[:12])
        + f"\n\nAgent-Run-ID: {run_id}"
    )
    try:
        subprocess.run(["git", "-C", str(service_root), "config", "user.name", "HSPACE Defense Agent"], check=False, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(service_root), "config", "user.email", "defense-agent@hspace.local"], check=False, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(service_root), "add", "-A"], check=True, capture_output=True, text=True)
        commit = subprocess.run(
            ["git", "-C", str(service_root), "commit", "-m", message],
            capture_output=True,
            text=True,
        )
        committed = commit.returncode == 0 or "nothing to commit" in (commit.stdout + commit.stderr)
        if not committed:
            agent_log.write("patch_commit_failed", stderr=commit.stderr[-500:], stdout=commit.stdout[-500:])
            return PatchResult(patch_result.applied, patch_result.changed_files, patch_result.actions, patch_result.issues, False, False)
        push = subprocess.run(["git", "-C", str(service_root), "push"], capture_output=True, text=True)
        pushed = push.returncode == 0
        if not pushed:
            agent_log.write("patch_push_failed", stderr=push.stderr[-500:], stdout=push.stdout[-500:])
        return PatchResult(patch_result.applied, patch_result.changed_files, patch_result.actions, patch_result.issues, committed, pushed)
    except Exception as exc:
        agent_log.write("patch_commit_exception", error=str(exc)[:500])
        return PatchResult(patch_result.applied, patch_result.changed_files, patch_result.actions, patch_result.issues, False, False)


def build_report(
    service_root: Path,
    log_path: Path | None,
    strict: bool,
    base_url: str | None,
    model: str,
    llm_review_enabled: bool,
    agent_log: AgentLogger | None = None,
    patch_result: PatchResult | None = None,
) -> DefenseReport:
    files = collect_text_files(service_root)
    checks = build_static_checks(service_root, files, strict)
    log_findings = inspect_log(log_path) if log_path else []
    runtime_probe = inspect_runtime(base_url) if base_url else None
    policy = hardening_policy()
    posture = posture_from_checks(checks, log_findings, runtime_probe)
    readiness = readiness_from_checks(checks, log_findings, runtime_probe)
    strategy = build_strategy(checks, log_findings, policy, runtime_probe)
    llm_review = build_llm_review(
        llm_review_enabled,
        model,
        strategy,
        checks,
        log_findings,
        runtime_probe,
        agent_log,
    )
    return DefenseReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        mode="generic-obsidian-upload-defense",
        service_root=str(service_root),
        base_url=base_url,
        posture=posture,
        readiness=readiness,
        strategy=strategy,
        static_checks=checks,
        log_findings=log_findings,
        runtime_probe=runtime_probe,
        llm_review=llm_review,
        hardening_policy=policy,
        patch_result=patch_result,
    )


def collect_text_files(root: Path) -> dict[Path, list[str]]:
    result: dict[Path, list[str]] = {}
    skip_dirs = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "dist",
        "build",
        "docs",
        "tests",
        "scripts",
        "coverage",
    }
    skip_names = {
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "README.md",
        "USER_DEPLOY_GUIDE.md",
        "vuln_spec.json",
        "vuln_spec.json.starter",
        "task.md",
    }
    for path in root.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.name in skip_names:
            continue
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            result[path] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
    return result


def build_static_checks(
    service_root: Path, files: dict[Path, list[str]], strict: bool
) -> list[DefenseCheck]:
    return [
        check_upload_allowlist(files, strict),
        check_archive_extraction(files, strict),
        check_path_traversal(files, strict),
        check_markdown_sanitization(files, strict),
        check_obsidian_specific_controls(files, strict),
        check_secret_file_protection(files, strict),
        check_authz_isolation(files, strict),
        check_security_headers(files, strict),
        check_debug_surface(files, strict),
        check_rate_limit_and_size(files, strict),
        check_llm_prompt_injection(files, strict),
        check_expected_service_shape(service_root, strict),
    ]


def check_upload_allowlist(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(
        files,
        [
            r"allowed(_|\s)?extensions",
            r"content[-_]?type",
            r"mime",
            r"\.md",
            r"\.markdown",
            r"UploadFile",
            r"multer",
        ],
    )
    status = status_by_evidence(evidence, strict)
    return DefenseCheck(
        "upload_allowlist",
        "Upload allowlist and dangerous extension blocking",
        "critical",
        status,
        "Obsidian vault upload is the main attack entry. Unsafe extensions can become XSS, RCE, or secret exfiltration paths.",
        evidence,
        [
            "Allow only .md, .markdown, .txt, and optionally .zip after safe extraction checks.",
            f"Deny executable or browser-active suffixes: {', '.join(DENY_UPLOAD_SUFFIXES)}.",
            "Validate MIME and file magic; do not trust filename or Content-Type alone.",
        ],
        [
            "Reject .html/.svg/.js/.env/.py/.sh inside uploads and archives.",
            "Store uploads outside the web root under generated server-side names.",
        ],
    )


def check_archive_extraction(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"zipfile", r"tarfile", r"extractall", r"unzip", r"archive"])
    has_danger = bool(find_patterns(files, [r"extractall\s*\(", r"\.extract\s*\("]))
    status = "fail" if has_danger else status_by_evidence(evidence, strict)
    return DefenseCheck(
        "archive_safety",
        "Archive extraction safety",
        "critical",
        status,
        "Vault uploads are often zip files. Zip Slip, symlinks, nested archives, and zip bombs can write outside the vault or exhaust resources.",
        evidence,
        [
            "Never call extractall on untrusted archives.",
            "Normalize every archive member and reject absolute paths, '..', drive letters, symlinks, and hardlinks.",
            "Enforce max files, max single file bytes, max total uncompressed bytes, and max depth.",
        ],
        [
            "Replace bulk extraction with per-entry validation.",
            "Reject nested .zip/.tar/.7z unless explicitly supported with depth limits.",
        ],
    )


def check_path_traversal(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(
        files,
        [r"resolve\(", r"realpath", r"normpath", r"safe_join", r"\.\.", r"send_file", r"FileResponse"],
    )
    danger = find_patterns(files, [r"send_file\s*\([^)]*(filename|path|file)", r"open\s*\([^)]*(filename|path|file)"])
    status = "attention" if danger else status_by_evidence(evidence, strict)
    return DefenseCheck(
        "path_traversal",
        "Path traversal and safe file serving",
        "critical",
        status,
        "Markdown viewers and file download endpoints are natural IDOR/path traversal targets.",
        evidence[:8] + danger[:8],
        [
            "Map file IDs to database records or a vault manifest; do not accept raw paths from users.",
            "Use Path.resolve and verify the result stays under the vault root.",
            "Deny dotfiles and high-risk names regardless of path normalization.",
        ],
        ["Add a safe_join helper around every read/download endpoint."],
    )


def check_markdown_sanitization(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(
        files,
        [r"sanitize", r"bleach", r"DOMPurify", r"markdown", r"marked", r"rehype-sanitize", r"escape"],
    )
    danger = find_patterns(files, [r"dangerouslySetInnerHTML", r"innerHTML", r"v-html"])
    status = "fail" if danger and not evidence else status_by_evidence(evidence, strict)
    return DefenseCheck(
        "markdown_xss",
        "Markdown and HTML sanitization",
        "critical",
        status,
        "Obsidian markdown can contain raw HTML, links, embeds, and attributes that become stored XSS.",
        evidence[:10] + danger[:10],
        [
            "Render markdown through a sanitizer allowlist.",
            "Block raw HTML or sanitize tags/attributes/protocols.",
            "Deny javascript:, data:text/html, event handlers, iframe, object, embed, script, style.",
        ],
        ["Turn off raw HTML in markdown renderer or add DOMPurify/bleach policy."],
    )


def check_obsidian_specific_controls(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"\[\[", r"!\[\[", r"\.obsidian", r"frontmatter", r"yaml", r"embed"])
    status = status_by_evidence(evidence, strict)
    return DefenseCheck(
        "obsidian_controls",
        "Obsidian-specific vault controls",
        "high",
        status,
        "Obsidian has wikilinks, embeds, frontmatter, plugin folders, and attachment conventions that can bypass generic upload checks.",
        evidence,
        [
            "Reject .obsidian/plugins, workspace files, hidden folders, and plugin JavaScript.",
            "Resolve wikilinks and ![[embeds]] only through the sanitized vault manifest.",
            "Treat YAML frontmatter as data only; never use it for templates, redirects, or shell paths.",
        ],
        ["Add manifest-based link resolution for [[note]] and ![[file]] references."],
    )


def check_secret_file_protection(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"\.env", r"secret", r"token", r"flag", r"private", r"deny"])
    status = status_by_evidence(evidence, strict)
    return DefenseCheck(
        "secret_file_protection",
        "Secret and dotfile protection",
        "critical",
        status,
        "Attackers will try to upload, list, or download .env, flag, token, and key files.",
        evidence,
        [
            f"Always deny exact high-risk names: {', '.join(HIGH_RISK_UPLOAD_NAMES)}.",
            "Never return environment variables, config, debug state, or local filesystem listings.",
            "Redact secrets from logs and reports.",
        ],
        ["Add deny rules before any preview/download/list response."],
    )


def check_authz_isolation(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"user_id", r"session", r"owner", r"auth", r"jwt", r"cookie", r"vault_id"])
    status = status_by_evidence(evidence, strict)
    return DefenseCheck(
        "authz_isolation",
        "Per-user vault isolation and IDOR defense",
        "critical",
        status,
        "Every vault, note, and attachment must be scoped to the owner. Guessable IDs leak other teams' uploaded vault contents.",
        evidence,
        [
            "Every list/read/download/delete path must check owner/team/session.",
            "Use unguessable IDs; do not expose raw filesystem paths.",
            "Treat X-Forwarded-For and client supplied local/admin headers as untrusted.",
        ],
        ["Audit all endpoints that accept vault_id, file_id, filename, path, session_id, or user_id."],
    )


def check_security_headers(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"Content-Security-Policy", r"X-Content-Type-Options", r"frame-ancestors", r"nosniff"])
    status = status_by_evidence(evidence, strict)
    return DefenseCheck(
        "security_headers",
        "Browser security headers",
        "high",
        status,
        "Even sanitized markdown can miss a payload. CSP and nosniff reduce impact of stored XSS and content confusion.",
        evidence,
        [
            "Set Content-Security-Policy with default-src 'self' and script-src 'self'.",
            "Set X-Content-Type-Options: nosniff.",
            "Serve downloaded attachments as application/octet-stream with Content-Disposition: attachment unless preview is sanitized.",
        ],
        ["Add middleware for CSP, nosniff, referrer-policy, and frame-ancestors."],
    )


def check_debug_surface(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"/debug", r"/admin", r"/internal", r"DEBUG", r"print\(.*secret", r"traceback"])
    status = "attention" if evidence else "pass"
    return DefenseCheck(
        "debug_surface",
        "Debug/admin/internal surface",
        "high",
        status,
        "Debug endpoints often leak flags, upload paths, environment variables, or internal cache state.",
        evidence,
        [
            "Disable debug endpoints in production.",
            "Require server-side auth for admin routes.",
            "Do not trust client headers such as X-Debug-Token or X-Forwarded-For for admin access.",
        ],
        ["Search for /debug, /admin, internal state dumps, and env echo endpoints."],
    )


def check_rate_limit_and_size(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"max(_|-)?size", r"limit", r"rate", r"slowapi", r"MAX_CONTENT_LENGTH", r"bodyLimit"])
    status = status_by_evidence(evidence, strict)
    return DefenseCheck(
        "resource_limits",
        "Upload size, parse time, and request rate limits",
        "high",
        status,
        "Large vaults, zip bombs, and repeated render requests can take the service down before PoC scoring even starts.",
        evidence,
        [
            "Limit request body size, per-file size, total vault size, number of files, render time, and markdown length.",
            "Rate-limit upload, preview, analysis, and search endpoints per team/session/IP.",
            "Timeout markdown parsing and archive scanning.",
        ],
        ["Add size and count limits before reading entire upload bodies into memory."],
    )


def check_llm_prompt_injection(files: dict[Path, list[str]], strict: bool) -> DefenseCheck:
    evidence = find_patterns(files, [r"openai", r"openrouter", r"anthropic", r"chat/completions", r"LLM", r"prompt"])
    status = "attention" if evidence else "pass"
    return DefenseCheck(
        "llm_prompt_injection",
        "LLM analysis prompt-injection safety",
        "medium",
        status,
        "If uploaded notes are summarized by an LLM, note content can instruct the model to leak secrets or ignore rules.",
        evidence,
        [
            "Treat uploaded note content as untrusted data in prompts.",
            "Never include flags, API keys, or server env in LLM context.",
            "Use only injected OPENROUTER_BASE_URL/OPENAI_BASE_URL wrapper endpoints.",
        ],
        ["Wrap note content in clear data delimiters and add refusal instructions for secret exfiltration."],
    )


def check_expected_service_shape(service_root: Path, strict: bool) -> DefenseCheck:
    exists = [name for name in ("backend", "frontend", "src", "app", "Dockerfile") if (service_root / name).exists()]
    status = "pass" if exists else ("attention" if strict else "unknown")
    evidence = [StaticEvidence(str(service_root), 0, "found: " + ", ".join(exists))] if exists else []
    return DefenseCheck(
        "service_shape",
        "Expected web service shape",
        "low",
        status,
        "The agent needs enough local service structure to run static checks.",
        evidence,
        ["Run from the service repository or pass --service-root."],
        ["If this is a container, mount the service repository into the agent runtime."],
    )


def find_patterns(files: dict[Path, list[str]], patterns: list[str]) -> list[StaticEvidence]:
    compiled = [re.compile(pattern, re.I) for pattern in patterns]
    hits: list[StaticEvidence] = []
    for path, lines in files.items():
        for idx, line in enumerate(lines, 1):
            if any(pattern.search(line) for pattern in compiled):
                hits.append(StaticEvidence(str(path), idx, line.strip()[:220]))
                if len(hits) >= 20:
                    return hits
    return hits


def status_by_evidence(evidence: list[StaticEvidence], strict: bool) -> str:
    if evidence:
        return "attention"
    return "fail" if strict else "unknown"


def inspect_log(log_path: Path) -> list[LogFinding]:
    if not log_path.exists():
        return [
            LogFinding(
                "log_missing",
                "low",
                0,
                str(log_path),
                "Provide --log with access/app logs to detect active exploitation attempts.",
            )
        ]
    findings: list[LogFinding] = []
    for idx, line in enumerate(log_path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        for category, pattern in LOG_ATTACK_PATTERNS.items():
            if pattern.search(line):
                findings.append(
                    LogFinding(
                        category=category,
                        severity="high" if category != "debug_probe" else "medium",
                        line_no=idx,
                        line=line.strip()[:500],
                        action=response_for_log_category(category),
                    )
                )
    return findings


def inspect_runtime(base_url: str | None) -> RuntimeProbe | None:
    if not base_url:
        return None
    normalized = normalize_base_url(base_url)
    paths = [
        "/",
        "/health",
        "/api/markdown/list",
        "/api/markdown/interests",
        "/api/markdown/patterns",
        "/api/markdown/recommendations",
        "/debug/state",
        "/admin/check",
    ]
    endpoints = [fetch_runtime_endpoint(normalized, path) for path in paths]
    reachable = any(endpoint.status is not None for endpoint in endpoints)
    probe_limited = not reachable and all(is_probe_environment_error(endpoint.error) for endpoint in endpoints)
    health = next((endpoint for endpoint in endpoints if endpoint.path == "/health"), None)
    health_ok = bool(health and health.ok and "ok" in health.body_signal.lower())
    root = next((endpoint for endpoint in endpoints if endpoint.path == "/"), None)
    header_source = root or health
    required_headers = hardening_policy()["required_headers"]
    missing_headers = []
    if header_source and reachable:
        present = {name.lower() for name in header_source.security_headers}
        missing_headers = [
            name for name in required_headers if name.lower() not in present
        ]
    return RuntimeProbe(
        base_url=normalized,
        reachable=reachable,
        health_ok=health_ok,
        probe_limited=probe_limited,
        missing_security_headers=missing_headers,
        endpoints=endpoints,
    )


def build_llm_review(
    enabled: bool,
    model: str,
    strategy: dict[str, Any],
    checks: list[DefenseCheck],
    findings: list[LogFinding],
    runtime_probe: RuntimeProbe | None,
    agent_log: AgentLogger | None,
) -> LLMReview | None:
    if not enabled:
        return None
    wrapper_base, source = resolve_llm_wrapper_base()
    if not wrapper_base:
        return LLMReview(
            enabled=True,
            model=model,
            status="skipped_no_wrapper",
            base_url_source=None,
            error="OPENROUTER_BASE_URL or OPENAI_BASE_URL was not injected",
        )
    prompt = build_llm_review_prompt(strategy, checks, findings, runtime_probe)
    if agent_log:
        agent_log.write("llm_review_start", model=model, base_url_source=source)
    try:
        summary = call_llm_review(wrapper_base, model, prompt)
        if agent_log:
            agent_log.write("llm_review_finish", status="ok", chars=len(summary))
        return LLMReview(
            enabled=True,
            model=model,
            status="ok",
            base_url_source=source,
            summary=summary,
        )
    except Exception as exc:
        if agent_log:
            agent_log.write("llm_review_finish", status="error", error=str(exc)[:500])
        return LLMReview(
            enabled=True,
            model=model,
            status="error",
            base_url_source=source,
            error=str(exc)[:500],
        )


def resolve_llm_wrapper_base() -> tuple[str | None, str | None]:
    if os.environ.get("OPENROUTER_BASE_URL"):
        return os.environ["OPENROUTER_BASE_URL"].rstrip("/"), "OPENROUTER_BASE_URL"
    if os.environ.get("OPENAI_BASE_URL"):
        return os.environ["OPENAI_BASE_URL"].rstrip("/"), "OPENAI_BASE_URL"
    return None, None


def build_llm_review_prompt(
    strategy: dict[str, Any],
    checks: list[DefenseCheck],
    findings: list[LogFinding],
    runtime_probe: RuntimeProbe | None,
) -> str:
    critical = [check for check in checks if check.severity == "critical"]
    high = [check for check in checks if check.severity == "high"]
    payload = {
        "role": "defense_agent_review",
        "rules": [
            "Do not remove features or endpoints.",
            "Prefer small patches that keep upload, preview, list, and analysis features working.",
            "Never hardcode current flags.",
            "Assume patches must be performed by the agent, not by a human operator.",
            "Return concise Korean output.",
        ],
        "strategy": {
            "first_actions": strategy.get("first_actions", [])[:6],
            "critical_gaps": strategy.get("critical_gaps", []),
            "high_gaps": strategy.get("high_gaps", []),
            "runtime_probe_limited": strategy.get("runtime_probe_limited"),
        },
        "runtime": {
            "base_url": runtime_probe.base_url if runtime_probe else None,
            "reachable": runtime_probe.reachable if runtime_probe else None,
            "health_ok": runtime_probe.health_ok if runtime_probe else None,
            "probe_limited": runtime_probe.probe_limited if runtime_probe else None,
        },
        "critical_checks": [compact_check(check) for check in critical],
        "high_checks": [compact_check(check) for check in high],
        "log_findings": [asdict(finding) for finding in findings[:8]],
    }
    return (
        "You are a CTF A&D defense agent reviewer. "
        "The model may be lightweight, so follow the JSON data literally. "
        "Output exactly four short Korean sections: "
        "1) 현재 판단 2) 먼저 할 자동 패치 3) 기능 유지 주의점 4) 로그로 확인할 것.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )


def compact_check(check: DefenseCheck) -> dict[str, Any]:
    return {
        "id": check.check_id,
        "severity": check.severity,
        "status": check.status,
        "actions": check.immediate_actions[:2],
        "evidence": [
            {"file": ev.file, "line": ev.line, "text": ev.text[:120]}
            for ev in check.evidence[:3]
        ],
    }


def call_llm_review(wrapper_base: str, model: str, prompt: str) -> str:
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You produce concise defensive engineering advice. Never suggest feature deletion.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 900,
    }
    request = urllib.request.Request(
        f"{wrapper_base}/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.loads(response.read().decode("utf-8", errors="ignore"))
    return str(data["choices"][0]["message"]["content"]).strip()


def normalize_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url if "://" in base_url else f"http://{base_url}")
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""
    return urllib.parse.urlunparse((scheme, netloc, path.rstrip("/"), "", "", ""))


def fetch_runtime_endpoint(base_url: str, path: str) -> RuntimeEndpoint:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "hspace-defense-agent/1.0",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=4) as response:
            body = response.read(2048)
            headers = dict(response.headers.items())
            status = int(response.status)
            return RuntimeEndpoint(
                path=path,
                status=status,
                ok=200 <= status < 400,
                security_headers=extract_security_headers(headers),
                content_type=headers.get("Content-Type", ""),
                body_signal=safe_body_signal(body, headers.get("Content-Type", "")),
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(1024)
        headers = dict(exc.headers.items())
        return RuntimeEndpoint(
            path=path,
            status=int(exc.code),
            ok=False,
            security_headers=extract_security_headers(headers),
            content_type=headers.get("Content-Type", ""),
            body_signal=safe_body_signal(body, headers.get("Content-Type", "")),
            error=f"http_{exc.code}",
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return RuntimeEndpoint(
            path=path,
            status=None,
            ok=False,
            security_headers={},
            content_type="",
            body_signal="",
            error=str(exc)[:180],
        )


def is_probe_environment_error(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return any(
        marker in lowered
        for marker in (
            "nodename nor servname",
            "name or service not known",
            "temporary failure in name resolution",
            "network is unreachable",
            "operation not permitted",
        )
    )


def extract_security_headers(headers: dict[str, str]) -> dict[str, str]:
    wanted = {
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
        "x-frame-options",
        "permissions-policy",
    }
    return {
        name: value
        for name, value in headers.items()
        if name.lower() in wanted
    }


def safe_body_signal(body: bytes, content_type: str) -> str:
    text = body.decode("utf-8", errors="ignore").strip()
    if not text:
        return ""
    compact = re.sub(r"\s+", " ", text)
    if "text/html" in content_type.lower():
        title = re.search(r"<title[^>]*>(.*?)</title>", compact, re.I)
        if title:
            return f"title={title.group(1)[:120]}"
    return compact[:220]


def response_for_log_category(category: str) -> str:
    return {
        "path_traversal": "Block request, inspect file-serving endpoint, and verify safe_join/owner checks.",
        "secret_file_probe": "Block request and confirm dotfile/secret filename denylist.",
        "xss_markdown": "Quarantine uploaded note and verify markdown sanitizer/CSP.",
        "obsidian_embed_probe": "Resolve embeds through manifest only; reject .obsidian plugin paths.",
        "archive_traversal": "Quarantine archive and inspect extractor for Zip Slip.",
        "debug_probe": "Disable debug/admin routes or require server-side auth.",
        "ssrf_probe": "Deny remote URL fetches from markdown unless strict allowlist is present.",
    }.get(category, "Investigate and apply the matching hardening control.")


def hardening_policy() -> dict[str, Any]:
    return {
        "allowed_upload_suffixes": [".md", ".markdown", ".txt", ".zip"],
        "denied_upload_suffixes": list(DENY_UPLOAD_SUFFIXES),
        "denied_exact_names": list(HIGH_RISK_UPLOAD_NAMES),
        "archive_limits": {
            "max_files": 300,
            "max_single_file_bytes": 1_000_000,
            "max_total_uncompressed_bytes": 20_000_000,
            "max_nested_depth": 1,
        },
        "markdown_deny_patterns": [
            "<script",
            "javascript:",
            "data:text/html",
            "onerror=",
            "onload=",
            "<iframe",
            "<object",
            "<embed",
        ],
        "obsidian_deny_paths": [".obsidian/plugins", ".obsidian/workspace", ".trash"],
        "required_headers": {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    }


def posture_from_checks(
    checks: list[DefenseCheck], findings: list[LogFinding], runtime_probe: RuntimeProbe | None
) -> str:
    if runtime_probe and runtime_probe.probe_limited:
        return "runtime_probe_limited"
    if runtime_probe and not runtime_probe.reachable:
        return "service_unreachable"
    if any(f.severity == "high" for f in findings):
        return "active_attack_signals"
    if runtime_probe and runtime_probe.missing_security_headers:
        return "runtime_hardening_needed"
    if any(c.status == "fail" and c.severity == "critical" for c in checks):
        return "critical_controls_missing"
    if any(c.status in {"fail", "attention"} for c in checks if c.severity in {"critical", "high"}):
        return "hardening_needed"
    return "baseline_ready"


def readiness_from_checks(
    checks: list[DefenseCheck], findings: list[LogFinding], runtime_probe: RuntimeProbe | None
) -> str:
    if runtime_probe and runtime_probe.probe_limited:
        return "ready_runtime_probe_limited"
    if runtime_probe and not runtime_probe.reachable:
        return "not_ready_service_unreachable"
    if runtime_probe and not runtime_probe.health_ok:
        return "runtime_attention_health_endpoint"
    critical_failures = [c.check_id for c in checks if c.status == "fail" and c.severity == "critical"]
    if critical_failures:
        return "not_ready_critical_controls_missing"
    if findings:
        return "runtime_attention_active_signals"
    if any(c.status in {"attention", "unknown"} for c in checks if c.severity in {"critical", "high"}):
        return "ready_with_hardening_gaps"
    return "ready"


def build_strategy(
    checks: list[DefenseCheck],
    findings: list[LogFinding],
    policy: dict[str, Any],
    runtime_probe: RuntimeProbe | None,
) -> dict[str, Any]:
    critical = [c for c in checks if c.severity == "critical" and c.status in {"fail", "attention", "unknown"}]
    high = [c for c in checks if c.severity == "high" and c.status in {"fail", "attention", "unknown"}]
    first_actions = []
    if runtime_probe and runtime_probe.probe_limited:
        first_actions.append("Runtime URL probe was limited by the agent environment; verify availability from the scoring network.")
    elif runtime_probe and not runtime_probe.reachable:
        first_actions.append("Restore deployed service reachability before the scoring availability check.")
    elif runtime_probe and not runtime_probe.health_ok:
        first_actions.append("Fix /health or equivalent availability endpoint before round-end scoring.")
    if runtime_probe and runtime_probe.missing_security_headers:
        first_actions.append(
            "Add missing browser security headers: "
            + ", ".join(runtime_probe.missing_security_headers)
            + "."
        )
    if findings:
        first_actions.append("Quarantine suspicious uploads referenced in logs and block matching requests.")
    first_actions.extend(action for check in critical[:4] for action in check.immediate_actions[:1])
    if not first_actions:
        first_actions.append("Keep upload allowlist, safe extraction, sanitization, and owner checks enabled.")
    return {
        "one_line": "Defend the common Obsidian upload surface first: upload validation, archive extraction, markdown rendering, path access, and vault ownership.",
        "first_actions": dedupe(first_actions),
        "critical_gaps": [f"{c.check_id}:{c.status}" for c in critical],
        "high_gaps": [f"{c.check_id}:{c.status}" for c in high],
        "active_log_findings": len(findings),
        "runtime_reachable": runtime_probe.reachable if runtime_probe else None,
        "runtime_health_ok": runtime_probe.health_ok if runtime_probe else None,
        "runtime_probe_limited": runtime_probe.probe_limited if runtime_probe else None,
        "runtime_missing_headers": runtime_probe.missing_security_headers if runtime_probe else [],
        "drop_in_policy": policy,
    }


def write_markdown_report(report_dir: Path, report: DefenseReport) -> Path:
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        report_dir = Path(tempfile.gettempdir()) / "defense_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"obsidian_defense_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md"
    lines = [
        "# Obsidian Upload Defense Report",
        "",
        f"- generated_at: `{report.generated_at}`",
        f"- service_root: `{report.service_root}`",
        f"- base_url: `{report.base_url or 'not supplied'}`",
        f"- posture: `{report.posture}`",
        f"- readiness: `{report.readiness}`",
        "",
        "## Model",
        "",
    ]
    if report.llm_review:
        lines.extend(
            [
                f"- enabled: `{report.llm_review.enabled}`",
                f"- model: `{report.llm_review.model}`",
                f"- status: `{report.llm_review.status}`",
                f"- wrapper_source: `{report.llm_review.base_url_source or 'none'}`",
                "",
            ]
        )
        if report.llm_review.summary:
            lines.extend(["LLM review:", "", report.llm_review.summary, ""])
        elif report.llm_review.error:
            lines.extend([f"- error: `{report.llm_review.error}`", ""])
    else:
        lines.extend(["- llm_review: `not requested`", ""])
    lines.extend(["## Patch Result", ""])
    if report.patch_result:
        lines.extend(
            [
                f"- applied: `{report.patch_result.applied}`",
                f"- committed: `{report.patch_result.committed}`",
                f"- pushed: `{report.patch_result.pushed}`",
                f"- changed_files: `{', '.join(report.patch_result.changed_files) or 'none'}`",
                "",
                "Actions:",
                *[f"- {item}" for item in report.patch_result.actions or ["none"]],
                "",
                "Issues:",
                *[f"- {item}" for item in report.patch_result.issues or ["none"]],
                "",
            ]
        )
    else:
        lines.extend(["- patch mode: `not enabled`", ""])
    lines.extend(
        [
        "## Emergency Strategy",
        "",
        f"- {report.strategy['one_line']}",
        "",
        "First actions:",
        *[f"- {item}" for item in report.strategy["first_actions"]],
        "",
        "Critical gaps:",
        *[f"- {item}" for item in report.strategy["critical_gaps"] or ["none"]],
        "",
        "High gaps:",
        *[f"- {item}" for item in report.strategy["high_gaps"] or ["none"]],
        "",
        ]
    )
    lines.extend(
        [
        "## Runtime Probe",
        "",
        ]
    )
    if report.runtime_probe:
        lines.extend(
            [
                f"- base_url: `{report.runtime_probe.base_url}`",
                f"- reachable: `{report.runtime_probe.reachable}`",
                f"- health_ok: `{report.runtime_probe.health_ok}`",
                f"- probe_limited: `{report.runtime_probe.probe_limited}`",
                f"- missing_security_headers: `{', '.join(report.runtime_probe.missing_security_headers) or 'none'}`",
                "",
                "| path | status | ok | content_type | signal |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for endpoint in report.runtime_probe.endpoints:
            signal = endpoint.error or endpoint.body_signal.replace("|", "\\|")
            lines.append(
                f"| `{endpoint.path}` | `{endpoint.status}` | `{endpoint.ok}` | `{endpoint.content_type}` | {signal[:180]} |"
            )
        lines.append("")
    else:
        lines.extend(["- no base URL supplied", ""])
    lines.extend(
        [
        "## Static Checks",
        "",
        ]
    )
    for check in report.static_checks:
        lines.extend(
            [
                f"### {check.check_id} - {check.title}",
                "",
                f"- severity: `{check.severity}`",
                f"- status: `{check.status}`",
                f"- why: {check.why_it_matters}",
                "",
                "Required controls:",
                *[f"- {item}" for item in check.required_controls],
                "",
                "Immediate actions:",
                *[f"- {item}" for item in check.immediate_actions],
                "",
                "Evidence:",
            ]
        )
        if check.evidence:
            lines.extend(f"- `{ev.file}:{ev.line}` {ev.text}" for ev in check.evidence[:8])
        else:
            lines.append("- none found")
        lines.append("")
    lines.extend(["## Log Findings", ""])
    if report.log_findings:
        for finding in report.log_findings:
            lines.extend(
                [
                    f"- `{finding.category}` severity=`{finding.severity}` line=`{finding.line_no}`",
                    f"  - {finding.line}",
                    f"  - action: {finding.action}",
                ]
            )
    else:
        lines.append("- no log findings supplied/detected")
    lines.extend(
        [
            "",
            "## Drop-in Hardening Policy",
            "",
            "```json",
            json.dumps(report.hardening_policy, ensure_ascii=False, indent=2),
            "```",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def report_to_json(report: DefenseReport) -> dict[str, Any]:
    return asdict(report)


def dedupe(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


if __name__ == "__main__":
    main()
