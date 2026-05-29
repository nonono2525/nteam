# A&D Defense Agent Progress Report

작성일: 2026-05-29

## 1. 긴급 방향 전환

기존에는 Team2 서비스의 `vuln_spec.json`과 선언된 취약 endpoint를 읽어 방어 판단을 만드는 방향으로 구현했다. 그러나 새로 공개된 룰 기준에서는 방어 대상이 우리 팀 서비스 하나가 아니라, 각 팀이 공통으로 만든 Obsidian vault 업로드 웹사이트의 기본 공격면이라는 점이 확인되었다.

이에 따라 방어 에이전트의 핵심 로직을 전면 수정했다.

현재 구현 방향은 다음과 같다.

- 특정 Team2 취약점 스펙에 의존하지 않는다.
- 서비스 코드는 수정하지 않는다.
- 제출 환경에서 전달되는 서비스 루트를 읽고 정적 분석한다.
- 배포 URL이 주어지면 안전한 정상 GET으로 런타임 가용성과 보안 헤더를 확인한다.
- Obsidian 업로드 서비스에서 공통적으로 위험한 공격면을 우선 점검한다.
- 로그가 있으면 라운드 중 실제 공격 흔적을 탐지한다.
- 결과는 JSON stdout과 Markdown report로 남긴다.

## 2. 지켜야 하는 규칙

현재 구현은 다음 제한을 기준으로 작성했다.

- 개인 API key를 코드에 넣지 않는다.
- `openrouter.ai`, `api.openai.com`, `api.anthropic.com`을 직접 호출하지 않는다.
- LLM 호출이 필요하더라도 coordinator가 주입한 `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL`만 사용해야 한다.
- 현재 flag 값을 코드나 리포트에 하드코딩하지 않는다.
- 서비스 배포 마감 이후 서비스 기능을 삭제하거나 endpoint를 없애는 방식으로 방어하지 않는다.
- 방어 에이전트는 서비스 코드를 직접 패치하지 않고, 분석과 판단을 수행한다.

## 3. 현재 구현 파일

주요 파일은 다음과 같다.

```text
defense_agent/main.py
defense/main.py
agent/main.py
rules/default_rules.yml
README.md
REPORT.md
```

`defense/main.py`와 `agent/main.py`는 제출 템플릿 및 기존 실행 경로와 호환되도록 wrapper로 두었고, 둘 다 `defense_agent.main:main`을 실행한다.

## 4. 방어 분석 로직

현재 `defense_agent/main.py`는 generic Obsidian upload defense mode로 동작한다.

분석하는 항목은 다음과 같다.

| Check ID | 목적 | 중요도 |
| --- | --- | --- |
| `upload_allowlist` | 업로드 허용 확장자와 위험 확장자 차단 여부 확인 | critical |
| `archive_safety` | ZIP/TAR 압축 해제 시 Zip Slip, symlink, zip bomb 방어 확인 | critical |
| `path_traversal` | 파일 조회/download endpoint에서 경로 조작 가능성 확인 | critical |
| `markdown_xss` | Markdown raw HTML, script, iframe, event handler sanitizer 확인 | critical |
| `obsidian_controls` | wikilink, embed, frontmatter, `.obsidian/plugins` 처리 확인 | high |
| `secret_file_protection` | `.env`, `flags.env`, private key, config file 노출 방지 확인 | critical |
| `authz_isolation` | vault/note/attachment owner check와 IDOR 방어 확인 | critical |
| `security_headers` | CSP, nosniff, referrer-policy 등 browser header 확인 | high |
| `debug_surface` | `/debug`, `/admin`, `/internal` 노출 여부 확인 | high |
| `resource_limits` | upload size, file count, parse timeout, rate limit 확인 | high |
| `llm_prompt_injection` | LLM note 분석 기능이 있을 때 prompt injection 위험 확인 | medium |
| `service_shape` | 분석 가능한 웹서비스 구조인지 확인 | low |

각 check는 `pass`, `attention`, `unknown`, `fail` 중 하나로 상태를 낸다. Critical 또는 high 항목에서 `attention`, `unknown`, `fail`이 나오면 report의 readiness에 반영된다.

추가로 `--base-url`이 들어오면 다음 runtime probe를 수행한다.

- `/` root page 응답 확인
- `/health` availability 응답 확인
- `/api/markdown/list`, `/api/markdown/interests`, `/api/markdown/patterns`, `/api/markdown/recommendations` 정상 GET 확인
- `/debug/state`, `/admin/check`가 공개 응답하는지 확인
- `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` 누락 여부 확인

이 probe는 공격 payload나 특수 우회 header를 보내지 않고, 정상 GET만 사용한다.
만약 agent 실행 환경에서 DNS/network가 막혀 있으면 이를 서비스 다운으로 단정하지 않고 `runtime_probe_limited`로 분리한다.

## 5. 공격/채점 흐름 반영

A&D 라운드에서는 먼저 서비스 가용성이 확인되고, 이후 제출된 PoC가 snapshot 기준으로 batch 실행된다. 따라서 방어 에이전트는 단순히 "취약해 보이는 코드"만 찾는 것이 아니라, 실제 채점에서 문제가 될 가능성이 큰 순서로 판단한다.

우선순위는 다음과 같다.

1. 가용성을 해칠 수 있는 upload size, zip bomb, heavy markdown render 위험
2. round snapshot에서 flag나 secret을 읽을 수 있는 path traversal, dotfile exposure, debug surface
3. PoC로 재현되기 쉬운 stored XSS, archive traversal, IDOR
4. 서비스별 기능 차이로 누락되기 쉬운 Obsidian-specific embed/plugin/frontmatter 처리

리포트 상단에는 `Emergency Strategy`를 둬서 라운드 중 바로 볼 수 있는 first action을 출력한다.

## 6. 로그 탐지 규칙

`rules/default_rules.yml`을 Obsidian 업로드 서비스 기준으로 교체했다.

탐지 항목은 다음과 같다.

| Rule ID | 탐지 내용 |
| --- | --- |
| `OBS-001` | vault path traversal probe |
| `OBS-002` | `.env`, `flags.env`, private key, `/etc/passwd` probe |
| `OBS-003` | Markdown XSS payload |
| `OBS-004` | Obsidian plugin/embed abuse |
| `OBS-005` | archive traversal, symlink, zip bomb signal |
| `OBS-006` | debug/admin/internal surface probe |
| `OBS-007` | Markdown SSRF/local URL probe |

실행 시 `--log /path/to/log`를 넘기면 agent가 로그를 읽고 active attack signal을 JSON과 Markdown report에 반영한다.

## 7. Hardening Policy

리포트에는 바로 참고할 수 있는 hardening policy JSON을 포함한다.

핵심 정책은 다음과 같다.

- 허용 확장자: `.md`, `.markdown`, `.txt`, `.zip`
- 차단 확장자: `.html`, `.htm`, `.svg`, `.js`, `.mjs`, `.py`, `.php`, `.sh`, `.exe`, `.dll`, `.so`, `.dylib`, `.env`
- 차단 파일명: `.env`, `flags.env`, `id_rsa`, `id_ed25519`, `config.yml`, `config.yaml`, `docker-compose.yml`
- archive limit: 파일 300개, 단일 파일 1MB, 전체 압축 해제 20MB, nested depth 1
- Markdown 차단 패턴: `<script`, `javascript:`, `data:text/html`, `onerror=`, `onload=`, `<iframe`, `<object`, `<embed`
- Obsidian 차단 경로: `.obsidian/plugins`, `.obsidian/workspace`, `.trash`
- 필수 보안 헤더: CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`

## 8. 실행 방법

기본 실행:

```bash
python3 defense/main.py --service-root /path/to/obsidian-upload-service
```

기존 wrapper 경로:

```bash
python3 agent/main.py --service-root /path/to/obsidian-upload-service
```

로그와 JSON 산출물 포함:

```bash
python3 defense_agent/main.py \
  --service-root /path/to/obsidian-upload-service \
  --base-url http://knights.hspace.io:42001/ \
  --log /path/to/access.log \
  --json-out /tmp/obsidian-defense.json
```

`--service-root`가 없으면 `SERVICE_ROOT`, `TEAM_PROJECT_ROOT`, `TARGET_SERVICE_ROOT`, `HSPACE_SERVICE_ROOT`, `/service`, `/app`, `/workspace/service` 등을 자동 탐색한다.

이번에 확인된 실제 배포 URL:

```text
http://knights.hspace.io:42001/
```

수동 확인 결과:

```text
/       -> Study Compass HTML 응답
/health -> {"status":"ok"}
```

## 9. 검증 결과

현재 실행한 검증:

```bash
python3 -m compileall agent defense defense_agent
python3 defense/main.py --service-root /Users/kim-yeseul/hspace-folder/team2 --base-url http://knights.hspace.io:42001/ --report-dir /private/tmp/obsidian-defense-live --json-out /private/tmp/obsidian-defense-live.json
```

확인 결과:

- Python compile 성공
- `defense/main.py`, `agent/main.py`, `defense_agent/main.py` entrypoint 구조 정상
- Team2 프로젝트를 샘플 서비스 루트로 읽어 generic Obsidian upload defense report 생성 성공
- JSON output 생성 성공
- Markdown report 생성 성공
- 서비스 코드 수정 없음

샘플 실행에서 나온 판단:

```text
mode: generic-obsidian-upload-defense
posture: hardening_needed
readiness: ready_with_hardening_gaps
```

샘플 first action:

```text
Reject .html/.svg/.js/.env/.py/.sh inside uploads and archives.
Replace bulk extraction with per-entry validation.
Add a safe_join helper around every read/download endpoints.
Turn off raw HTML in markdown renderer or add DOMPurify/bleach policy.
```

## 10. 현재 결론

방어 에이전트는 이제 새 룰에 맞게 공통 Obsidian vault upload 웹사이트를 방어 분석하는 형태로 전환되었다.

가장 중요한 변화는 Team2 전용 취약점 분석에서 벗어나, 업로드 서비스라면 공통으로 터질 수 있는 다음 공격면을 촘촘하게 보는 것이다.

- 위험 파일 업로드
- 안전하지 않은 archive extraction
- path traversal
- Markdown stored XSS
- Obsidian embed/plugin/frontmatter abuse
- dotfile/secret 노출
- vault owner check 누락
- debug/admin surface
- 가용성 저하 공격

남은 작업은 실제 제출 환경에서 service root와 log path가 어떻게 주입되는지 확인하고, 필요하면 environment variable 이름만 추가하는 것이다.
