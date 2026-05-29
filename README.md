# A&D Obsidian Upload Defense Agent

HSPACE A&D 라운드용 방어 에이전트입니다.

현재 구현은 특정 Team2 서비스의 `vuln_spec.json`을 방어하는 방식이 아니라, 각 팀이 공통으로 만든 Obsidian vault 업로드 웹사이트를 기준으로 동작합니다. 서비스 코드는 수정하지 않고, 제출 환경에서 주어진 서비스 디렉터리를 읽어 업로드, 압축 해제, Markdown 렌더링, 파일 접근, vault 소유권, 로그 공격 흔적을 분석합니다.

## Constraints

- 서비스 배포 마감 이후 서비스 코드를 임의 수정하지 않습니다.
- 개인 OpenAI/OpenRouter/Anthropic API key를 코드에 넣지 않습니다.
- public provider endpoint를 직접 호출하지 않습니다.
- LLM이 필요해도 coordinator가 주입한 `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL`만 사용해야 합니다.
- 현재 flag 값을 코드, 리포트, PoC에 하드코딩하지 않습니다.

## Run

```bash
python3 defense/main.py --service-root /path/to/obsidian-upload-service
python3 agent/main.py --service-root /path/to/obsidian-upload-service
python3 defense_agent/main.py --service-root /path/to/obsidian-upload-service
python3 defense_agent/main.py --service-root /path/to/obsidian-upload-service --log /path/to/access.log --json-out /tmp/obsidian-defense.json
python3 defense/main.py --service-root /path/to/obsidian-upload-service --base-url http://knights.hspace.io:42001/
```

`--service-root`를 생략하면 다음 환경변수와 일반적인 mount 경로를 순서대로 탐색합니다.

```text
SERVICE_ROOT
TEAM_PROJECT_ROOT
TARGET_SERVICE_ROOT
HSPACE_SERVICE_ROOT
/service
/app
/workspace/service
```

`--base-url`를 넘기면 배포된 서비스에 정상 GET만 보내서 root, `/health`, 주요 Markdown API, debug/admin 노출 여부, 보안 헤더 상태를 확인합니다. 공격 payload나 특수 header는 보내지 않습니다. 실행 환경의 DNS/network 제한으로 probe가 막히면 서비스 다운으로 단정하지 않고 `runtime_probe_limited`로 표시합니다.

coordinator가 알 수 없는 CLI 인자를 붙여도 agent가 즉시 죽지 않도록 unknown args는 무시합니다.

## Entrypoints

- `defense/main.py` - 제출 템플릿 호환 wrapper
- `agent/main.py` - 기존 실행 경로 호환 wrapper
- `defense_agent/main.py` - 실제 방어 분석 본체
- `rules/default_rules.yml` - Obsidian 업로드 서비스용 로그 탐지 규칙

세 entrypoint는 모두 같은 `defense_agent.main:main`을 실행합니다.

## What It Defends

공통 Obsidian 업로드 서비스에서 가장 위험한 경로를 우선 분석합니다.

- 업로드 allowlist와 위험 확장자 차단
- ZIP/TAR archive extraction 안전성
- Zip Slip, symlink, zip bomb 방어 조건
- path traversal과 안전한 파일 제공
- Markdown raw HTML, script, iframe, event handler, dangerous URL sanitizer
- Obsidian wikilink, embed, frontmatter, `.obsidian/plugins` 처리
- `.env`, `flags.env`, private key, config file 노출 방지
- vault/note/attachment owner check와 IDOR 방어
- CSP, nosniff, attachment download header
- `/debug`, `/admin`, `/internal` 노출 여부
- upload size, file count, render timeout, rate limit
- LLM 기반 note 분석이 있는 경우 prompt injection 위험

## Output

기본 실행 시 JSON을 stdout으로 출력하고, Markdown 리포트를 `defense_reports/`에 저장합니다.

리포트에는 다음 항목이 포함됩니다.

- 현재 posture와 readiness
- 라운드 중 먼저 봐야 할 emergency strategy
- critical/high gap 목록
- check별 evidence, required controls, immediate actions
- 로그 기반 공격 흔적
- 배포 URL runtime probe 결과
- 바로 적용 가능한 hardening policy JSON

## Log Detection Rules

`rules/default_rules.yml`은 다음 공격 흔적을 찾습니다.

- `../`, `%2e%2e` 기반 vault path traversal
- `.env`, `flags.env`, private key, `/etc/passwd` probe
- Markdown XSS payload
- `.obsidian/plugins`, `![[embed]]`, wikilink abuse
- archive traversal, symlink, zip bomb signal
- debug/admin/internal route probe
- markdown SSRF/local URL probe

## Current Direction

이 agent의 목적은 "우리 팀 서비스 전용 취약점 방어"가 아니라 "공통 Obsidian vault upload 서비스의 기본 공격면을 빠르게 점검하고, 라운드 중 방어 판단에 쓸 수 있는 리포트를 만드는 것"입니다.
