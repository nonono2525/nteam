# A&D Obsidian Upload Defense Agent

HSPACE A&D 라운드용 방어 에이전트입니다.

현재 구현은 특정 Team1 서비스의 `vuln_spec.json`을 방어하는 방식이 아니라, 각 팀이 공통으로 만든 Obsidian vault 업로드 웹사이트를 기준으로 동작합니다. 제출 환경에서 주어진 서비스 디렉터리를 읽어 업로드, 압축 해제, Markdown 렌더링, 파일 접근, vault 소유권, 로그 공격 흔적을 분석합니다.

이 README를 현재 agent 운영 규칙의 기준 문서로 둡니다. 구현 판단이 애매하면 아래 원칙을 우선합니다.

## Constraints

- 서비스 기능을 삭제하거나 endpoint를 없애는 패치는 하지 않습니다.
- 기능을 유지하면서 취약 조건만 무력화하는 패치는 허용합니다.
- 패치가 필요한 경우 사람의 수동 개입이 아니라 agent가 자동으로 판단하고 수행해야 합니다.
- agent가 API로 호출되면 실행 과정을 나중에 확인하기 어렵기 때문에, agent 실행 로그는 반드시 파일로 남깁니다.
- 개인 OpenAI/OpenRouter/Anthropic API key를 코드에 넣지 않습니다.
- public provider endpoint를 직접 호출하지 않습니다.
- LLM이 필요해도 coordinator가 주입한 `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL`만 사용해야 합니다.
- 허용 모델 제한이 있으므로 기본 LLM review 모델은 `google/gemini-2.0-flash-001`로 둡니다.
- 현재 flag 값을 코드, 리포트, PoC에 하드코딩하지 않습니다.

## Patch Policy

방어 patch는 "서비스를 없애서 막는 방식"이 아니라 "서비스는 그대로 살리고 위험 조건만 차단하는 방식"이어야 합니다.

허용되는 예:

- 업로드 파일 확장자와 파일명 denylist 추가
- ZIP entry별 path normalization, symlink 차단, size/count limit 추가
- Markdown sanitizer와 CSP 추가
- 파일 조회 시 safe path check와 owner/session check 추가
- debug/admin 응답에서 secret만 제거하거나 server-side auth 추가
- rate limit, timeout, request size limit 추가

금지되는 예:

- 업로드 기능 삭제
- Markdown preview 기능 삭제
- 파일 목록/상세 조회 endpoint 삭제
- 서비스가 정상 사용되지 않을 정도로 모든 요청 차단
- 현재 flag 값을 기준으로 한 임시 차단

## Mandatory Execution Logging

agent는 API runner에서 실행되므로 stdout만 믿으면 안 됩니다. 모든 실행은 JSONL 로그를 남깁니다.

기본 로그 위치:

```text
/tmp/hspace_defense_agent.jsonl
```

변경 방법:

```bash
python3 defense/main.py --agent-log /tmp/defense-agent.jsonl
AGENT_LOG_PATH=/tmp/defense-agent.jsonl python3 defense/main.py
HSPACE_AGENT_LOG_PATH=/tmp/defense-agent.jsonl python3 defense/main.py
```

로그에 남기는 내용:

- agent start/finish/error
- runner가 넘긴 argv와 unknown args
- service root, base URL, input log path
- posture/readiness
- critical/high gap
- report/json output path
- runtime probe 제한 여부

## LLM Model

대회 환경에서는 개인 API key를 넣지 않습니다. 모델 호출이 필요하면 coordinator가 주입한 wrapper URL만 사용합니다.

사용 모델:

```text
google/gemini-2.0-flash-001
```

실행 예:

```bash
MODEL=google/gemini-2.0-flash-001 \
ENABLE_LLM_REVIEW=1 \
python3 defense/main.py --service-root /path/to/obsidian-upload-service
```

또는 CLI로 명시:

```bash
python3 defense/main.py \
  --service-root /path/to/obsidian-upload-service \
  --llm-review \
  --model google/gemini-2.0-flash-001
```

주의:

- `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL`이 주입되어 있을 때만 LLM review가 실행됩니다.
- wrapper URL이 없으면 `skipped_no_wrapper`로 기록하고 agent 자체는 계속 동작합니다.
- `openrouter.ai`, `api.openai.com`, `api.anthropic.com` 직접 호출은 하지 않습니다.
- 모델이 가벼운 편이라 prompt는 짧은 JSON 요약과 4개 섹션 출력으로 제한합니다.

## Run

```bash
python3 defense/main.py --service-root /path/to/obsidian-upload-service --apply-patches
python3 agent/main.py --service-root /path/to/obsidian-upload-service --apply-patches
python3 defense_agent/main.py --service-root /path/to/obsidian-upload-service
python3 defense_agent/main.py --service-root /path/to/obsidian-upload-service --log /path/to/access.log --json-out /tmp/obsidian-defense.json
python3 defense/main.py --service-root /path/to/obsidian-upload-service --base-url http://knights.hspace.io:42001/
python3 defense/main.py --service-root /path/to/obsidian-upload-service --agent-log /tmp/defense-agent.jsonl
python3 defense/main.py --service-root /path/to/obsidian-upload-service --llm-review --model google/gemini-2.0-flash-001
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

## Automatic Patch Mode

agent는 공식 runner에서 `AGENT_RUN_ID`가 주입되면 자동으로 안전 패치 모드에 들어갑니다. 로컬 검증에서는 `--apply-patches`를 명시합니다.

```bash
python3 agent/main.py --service-root /path/to/service --apply-patches --no-push
```

패치 원칙:

- `/chat`, Markdown upload/list/preview 등 기존 기능과 endpoint를 삭제하지 않습니다.
- Team1의 flag 누출 sink는 응답에서 secret만 제거합니다.
- Obsidian ZIP 업로드는 유지하되, path traversal, dotfile, `.obsidian`, 위험 확장자, 과대 파일만 거절합니다.
- Markdown preview 기능은 유지하되, script/iframe/event handler/javascript URL은 sanitizer로 제거합니다.
- FastAPI 앱이면 CSP, nosniff, Referrer-Policy header middleware를 추가합니다.
- 패치 후 `main.py`, `scripts/md_parser.py` 문법 검사와 endpoint marker 검증을 통과하지 못하면 즉시 롤백합니다.
- 공식 runner에서 `AGENT_RUN_ID`가 있으면 `Agent-Run-ID` trailer가 붙은 커밋을 만들고 `git push`를 시도합니다.

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
- agent 실행 JSONL 로그 경로
- 선택 LLM review 모델과 결과
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


Agent 수정 / 빌드 안내 @here
공격/방어 agent를 수정한 팀은 아래 순서대로 확인하고 빌드해 주세요.
team1은 본인 팀 번호로 바꾸면 됩니다. 예: team2, team3

수정할 파일
기본 수정 위치:

attack_agent/main.py
defense_agent/main.py


공격 agent: attack_agent/main.py
방어 agent: defense_agent/main.py

파일 위치나 entrypoint를 바꿨다면 agent_manifest.json의 경로도 같이 수정해야 합니다.

entrypoint 확인
패키지 루트, 즉 user_deploy 폴더에서 실행합니다.

cd user_deploy

python scripts/gitctf.py agent doctor --mode attack
python scripts/gitctf.py agent doctor --mode defense


여기서 runner가 실행할 파일 경로가 의도한 main.py로 잡히는지 확인하세요.

agent 이미지 빌드
공격 agent만 빌드:

python scripts/gitctf.py agent build team1 --mode attack


방어 agent만 빌드:

python scripts/gitctf.py agent build team1 --mode defense


공격/방어 agent 둘 다 한 번에 빌드:

python scripts/gitctf.py agent build team1


빌드가 끝나면 아래 형태의 이미지가 생성됩니다.

and-attack-team1:latest
and-defense-team1:latest


꼭 지켜야 할 것
개인 OpenAI/OpenRouter API key를 코드에 넣지 마세요.
LLM 호출은 주입된 OPENAI_BASE_URL 또는 OPENROUTER_BASE_URL로만 보내세요.
공격 요청과 PoC 제출은 HSPACE_AGENT_BASE_URL의 /attack, /pocs wrapper로만 보내세요.
타겟 팀 IP/포트로 직접 공격 요청을 보내지 마세요.
PoC에 현재 flag 값을 하드코딩하지 마세요.

공식 실행
공식 라운드에서 agent 실행은 운영 서버가 자동으로 합니다.
참가자가 직접 agent run을 실행한 결과는 점수에 반영되지 않습니다.

공격 절대 사람이 하면 안됨(에이전트가 해야함)
PoC.py로 공격이 들어온다
기능 없애면 안됨
절대 없애면 안됨 기능 패치는 가능, 다만 패치할때 그렇게 진행되면 안됨.
유효한 poc를 보내면 됨
가용성 침해되면 -10점 
