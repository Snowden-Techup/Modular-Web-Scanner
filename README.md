# 🎯 Modular Web Scanner
### **Python 비동기 I/O 아키텍처**를 기반으로 개발된 **모듈형 웹 취약점 스캐너 CLI 솔루션**

대상 웹 애플리케이션을 자동으로 크롤링하여 파라미터와 폼 등 공격 표면(Attack Surface)을 수집하고 다종의 보안 취약점을 병렬로 정밀 진단합니다.

사용자가 터미널 환경의 **CLI** 또는 [snowden-backend](https://github.com/Snowden-Techup/snowden-backend) 기반의 **웹 UI**를 통해 편리하게 스캔을 트리거하고 결과를 조회할 수 있는 고성능 실전형 퍼징 엔진입니다.

> **법적·윤리적 고지**
> 본 도구는 **본인이 소유하거나 명시적 서면 허가를 받은 시스템**에서만 사용하세요. 무단 스캔은 불법일 수 있습니다. 교육·연구·침투 테스트 계약 범위 내에서만 사용하시기 바랍니다.

---

## 👥 팀원 소개

| 이름 | 역할 |
| :---: | :---: |
| **김진우(팀장)** | PM / 퍼저 엔진 / 공격 모듈 개발 담당 |
| **강제윤** | 크롤러 / 파서 / 공격 모듈 개발 담당 |
| **이시은** | 파서 / 공격 모듈 개발 담당 |
| **허윤** | 공격 모듈 개발 담당 |

---

## 🛠️ 기술 스택

| 분류 | 기술 스택 | 설명 |
| :---: | :--- | :--- |
| **Language** | ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) | 프로젝트 핵심 개발 언어 |
| **Asynchronous** | ![asyncio](https://img.shields.io/badge/asyncio-3776AB?style=flat-square&logo=python&logoColor=white) | 비동기 이벤트 루프 기반의 동시성 제어 (병목 최소화) |
| **Network** | ![aiohttp](https://img.shields.io/badge/aiohttp-2C5BB4?style=flat-square&logo=python&logoColor=white) | 수많은 공격 페이로드를 동시에 전송하는 비동기 통신 |
| **Parsing** | ![BeautifulSoup4](https://img.shields.io/badge/BeautifulSoup4-4B8BBE?style=flat-square&logo=python&logoColor=white) | 크롤링한 HTML 원문에서 폼(Form), 파라미터 등 숨겨진 공격 표면(Attack Surface) 추출 |
| **Parsing** | ![Regex](https://img.shields.io/badge/Regex-4B8BBE?style=flat-square) | 응답 데이터(Response)에서 SQL 에러 시그니처, 취약점 징후 등을 빠르고 정밀하게 탐지 |
| **Package** | ![PyPI](https://img.shields.io/badge/PyPI-3775A9?style=flat-square&logo=pypi&logoColor=white) | 외부 패키지 및 의존성 관리 |
| **VCS** | ![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white) | 코드 형상 관리 및 브랜치(이슈) 기반 협업 |

---

## ⚙️ 주요 기능

| 영역 | 설명 |
| :---: | --- |
| **크롤러** | `CrawlerEngine`이 시작 URL부터 링크를 따라가며 `QueueManager`에 페이지를 넣고, 깊이·URL 수·지연·타임아웃·워커 수 등 `CrawlConfig`로 조절합니다. |
| **파서 / 공격 표면** | `SurfaceBuilder`가 큐에서 HTML을 소비해 `AttackSurface` 목록을 생성합니다. 결과는 `--surfaces-output`(기본 attack_surfaces.json)으로 보낼 수 있습니다. |
| **URL 필터** | `URLFilter`로 크롤링 대상을 제한하고, `--exclude-urls`로 정규식 패턴 목록을 넘기면 크롤러·세션에 주입됩니다. |
| **인증** | `--login-url`, `--username`, `--password` 및 폼 필드명으로 로그인 후 크롤링할 수 있습니다. `-c` / `--cookie`로 세션 쿠키를 직접 줄 수도 있습니다. |
| **퍼저** | `FuzzerEngine`이 모듈별 페이로드를 큐에 넣고 `aiohttp`로 요청을 보냅니다. RPS(`-r`), 워커 수(`-w`, 0이면 자동), 세션 풀(`--session-pool-size`)로 부하를 조절합니다. |
| **진단 모듈** | **SQLi**, **브루트포스**, **LFI**, **파일 업로드**, **OSCI**, **XSS(Stored, Reflected)**, **SSRF** (`fuzzer/setup.py` 기준). `-t all`은 브루트포스를 제외한 나머지를 순차 실행합니다. |
| **리포트** | 콘솔 요약 + JSON (`-o`, 기본 `scan_report.json`). 중복 제거·정렬 등은 `reporter` 패키지에서 처리합니다. |
| **웹 UI** | [snowden-backend](https://github.com/Snowden-Techup/snowden-backend) 레포지토리를 통해 FastAPI 기반 웹 대시보드를 제공합니다. 스캔 시작, 진행 상태 모니터링, 결과 조회를 지원합니다. |

---

## 🧩 설치 방법

#### 요구 사항
- **Python 3.10+** 권장
  *(Windows 환경에서 Python 3.13+ 사용 시 발생할 수 있는 asyncio 관련 경고 억제 코드가 `main.py`에 포함되어 있습니다.)*

#### 주요 서드파티 패키지: **`aiohttp`**, **`beautifulsoup4`**, **`fastapi`**, **`pydantic`**, **`uvicorn`**

```bash
pip install aiohttp beautifulsoup4 lxml fastapi pydantic uvicorn
```

---

## 🚀 사용 방법

### 1. CLI 스캔 모드

```bash
# 저장소 루트에서
python main.py -u http://127.0.0.1/DVWA -t all
```

### 2. 웹 UI

웹 UI는 [snowden-backend](https://github.com/Snowden-Techup/snowden-backend) 레포지토리를 통해 제공됩니다.

### CLI 옵션 요약

#### 공통

| 옵션 | 설명 |
|------|------|
| `-u`, `--url` | **필수.** 스캔 대상 베이스 URL (예: DVWA 루트). |
| `-t`, `--type` | `sqli` \| `osci` \| `bruteforce` \| `lfi` \| `file_upload` \| `ssrf` \| `stored_xss` \| `reflected_xss` \| `all` (기본: `all`). `all`은 **브루트포스를 제외**한 나머지 모듈을 순차 실행. |
| `-r`, `--rps` | 초당 요청 상한 (기본 100). |
| `-w`, `--workers` | 큐 워커 수 (0이면 RPS 기반 자동). |
| `-c`, `--cookie` | 쿠키 헤더 문자열 (예: `PHPSESSID=...; security=low`). |
| `-o`, `--output` | 스캔 리포트 JSON 경로 (기본 `scan_report.json`). |
| `--surfaces-output` | 크롤링된 공격 표면 JSON (기본 `attack_surfaces.json`). |
| `--session-pool-size` | 병렬 HTTP 세션 수 (기본 3). |
| `--level N` | SQLi·OSCi·LFI·SSRF 회피 레벨을 한 번에 `N`(0–3)으로 설정. SSRF는 최대 2. 설정 시 개별 `--*-evasion-level`을 덮어씀. 브루트포스·XSS에는 적용되지 않음. |
| `--exclude-urls` | 크롤·공격에서 제외할 URL **정규식** 패턴 (공백으로 여러 개). |

#### 인증 (크롤 전 로그인)

| 옵션 | 설명 |
|------|------|
| `--login-url` | 로그인 페이지 URL (예: `http://target/login.php`). |
| `--username`, `--password` | 로그인 계정. |
| `--username-field`, `--password-field` | 폼 필드명 (기본 `username` / `password`). |
| `--csrf-field` | CSRF 토큰 필드명 (기본 `user_token`). |
| `--submit-field` | 제출 필드명 (기본 `Login`). |

#### 모듈별 옵션

| 모듈 | 옵션 | 설명 |
|------|------|------|
| **SQLi** | `--sqli-evasion-level` | 회피 강도 0–3 (기본 0). |
| | `--sqli-time-based` | time/stacked 페이로드 포함 (느림). |
| | `--sqli-time-max` | time 페이로드 상한 (0=전체). |
| **OSCi** | `--osci-evasion-level` | 회피 강도 0–3 (기본 0). |
| | `--osci-time-based` | time-based 지연 페이로드 포함. |
| | `--osci-time-max` | time 페이로드 상한 (0=전체). |
| | `--target-os` | `linux` \| `windows` \| `all` (기본 `linux`). |
| **LFI** | `--lfi-evasion-level` | 변형 레벨 0–3 (기본 1). |
| **SSRF** | `--ssrf-evasion-level` | 변형 레벨 0–2 (기본 1). |
| | `--ssrf-oob` | OOB/템플릿 페이로드 추가. |
| **Stored XSS** | `--sxss-evasion-level` | 변형 레벨 0–3 (기본 1). |
| **Reflected XSS** | `--rxss-evasion-level` | 변형 레벨 0–3 (기본 1). |
| **파일 업로드** | — | 모듈 전용 CLI 플래그 없음 (`-t file_upload`). |

#### 브루트포스

| 옵션 | 설명 |
|------|------|
| `--bf-wordlist` | 워드리스트 경로 (기본 `config/payloads/bruteforce/common_passwords.txt`). |
| `--bf-disable-mutation` | 사전 모드에서 비밀번호 돌연변이 비활성화. |
| `--bf-mutation-level` | 돌연변이 강도 0–3 (기본 1). |
| `--bf-true-random` | true-random 전용 모드 (사전 비활성화). |
| `--bf-charset` | true-random 문자 집합. |
| `--bf-min-length`, `--bf-max-length` | true-random 길이 범위. |
| `--bf-length` | 길이 또는 범위 (`8` → 1~8, `2~8`). `--bf-max-length`보다 우선. |
| `--bf-max-dictionary`, `--bf-max-true-random` | 페이로드 상한 (0=전체). |
| `--bf-stop-on-first-hit` / `--no-bf-stop-on-first-hit` | 첫 자격 증명 성공 시 중단 (기본: 활성). |
| `--bf-target-url` | 단일 대상 URL. |
| `--bf-method` | `GET` \| `POST` (기본 `GET`). |
| `--bf-fuzz-param` | FUZZ로 치환할 파라미터 (기본 `password`). |
| `--bf-target-param` | 대상 파라미터 강제 지정 (생략 시 자동 선택). |
| `--bf-username-param`, `--bf-username` | 사용자명 파라미터·값 (기본 `username` / `admin`). |
| `--bf-extra-params` | 고정 파라미터 `KEY=VALUE` (여러 개). |

`--bf-target-url`을 생략하면 `-u`로 크롤한 표면에서 `BruteforceModule` 휴리스틱으로 대상을 고릅니다.

전체 옵션은 다음으로 확인할 수 있습니다.

```bash
python main.py -h
```

---

## 📂 디렉터리 구조

```
├── main.py                  # CLI 진입점 (asyncio)
├── cli/                     # 인자 파싱, 서피스 해석, 실행·출력
├── core/                    # AttackSurface 등 공통 모델, 큐
├── crawler/                 # 크롤러 엔진, 세션, URL 필터
├── parsers/                 # HTML 파싱, 링크·폼 추출, SurfaceBuilder
├── fuzzer/                  # FuzzerEngine, 요청 빌더
├── modules/                 # 취약점 진단 공격 모듈
├── config/payloads/         # 모듈별 페이로드·워드리스트
├── reporter/                # 리포트 생성·중복 제거
└── utils/                   # 로거, 뮤테이터 등
```

---

## 🔗 CI/CD 파이프라인 연동

GitHub Actions를 통해 PR·Push 시 자동으로 DAST 스캔을 실행할 수 있습니다.

### 📌 0단계: 사전 준비

스캐너 이미지는 **Private**으로 관리됩니다. GitHub Actions에서 Pull할 수 있도록 **권한 요청**이 필요합니다.

스캐너 팀에 전달할 정보:

- 타겟 레포 주소 (프론트/백엔드 분리 시 백엔드 레포 주소만 전달)
- 요청 권한: `modular-web-scanner` 패키지 **Read** 권한

> ✅ 권한 부여 완료 회신을 받은 후 다음 단계를 진행하세요.

---

### 📌 1단계: Repository 권한 설정

PR 자동 생성이 일어나는 레포지토리(단일 레포 또는 백엔드 레포)에서 설정합니다.

`Settings` → `Actions` → `General`

- **Workflow permissions** → `Read and write permissions` 선택
- `Allow GitHub Actions to create and approve pull requests` 체크 → **Save**

---

### 📌 2단계: Secrets 등록

`Settings` → `Secrets and variables` → `Actions` → `New repository secret`

> ⚠️ 로그인 정보를 yml 파일에 평문으로 적지 마세요. 반드시 Secrets로 등록 후 참조해야 레포 히스토리에 영구 노출되지 않습니다.

#### 공통 Secrets (타겟 레포 또는 백엔드 레포에 등록)

| Secret 이름 | 설명 |
|-------------|------|
| `SLACK_WEBHOOK_URL` | Slack 알림 웹훅 URL |
| `SCAN_TEST_USERNAME` | 인증 스캔용 테스트 계정 ID |
| `SCAN_TEST_PASSWORD` | 인증 스캔용 테스트 계정 비밀번호 |

#### 프론트/백엔드 분리 환경 추가 설정

**PAT (Personal Access Token) 발급:**

`GitHub` → `Settings` → `Developer settings` → `Personal access tokens` → `Tokens (classic)`
→ `repo` 권한 체크 → 생성 → 토큰값 복사

| 레포 | Secret 이름 | 용도 |
|------|-------------|------|
| 프론트엔드 | `FRONTEND_ACCESS_TOKEN` | 백엔드 파이프라인 원격 트리거 |
| 백엔드 | `FRONTEND_ACCESS_TOKEN` | 프론트엔드 코드 Clone |

> ⚠️ PAT는 양쪽 레포 모두에 접근 가능한 계정으로 발급하세요.

#### 🔔 Slack 웹훅 발급 절차

1. [https://api.slack.com/apps](https://api.slack.com/apps) → `Create New App` → `From scratch`
2. 좌측 `Incoming Webhooks` → **On** → `Add New Webhook to Workspace`
3. 채널 선택 → 발급된 URL 복사 → Secrets에 등록

---

### 📌 3단계: Workflow YAML 추가

#### A. 단일 레포 환경

`.github/workflows/security-scan.yml` 생성 후 본인 환경에 맞게 수정:

```yaml
# ① 앱 실행 명령어
- name: Build and Start Target App
  run: |
    docker compose up -d --build   # npm start, python manage.py runserver 등

# ② Health Check (포트/경로 수정)
- name: Wait for Target to be Healthy
  run: |
    timeout 30 bash -c 'until curl -s -f -o /dev/null http://127.0.0.1:3000/health; do sleep 2; done'

# ③ 스캐너 실행 (URL, 인증정보, 모듈 수정)
- name: Run DAST Scanner
  run: |
    docker run --rm --network host \
      -v ${{ github.workspace }}:/reports \
      -e WAF_FUZZER_ALLOW_PRIVATE_TARGETS=true \
      ghcr.io/snowden-techup/modular-web-scanner:develop \
      python main.py -u "http://127.0.0.1:3000/" \
        --output /reports/scan_report.json \
        --login-url "http://127.0.0.1:3000/login" \
        --username "${{ secrets.SCAN_TEST_USERNAME }}" \
        --password "${{ secrets.SCAN_TEST_PASSWORD }}" \
        --username-field "username" \
        --password-field "password" \
        -t sqli -r 50 -w 5 \
        --sqli-evasion-level 0 --target-dbms mysql
```

#### B. 프론트/백엔드 분리 환경

**[프론트엔드 레포]** `.github/workflows/trigger-dast.yml`

```yaml
name: Trigger Backend DAST Scan

on:
  push:
    branches: ["main"]

jobs:
  trigger-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: peter-evans/repository-dispatch@v3
        with:
          token: ${{ secrets.FRONTEND_ACCESS_TOKEN }}
          repository: <조직명>/<백엔드_레포명>
          event-type: frontend-updated
```

**[백엔드 레포]** `.github/workflows/auto-scan.yml`

```yaml
on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]
  repository_dispatch:
    types: [frontend-updated]     # 프론트엔드 레포의 event-type과 반드시 동일

jobs:
  dast-scan:
    runs-on: ubuntu-latest
    steps:
      # 백엔드 코드 Checkout
      - name: Checkout Backend Repository
        uses: actions/checkout@v4

      # 프론트엔드 코드 Checkout
      - name: Checkout Frontend Repository
        uses: actions/checkout@v4
        with:
          repository: <조직명>/<프론트엔드_레포명>
          path: frontend-repo
          token: ${{ secrets.FRONTEND_ACCESS_TOKEN }}

      # 이후 앱 실행 / Health Check / 스캐너 실행은 단일 레포(A)와 동일
```

> ⚠️ 프론트엔드 YAML의 `event-type` 값과 백엔드 YAML의 `types` 값이 **반드시 동일**해야 신호가 정상 수신됩니다.

> 💡 `docker-compose.yml`에서 프론트엔드 빌드 컨텍스트를 `./frontend-repo`로 참조하도록 구성하세요.

#### 이미지 태그 가이드

| 태그 | 용도 |
|------|------|
| `:develop` | 현재 권장 ✅ |
| `:latest` | 안정화 후 프로덕션 |
| `:sha-xxxxxxx` | 특정 커밋 고정 (디버깅용) |

---

### 📌 4단계: 결과 확인

| 항목 | 확인 위치 |
|------|-----------|
| 워크플로우 실행 | `Actions` 탭 → 최근 실행 |
| 스캔 리포트 | 실행 결과 하단 `Artifacts` → ZIP 다운로드 |
| Slack 알림 | 등록한 채널에서 수신 확인 |
| 자동 PR | `Pull requests` 탭 → `security-fix/auto-patch-xxx` 확인 → 리뷰 후 머지 |

---

## 📚 참고 자료

* **SQL Injection Module**
    * [sqlmap](https://github.com/sqlmapproject/sqlmap)
* **Login Brute Force Module**
    * [SecLists - Pwdb top 1000](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/Pwdb_top-1000.txt)
* **LFI Module**
    * [SecLists - LFI-LFISuite-pathtotest](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt)
