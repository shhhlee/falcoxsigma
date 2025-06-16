# Falco × Sigma 파이프라인

Falco가 생성한 보안 이벤트를 Otel Collector를 통해 Sigma 룰 엔진으로 전달하여 실시간 탐지를 구현합니다.

---

## 구성 요소

* **falco\_agent**

  * Falco Modern BPF Unix 소켓(`/run/falco/falco.sock`)에서 이벤트를 구독
  * JSONL 파일에 이벤트 기록 (`exporter/event/events.jsonl`)
  * OTLP Trace 방식으로 Sigma matcher에 전송

* **sigma\_matcher**

  * OTLP Trace gRPC 서버(포트 55680)로 동작
  * `sigma_matcher/rules/rules/linux` 디렉터리에서 Sigma 룰(.yaml) 로드
  * 수신된 이벤트를 Sigma 룰 엔진에 매핑·평가 후 탐지 로그 출력

---

## 사전 준비

1. **우분투 환경**
2. **Falco** 설치 및 실행
```bash
# Falco 설치 후
sudo systemctl start falco-modern-bpf
```
3. **Go** 1.23 이상 설치 (`go version` 확인)

---

## 설정 파일 적용

### Falco 설정 덮어쓰기

프로젝트 루트에서 제공하는 설정 파일을 Falco 시스템 경로에 덮어씁니다:

```bash
# falco.yaml
sudo cp falco.yaml /etc/falco/falco.yaml

# falco_rules.local.yaml
sudo cp falco_rules.local.yaml /etc/falco/falco_rules.local.yaml

# Falco 재시작
sudo systemctl restart falco-modern-bpf
```

> **경로 주의**: 만약 Falco 설정 경로가 다르다면 해당 경로로 복사하세요.

---

## 설치 및 실행

### 옵션 A: 실행 파일 사용

프로젝트에서 미리 빌드된 `falco_agent` 및 `sigma_matcher` 실행 파일을 사용하는 경우, 소스 빌드 없이 바로 실행할 수 있습니다:

```bash
# 저장소 클론
git clone https://github.com/shhhlee/falcoxsigma.git

# 터미널1: falco_agent 실행 파일 실행
cd falcoxsigma/falco_agent
./falco_agent

# 터미널2: sigma_matcher 실행 파일 실행
cd falcoxsigma/sigma_matcher
./sigma_matcher

#터미널3: otel-collector 실행
cd falcoxsigma
otelcol-contrib --config otel-collector-config.yaml
```

### 옵션 B: 소스 빌드

```bash
# 1. 저장소 클론
git clone https://github.com/shhhlee/falcoxsigma.git
cd falcoxsigma

# 2. falco_agent, sigma_matcher 폴더 별 의존성 정리, 실행 파일 빌드
cd falco_agent
go mod tidy
go build -o falco_agent main.go

cd ../sigma_matcher
go mod tidy
go build -o sigma_matcher main.go

# 3. 실행
# 터미널1: falco_agent
cd falco_agent
./falco_exporter

# 터미널2: sigma_matcher
cd sigma_matcher
./sigma_matcher
```
---

## 테스트
현재 테스트용으로 falco와 sigma 룰에 ls 명령어와 Wget 다운로드 (/tmp)에 대한 룰 추가한 상태

```bash
# 별도 터미널 실행 후

# ls 이벤트
ls

# Wget 다운로드 (/tmp)
wget http://example.com/test -O /tmp/testfile
```

* **Falco 로그**: `sudo journalctl -u falco-modern-bpf -f`
* **Exporter 로그**: 파일 기록 및 전송 확인
* **Connector 로그**: `[DEBUG] Incoming attributes:` 및 `Sigma 매칭:` 메시지

---


