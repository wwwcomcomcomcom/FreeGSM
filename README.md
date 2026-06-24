# FreeGSM - Next FxxxGSM

## 배경

https://github.com/kimgh06/VPN-for-GSM 을 비공식적으로 계승합니다.
[이전에 쓰던 FxxkGSM](https://github.com/kimgh06/VPN-for-GSM)도 사실 VPN으로 적혀있지만 VPN이 아닙니다.
내부는 `goodbyedpi`라는 차단 우회용 오픈소스를 일부 변형하여 구현 되어 있습니다.
FreeGSM은 소스코드가 상실된 FxxkGSM을 대체하고, DNS 차단과 SNI 기반 차단에 대한 이해도를 높이기 위한 학습을 목적으로 python으로 개발 되었습니다.

## 기본 지식

평문 DNS를 **DNS-over-HTTPS(DoH)** 로 자동 전환하고, **SNI 기반 차단(DPI)** 까지
우회하는 Windows용 프로그램입니다. 실행해 두면 동작하고, 끄면 원래대로 돌아옵니다. (IPv4 전용)
VPN이 아니기 때문에 실질적으로 ip가 변경되거나 핑이 크게 튀지 않습니다.
따라서 ip가 차단당한 경우엔 사용할 수 없습니다.

## 요구 사항

- Windows 10/11, 64-bit
- **관리자 권한** (WinDivert가 커널 드라이버를 로드)
- 소스로 실행하거나 빌드하려면 Python 3.12+

## 사용법

### 방법 A — 빌드된 exe (간편)

Release에서 최신 버전의 exe를 다운로드하거나, 아래 방법을 통해 빌드하세요.

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

`dist\FreeGSM.exe`가 만들어집니다. WinDivert 드라이버가 내장되어 있고 실행 시
**UAC 관리자 권한을 자동으로 요청**하므로, 더블클릭만 하면 됩니다.

### 방법 B — 소스로 실행

```powershell
pip install -r requirements.txt
# 반드시 "관리자 권한"으로 연 터미널에서 실행:
python -m dohproxy.main
```

창을 열어 두면 DNS가 DoH로 전환된 상태입니다. **Ctrl+C** 로 종료하면 평범한 DNS로
돌아갑니다.

## 설정

설정 우선순위: **환경 변수 > `config.yml` > 내장 기본값**

### config.yml (권장)

실행 파일 옆이나 프로젝트 루트에 `config.yml`을 두면, 재빌드·환경 변수 없이
값을 바꿀 수 있습니다. 파일이 없거나 항목이 없으면 기본값이 그대로 쓰입니다.

```yaml
# 있는 항목만 기본값을 덮어씁니다
doh_url: https://8.8.8.8/dns-query   # Google DoH
dpi_bypass: true                       # false 로 설정하면 443 릴레이 비활성화
```

지원 항목:

| 항목 | 기본값 | 설명 |
|------|--------|------|
| `doh_url` | `https://1.0.0.1/dns-query` | DoH 업스트림 URL (반드시 IP로 지정) |
| `dpi_bypass` | `true` | SNI 우회 릴레이 활성화 여부 |

### 환경 변수 (env var가 config.yml보다 우선)

```powershell
# DoH 업스트림 바꾸기
set FREEGSM_DOH_URL=https://8.8.8.8/dns-query   # Google
set FREEGSM_DOH_URL=https://9.9.9.9/dns-query   # Quad9

# SNI 우회(443 릴레이) 끄고 DoH만 쓰기
set FREEGSM_DPI=0
```

## 동작 원리

DNS와 TLS(SNI) 단계에서 우회를 진행합니다.
하나의 **WinDivert** 캡처 루프가 나가는 패킷을 가로채 처리합니다. 패킷의 종류에 따라 길이 갈립니다.

### 1. DNS → DoH (포트 53)

- **UDP/53**: 나가는 DNS 질의 패킷을 잡아, 그 페이로드를 그대로 DoH 서버에 HTTPS로
  POST하고, 돌아온 응답을 그대로 다시 끼워 넣습니다. DNS 질의와 DoH 요청 본문은
  **같은 바이트 포맷**(RFC 8484)이라 DNS를 따로 해석할 필요가 없습니다.
- **TCP/53**: TCP DNS는 길이 접두사가 붙은 스트림이라 단일 패킷으로 답할 수 없어,
  연결을 로컬 프록시로 돌려서 처리합니다.
- **DoH 연결**: DoH 서버의 **IP에 직접** 접속합니다(`https://1.0.0.1/...`).
  인증서에 IP SAN이 들어 있어 검증이 통과하므로, DoH 서버 주소를 찾으려고 다시
  DNS를 쓰는 부트스트랩 문제가 없습니다. HTTP/2 연결을 유지해 질의마다 비용이 낮음.
- **Fail-closed(기본값)**: DoH 서버에 닿지 못하면 질의를 **평문으로 흘리지 않고
  버립니다.** 그래서 시작할 때 업스트림에 먼저 접속해 보고, 닿지 않으면 아예 실행을
  거부합니다(닿지 않는 업스트림으로 시작하면 모든 DNS가 끊기기 때문).

### 2. SNI 차단 우회 (포트 443)

나가는 모든 HTTPS 연결의 ClientHello 속 SNI를 검사하는
필터를 넘기위해 TLS 레코드 분할을 진행합니다.

- 나가는 `:443` 연결을 로컬 릴레이로 돌립니다.
- 릴레이가 TLS ClientHello를 받아 두 개의 유효한 TLS 레코드로 다시 쪼개 보냅니다.
  분할 지점은 SNI보다 앞(앞쪽 몇 바이트)이라, 첫 레코드만 읽는 DPI는 그 안에서
  호스트 이름을 찾지 못합니다. 반면 서버는 명세대로 레코드를 재조립해 정상적으로
  핸드셰이크를 끝냅니다.

## 한계

- IPv4만 처리합니다(IPv6 DNS는 그대로 통과).
- DNS 캐시가 없습니다(질의마다 DoH 왕복, HTTP/2 연결 유지로 비용은 낮음).
- 443 릴레이는 모든 트래픽을 파이썬 사용자 영역 파이프로 중계합니다. 일반적인
  웹 브라우징엔 충분하지만 대용량 다운로드는 느릴 수 있습니다(`FREEGSM_DPI=0`으로
  끌 수 있음).
- **QUIC / HTTP-3(UDP/443)은 처리하지 않습니다.** 네트워크가 QUIC를 SNI로 막는다면
  브라우저에서 HTTP/3을 꺼서 TCP로 폴백시키세요(TCP는 우회됩니다).
