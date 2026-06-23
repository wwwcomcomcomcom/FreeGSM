# FreeGSM

평문 DNS를 **DNS-over-HTTPS(DoH)** 로 자동 전환하고, **SNI 기반 차단(DPI)** 까지
우회하는 Windows용 프로그램입니다. 시스템 설정은 전혀 건드리지 않습니다 —
실행해 두면 동작하고, 끄면 원래대로 돌아옵니다. (IPv4 전용)

안드로이드의 [Intra](https://github.com/Jigsaw-Code/Intra)가 하는 일을 데스크톱에서
한다고 보면 됩니다.

## 무엇을 해결하나

학교·기관·일부 ISP 네트워크는 두 단계로 접속을 막습니다.

1. **DNS 단계** — 어떤 도메인을 찾는지 평문 DNS 질의(포트 53)를 들여다보고 차단.
2. **TLS 단계** — DNS가 통과해 IP를 알아내도, HTTPS 연결을 맺을 때 TLS ClientHello
   안의 평문 **SNI**(접속하려는 호스트 이름)를 검사해서, 차단 대상이면 그 즉시
   TCP `RST`를 보내 연결을 끊음.

FreeGSM-DoH는 이 두 단계를 모두 우회합니다.

## 동작 원리

하나의 **WinDivert** 캡처 루프가 나가는 패킷을 가로채 처리합니다. 패킷의 종류에
따라 길이 갈립니다.

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

DNS만 고쳐서는 절반입니다. 나가는 모든 HTTPS 연결의 ClientHello 속 SNI를 검사하는
필터를 넘으려면 **TLS 레코드 단위 분할(record-layer fragmentation)** 이 필요합니다.

- 나가는 `:443` 연결을 로컬 릴레이로 돌립니다.
- 릴레이가 TLS ClientHello를 받아 **두 개의 유효한 TLS 레코드**로 다시 쪼개 보냅니다.
  분할 지점은 SNI보다 앞(앞쪽 몇 바이트)이라, 첫 레코드만 읽는 DPI는 그 안에서
  호스트 이름을 찾지 못합니다. 반면 서버는 명세대로 레코드를 재조립해 정상적으로
  핸드셰이크를 끝냅니다. → 차단 사이트가 실제로 **열립니다.**

> **왜 패킷을 직접 수정하지 않고 릴레이를 쓰나?**
> 레코드 분할은 두 번째 레코드 헤더(5바이트)를 **삽입**합니다. WinDivert 경로에서
> 바이트를 삽입하면 클라이언트 커널의 TCP 시퀀스 번호가 어긋나 RST가 납니다.
> 두 소켓을 모두 소유한 프로세스(릴레이)만 자유롭게 다시 조립할 수 있습니다 —
> Intra가 같은 방식을 쓰는 이유입니다.

## 요구 사항

- Windows 10/11, 64-bit
- **관리자 권한** (WinDivert가 커널 드라이버를 로드)
- 소스로 실행하거나 빌드하려면 Python 3.12+

## 사용법

### 방법 A — 빌드된 exe (간편)

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

`dist\FreeGSM-DoH.exe`가 만들어집니다. WinDivert 드라이버가 내장되어 있고 실행 시
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

대부분의 옵션은 `dohproxy/config.py`에 있고, 자주 바꾸는 값은 **다시 빌드하지 않고**
환경 변수로 지정할 수 있습니다.

```powershell
# DoH 업스트림 바꾸기
set FREEGSM_DOH_URL=https://8.8.8.8/dns-query   # Google
set FREEGSM_DOH_URL=https://9.9.9.9/dns-query   # Quad9

# SNI 우회(443 릴레이) 끄고 DoH만 쓰기
set FREEGSM_DPI=0
```

> ⚠️ 기본 업스트림이 `1.1.1.1`이 아니라 **`1.0.0.1`** 인 이유: 많은 네트워크가
> `1.1.1.1` 주소만 콕 집어 막습니다. `1.0.0.1`은 **같은** Cloudflare DoH 리졸버의
> 보조 IP(인증서가 두 IP를 모두 포함)이고 보통 막히지 않아 기본값으로 둡니다.

## 동작 확인

관리자 터미널에서 앱을 켜 둔 채:

```powershell
nslookup example.com          # UDP 경로
nslookup -vc example.com      # TCP 경로 강제

# SNI 우회 확인: "OK  HTTP 200" 이 뜨면 ClientHello가 통과한 것
python verify_lolps.py            # https://lol.ps/ 로 GET
python verify_lolps.py <host>     # 다른 차단 호스트 시험
```

암호화 여부는 `pktmon`이나 Wireshark로 확인할 수 있습니다 — 포트 53에 평문 패킷이
전혀 나가지 않고, 포트 443으로 DoH 서버에 가는 TLS 트래픽만 보여야 합니다.

## 한계

- IPv4만 처리합니다(IPv6 DNS는 그대로 통과).
- DNS 캐시가 없습니다(질의마다 DoH 왕복, HTTP/2 연결 유지로 비용은 낮음).
- 443 릴레이는 모든 트래픽을 파이썬 사용자 영역 파이프로 중계합니다. 일반적인
  웹 브라우징엔 충분하지만 대용량 다운로드는 느릴 수 있습니다(`FREEGSM_DPI=0`으로
  끌 수 있음).
- **QUIC / HTTP-3(UDP/443)은 처리하지 않습니다.** 네트워크가 QUIC를 SNI로 막는다면
  브라우저에서 HTTP/3을 꺼서 TCP로 폴백시키세요(TCP는 우회됩니다).
