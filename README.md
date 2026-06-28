# FreeGSM - Next FxxxGSM

## 배경

https://github.com/kimgh06/VPN-for-GSM 을 비공식적으로 계승합니다.
[이전에 쓰던 FxxkGSM](https://github.com/kimgh06/VPN-for-GSM)도 사실 VPN으로 적혀있지만 VPN이 아닙니다.
내부는 `goodbyedpi`라는 차단 우회용 오픈소스를 일부 변형하여 구현 되어 있습니다.
FreeGSM은 소스코드가 상실된 FxxkGSM을 대체하고, DNS 차단과 SNI 기반 차단에 대한 이해도를 높이기 위한 학습을 목적으로 python으로 개발 되었습니다.

> 메모리 사용량과 성능이 소폭 개선된 [Rustify 버전](https://github.com/wwwcomcomcomcom/FreeGSM/tree/rustify)을 함께 제공합니다.

## 기본 지식

평문 DNS를 **DNS-over-HTTPS(DoH)** 로 자동 전환하고, **SNI 기반 차단(DPI)** 까지
우회하는 프로그램입니다. 주 대상은 **Windows**이며, macOS는 다른 메커니즘으로
포팅돼 있습니다(아래 [macOS](#macos-실험적) 섹션). 실행해 두면 동작하고, 끄면 원래대로 돌아옵니다. (IPv4 전용)
VPN이 아니기 때문에 실질적으로 ip가 변경되거나 핑이 크게 튀지 않습니다.
따라서 ip가 차단당한 경우엔 사용할 수 없습니다.

## 요구 사항

- Windows 10/11, 64-bit
- **관리자 권한** (WinDivert가 커널 드라이버를 로드)
- 소스로 실행하거나 빌드하려면 Python 3.12+
- (실험적) macOS — DoH + SNI/443 우회, root 필요(+tun2socks). 아래 [macOS](#macos-실험적) 섹션 참고

## 사용법 (Windows)

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

## macOS (실험적)

> macOS는 Windows와 **구현 메커니즘이 다른** 별도 포팅입니다(위 "사용법(Windows)"의
> WinDivert 방식이 적용되지 않음). 설계 상세는 [`docs/MACOS_PORT.md`](docs/MACOS_PORT.md).

macOS에는 WinDivert가 없고 pf의 `rdr`로는 자기 자신이 보내는 트래픽을 가로챌 수
없어, Windows의 패킷 캡처 방식을 그대로 옮길 수 없습니다. 대신 macOS 포팅은 두
기능을 이렇게 구현합니다:

- **DoH** — 로컬 DoH 리졸버를 띄우고 시스템 DNS를 그쪽으로 돌린 뒤, 종료 시
  원래 값으로 복원.
- **SNI/443 우회** — `tun2socks`가 utun으로 나가는 TCP를 받아 로컬 SOCKS5
  프록시로 넘기고, 프록시가 ClientHello를 두 TLS 레코드로 분할(Windows판의
  `https_proxy`/`dpi` 로직 재사용). 우회 채널은 `IP_BOUND_IF`로 물리 인터페이스에
  고정해 라우팅 루프를 막습니다.

### 요구 사항 (macOS)

- macOS, **root 권한** (`127.0.0.1:53` 바인딩 · 시스템 DNS 변경 · (DPI on) utun
  생성 + 기본 경로 변경)
- 소스로 실행하려면 Python 3.12+
- (DPI on) `tun2socks` 바이너리 — `run_macos.sh`가 자동 내려받음

### 설치 — 소스에서 실행

macOS는 **소스를 받아 실행**합니다. 더블클릭용 `.app`/`.pkg` 번들은 Apple
**공증(notarize)** 이 없으면 최신 macOS의 Gatekeeper가 설치·실행을 막으므로
배포하지 않습니다. `git clone`/`curl` 로 받은 파일에는 Gatekeeper 격리
(`com.apple.quarantine`)가 붙지 않아 "확인되지 않은 개발자" 경고 없이 바로
동작하고, 코드를 직접 확인할 수 있어 검열우회 도구로서 신뢰성도 높습니다.

```bash
git clone https://github.com/wwwcomcomcomcom/FreeGSM
cd FreeGSM
./run_macos.sh        # 의존성·tun2socks 자동 설치 + sudo 실행, Ctrl+C(또는 창 닫기)로 원복
```

<details><summary>수동 실행</summary>

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-macos.txt
sudo .venv/bin/python3 -m dohproxy.macos.main
```
</details>

동작/옵션:

- 실행 중 `dig example.com` 의 `SERVER` 가 `127.0.0.1#53` 이고, 로그에
  `... -> 2 TLS records` 가 보이면 DoH·SNI 우회가 모두 동작 중입니다.
  **Ctrl+C**(또는 실행한 터미널 닫기)로 종료하면 DNS·라우팅이 복원됩니다(비정상
  종료 대비 DNS·터널 상태를 디스크에 저장해 다음 실행 때 자동 복구).
- **SNI 우회 끄기**: `FREEGSM_DPI=0 ./run_macos.sh` (DoH만; tun2socks 불필요).
- **tun2socks**: brew 포뮬러가 없어 `run_macos.sh` 가 GitHub 릴리스 바이너리를
  `./bin/tun2socks` 로 자동 내려받습니다. 직접 둘 경우 PATH나 `./bin` 에 놓거나
  `FREEGSM_TUN2SOCKS=/path/to/tun2socks` 로 지정하세요. 없으면 DoH만 켜집니다.
- **VPN 주의**: VPN(예: ProtonVPN)은 자체 스코프 리졸버/utun을 쓰므로, VPN 활성
  시 DNS 변경이나 라우팅이 충돌할 수 있습니다. VPN을 끈 상태를 권장합니다.
- **적용 범위(Windows와 차이)**: macOS판은 *시스템 DNS*를 로컬 리졸버로 돌리는
  방식이라, **시스템 리졸버를 쓰는 앱만** DoH 보호를 받습니다. `8.8.8.8` 같은
  DNS 서버를 직접 박아 쓰는 앱은 DoH를 우회하며, DPI를 켠 상태에서는 그런 앱의
  UDP/53이 막힐 수 있습니다(로컬 SOCKS 프록시가 CONNECT만 지원, UDP ASSOCIATE
  미지원). 대부분의 앱은 시스템 리졸버를 쓰므로 실사용에는 문제없습니다.

> Windows 전용 의존성인 `pydivert` 는 macOS에 빌드가 없으므로, macOS는
> `requirements.txt` 대신 `requirements-macos.txt`(httpx + pyyaml)만 씁니다.

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

### 0. 검열과 차단

웹사이트에 접속할 때 브라우저가 가장 먼저 하는 일은 두 가지입니다.

1. **이름 풀이(DNS)**: `example.com` 같은 도메인 이름을 실제 IP 주소로 바꿉니다.
   기본적으로 평문 UDP/53(가끔 TCP/53)으로 오갑니다.
2. **TLS 핸드셰이크(SNI)**: 알아낸 IP의 443 포트로 TCP 연결을 맺고, **암호화가
   시작되기 전에** "나는 `example.com`에 접속하려 한다"는 호스트 이름을 평문으로
   보냅니다. 이 필드가 **SNI(Server Name Indication)**입니다.

학교·기관·ISP의 차단 장비(흔히 **DPI**, Deep Packet Inspection)는 바로 이
**두 평문 지점**을 노립니다. ① DNS 질의를 들여다보고 가짜 응답을 주입하고,
② TLS의 SNI를 읽어 차단 대상 호스트면 연결을 끊습니다. FreeGSM은 이 두 지점을
각각 우회합니다. — DNS는 **암호화**해서 들여다볼 수 없게, SNI는 **조각내서** 한 번에
읽을 수 없게 만듭니다.

구현상으로는 하나의 **WinDivert** 캡처 루프가 나가는 패킷을 모두 가로채고,
패킷의 포트와 방향에 따라 처리 경로가 갈립니다(`divert.py`).

### 1. DNS 차단과 DoH 우회 (포트 53)

**차단은 이렇게 동작합니다.** 평문 DNS는 보내는 사람도, 받는 IP(예: `8.8.8.8`)도,
**질문 내용("example.com의 IP는?")까지 전부 노출**됩니다. 그래서 차단 장비는

- 질의 안의 도메인 이름을 그대로 읽고,
- 차단 대상이면 진짜 응답이 오기 전에 **가짜 응답을 먼저 주입**하거나(존재하지 않는
  주소·차단 안내 페이지 IP로 위조 = DNS 스푸핑/하이재킹), 질의 자체를 버립니다.

UDP 질의는 응답을 검증할 길이 없어서, 먼저 도착한 위조 응답을 그대로 믿게 됩니다.

**FreeGSM의 우회 — DoH(DNS over HTTPS)로 질문을 암호화합니다.**

- **UDP/53**: 나가는 DNS 질의 패킷을 잡아, 그 페이로드를 그대로 DoH 서버에 HTTPS로
  POST하고, 돌아온 응답을 그대로 다시 끼워 넣습니다. 질의가 TLS 안에 들어가므로
  차단 장비는 도메인 이름은커녕 **그것이 DNS 질의라는 사실조차** 알 수 없어, 읽지도
  위조하지도 못합니다. DNS 질의와 DoH 요청 본문은 **같은 바이트 포맷**(RFC 8484)이라
  DNS를 따로 해석할 필요가 없습니다.
- **TCP/53**: TCP DNS는 길이 접두사가 붙은 스트림이라 단일 패킷으로 답할 수 없어,
  연결을 로컬 프록시로 돌려서 처리합니다(`nslookup -vc`가 쓰는 경로).
- **부트스트랩 문제 해결**: "DNS를 대신하는 서버의 주소를 또 DNS로 찾아야 하나?"라는
  순환을 피하려고, DoH 서버의 **IP에 직접** 접속합니다(`https://1.0.0.1/...`).
  인증서에 IP SAN이 들어 있어 TLS 검증이 통과하므로, 호스트 이름 풀이가 아예 필요
  없습니다. HTTP/2 연결을 유지해 질의마다 비용이 낮습니다.
- **Fail-closed(기본값)**: DoH 서버에 닿지 못하면 질의를 **평문으로 흘리지 않고
  버립니다.** 잠깐 실패했다고 평문으로 새어 나가면 우회의 의미가 없기 때문입니다.
  대신 시작할 때 업스트림에 먼저 접속해 보고, 닿지 않으면 아예 실행을 거부합니다
  (닿지 않는 업스트림으로 켜두면 모든 DNS가 끊기므로).

> DNS만 풀어도 IP는 알아낼 수 있지만, 그 IP로 HTTPS 연결을 맺는 순간 아래의 SNI
> 검사에 다시 걸립니다. 그래서 다음 단계가 필요합니다.

### 2. SNI 차단과 레코드 분할 우회 (포트 443)

**차단은 이렇게 동작합니다.** DNS를 암호화해도, TLS 핸드셰이크의 첫 메시지인
**ClientHello 속 SNI는 여전히 평문**입니다(서버가 어떤 인증서를 줄지 고르려면
암호화 키 교환 전에 호스트 이름을 알아야 하기 때문). 차단 장비는

- 나가는 TCP 스트림을 재조립해 ClientHello를 찾고,
- 그 안의 SNI 호스트 이름을 읽어,
- 차단 대상이면 즉시 **TCP RST를 주입하거나 패킷을 버려** 연결을 끊습니다.

그래서 DoH로 IP를 멀쩡히 알아내도, 그 사이트로의 HTTPS 연결이 SNI 단계에서 막혀
"DNS는 되는데 접속은 안 되는" 상태가 됩니다.

**FreeGSM의 우회 — ClientHello를 두 TLS 레코드로 쪼갭니다.**

핵심은 **TLS 레코드 계층 분할**입니다. 하나의
ClientHello 레코드를 **두 개의 유효한 TLS 레코드**로 다시 내보냅니다(하나의
핸드셰이크 메시지가 여러 레코드에 걸쳐도 명세상 정상입니다).

- 분할 지점을 **SNI보다 앞쪽 몇 바이트**에 둬서, 첫 레코드 안에는 호스트 이름이
  들어가지 않게 합니다. SNI를 "첫 레코드 하나에서" 찾는 차단 장비는 빈손이 되고,
  반면 진짜 서버는 명세대로 레코드를 재조립해 정상적으로 핸드셰이크를 끝냅니다.
  (`SPLIT_MIN`/`SPLIT_MAX`로 첫 레코드 크기를 무작위화)

**왜 패킷을 직접 수정하지 않고 로컬 릴레이를 쓰는가:** 레코드를 쪼개려면 두 번째
5바이트 레코드 헤더를 **새로 끼워 넣어야** 합니다. 그런데 WinDivert가 보는 원시
패킷 스트림에 바이트를 삽입하면 클라이언트 커널의 TCP 시퀀스 번호가 어긋나, 서버가
"보낸 적 없는 바이트"를 ACK하는 순간 커널이 RST를 쏩니다(README 상단의
"바이트를 넣거나 빼지 말 것" 불변식). 그래서 양쪽 소켓을 모두 소유한 사용자 영역
프로세스에서 연결을 종단(terminate)하고 다시 프레이밍합니다.

- 나가는 `:443` 연결을, 목적지를 `자기자신:릴레이포트`로 바꿔 **INBOUND로 재주입**해
  로컬 릴레이로 돌립니다(TCP/53과 같은 리다이렉트 기법). 원래 목적지는
  `(출발지 IP, 출발지 포트)`로 기억해 둡니다.
- 릴레이가 ClientHello를 받아 `dpi.split_hello`로 두 레코드로 쪼개 서버로 보낸 뒤,
  그 다음부터는 단순 양방향 파이프로 중계합니다. 릴레이→서버 소켓은 캡처 필터가
  제외하는 예약 포트 범위(`30000~32047`)를 써서 자기 트래픽을 다시 잡는 무한 루프를
  피합니다.

> 우리가 의존하는 DoH 채널 자체(`DOH_SERVER_IP:443`)는 분할 대상에서 제외됩니다 —
> 우회 통로를 우회하면 안 되니까요.

## 한계

- IPv4만 처리합니다(IPv6 DNS는 그대로 통과).
- DNS 캐시가 없습니다(질의마다 DoH 왕복, HTTP/2 연결 유지로 비용은 낮음).
- 443 릴레이는 모든 트래픽을 파이썬 사용자 영역 파이프로 중계합니다. 일반적인
  웹 브라우징엔 충분하지만 대용량 다운로드는 느릴 수 있습니다(`FREEGSM_DPI=0`으로
  끌 수 있음).
- **QUIC / HTTP-3(UDP/443)은 처리하지 않습니다.** 네트워크가 QUIC를 SNI로 막는다면
  브라우저에서 HTTP/3을 꺼서 TCP로 폴백시키세요(TCP는 우회됩니다).
- SNI 차단 장비가 분할된 SNI 레코드를 조합한다면 차단을 우회할 수 없습니다. 이를 해결하기 위한 노력으로는 [ESNI](https://www.cloudflare.com/ko-kr/learning/ssl/what-is-encrypted-sni/)가 있습니다.
