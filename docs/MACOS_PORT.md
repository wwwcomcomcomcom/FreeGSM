# FreeGSM — macOS 포팅 설계서

> **상태: 구현 완료 · 라이브 검증됨 (2026-06-26, macOS 26.5.1).**
> macOS 포팅은 Windows의 WinDivert 패킷 캡처 모델을 쓰지 않는다. pf `rdr`로 같은
> 모델을 재현하려던 1차 시도(아래 [부록 A](#부록-a--폐기된-pf-rdr-설계기록))는
> **실패**했고, 대신 OS 표준 메커니즘 두 가지로 두 작업을 따로 구현했다:
>
> | 작업 | macOS 방식 | 모듈 |
> |------|-----------|------|
> | **DoH** | 로컬 DoH 리졸버를 띄우고 **시스템 DNS를 `127.0.0.1`로 스왑**, 종료 시 원복 | `macos/resolver.py`, `macos/dns_control.py` |
> | **SNI/443** | **utun + tun2socks**로 아웃바운드 TCP를 로컬 **SOCKS5 분할 프록시**로 흘려보냄 | `macos/tunnel.py`, `macos/socks_proxy.py` |
>
> 엔트리포인트: `sudo python -m dohproxy.macos.main` (DoH + DPI 동시).
> 폐기된 pf 설계는 기록 목적으로 [부록 A](#부록-a--폐기된-pf-rdr-설계기록)에 보존한다.

---

## 1. 왜 Windows 모델이 안 맞나

FreeGSM의 절반(DoH 클라이언트 · TLS 레코드 분할 · 로컬 서버 로직)은 OS와 무관한
순수 Python이라 그대로 넘어간다. 문제는 나머지 절반인 **패킷 가로채기 엔진**이다.

- Windows는 WinDivert(커널 드라이버)로 *모든* 아웃바운드 UDP/53·TCP/53·TCP/443을
  캡처해 사용자공간에서 재주입한다. macOS에는 동등물이 없다.
- macOS pf의 `rdr`은 **인터페이스로 들어오는(inbound)** 패킷에만 적용되고, 이 호스트가
  스스로 만들어내는 아웃바운드 연결(=가로채려는 대상)에는 매칭되지 않는다. Linux
  `iptables OUTPUT REDIRECT` 대응물이 macOS pf엔 없고 `divert-to`도 없다 →
  [부록 A](#부록-a--폐기된-pf-rdr-설계기록)에서 스파이크로 확인.

그래서 두 작업을 **서로 다른 표준 메커니즘**으로 분리 구현한다. DoH는 시스템
리졸버를 재설정, SNI/443은 utun 미니 VPN. DNS는 utun에 태우지 않고 분리 유지한다
(엉킴 방지).

### 그대로 넘어온 모듈 (플랫폼 무관)

| 파일 | 비고 |
|------|------|
| `dohproxy/doh.py` | httpx HTTP/2 DoH 클라이언트. **그대로**. |
| `dohproxy/dpi.py` | `split_hello` / `sni_name`, I/O 없는 순수 TLS. **그대로**. |
| `dohproxy/dnsutil.py` | 로깅용. **그대로**. |
| `dohproxy/config.py` | DoH 상수 유지. macOS 상수 추가(`LOCAL_DNS_HOST/PORT`, `DPI_BYPASS` 등). |

---

## 2. DoH — 시스템 DNS 스왑 방식

**핵심 아이디어**: 패킷을 가로채지 않는다. 로컬에 DoH 리졸버를 띄우고 **시스템
DNS 서버를 `127.0.0.1`로 바꾼 뒤, 종료 시 원래 값으로 복원**한다. 표준 DNS
질의가 로컬 리졸버로 들어오면 그대로 DoH로 중계한다 (RFC 8484: DNS wire 포맷 ==
DoH 본문, 그래서 `doh.resolve(query_bytes)`를 그대로 쓸 수 있음).

```
앱(브라우저 등) --DNS--> 127.0.0.1:53 (로컬 리졸버) --DoH/HTTP2--> 1.0.0.1
                            ↑ 시스템 DNS를 여기로 재설정 (종료 시 원복)
```

### 모듈

| 파일 | 처리 |
|------|------|
| `dohproxy/macos/resolver.py` | `127.0.0.1:53` UDP+TCP 리졸버. UDP는 `recvfrom→doh.resolve→sendto`; TCP는 length-prefixed DoH 종단. |
| `dohproxy/macos/dns_control.py` | 활성 네트워크 서비스들의 현재 DNS 백업 → `127.0.0.1`로 설정 → 종료 시 복원 + 캐시 flush. |

### dns_control.py 동작

```bash
# 활성 서비스 열거 → 각 서비스의 현재 DNS 백업 → 127.0.0.1로 변경
networksetup -listallnetworkservices
networksetup -getdnsservers "<service>"      # 백업 (없으면 "empty"로 기록)
networksetup -setdnsservers "<service>" 127.0.0.1
# 복원 (종료 시): 원래 서버들로, 없었으면:
networksetup -setdnsservers "<service>" empty
# 캐시 flush (스왑 직후 + 복원 후):
dscacheutil -flushcache ; killall -HUP mDNSResponder
```

### 안전 / 불변식

- **스왑 전에 upstream probe** (`doh.probe()`). 깨진 리졸버로 DNS를 돌리면 전체
  DNS가 죽으므로, fail-closed 거부 로직을 유지한다 — "거부 = DNS 스왑 안 함".
- **어떤 경로로 종료되든 DNS 복원 보장**: `try/finally` + `signal`(SIGINT/SIGTERM/
  SIGHUP) + `atexit`. 크래시로 시스템 DNS가 `127.0.0.1`에 묶인 채 리졸버가 죽으면
  사용자 DNS가 전부 막히므로 이게 최우선 불변식이다 ([main.py](../dohproxy/macos/main.py#L97-L117)의
  `_teardown` — 각 단계가 격리·idempotent).
- **비정상 종료 잔재 복구**: 시작 시 시스템 DNS가 이미 `127.0.0.1`이면 이전 실행이
  복원에 실패한 것 → 백업 파일이 있으면 그걸로 먼저 복원 시도. (백업을 디스크에
  저장하는 이유)
- **fail-closed 유지**: 로컬 리졸버가 DoH 실패 시 응답 안 보냄(평문 누출 없음).
- `127.0.0.1:53` 바인딩은 root 필요 — 기존 모델과 동일하게 root로 실행.

### "시스템 설정 안 건드림" 원칙과의 타협

Windows판은 어떤 설정도 안 바꿨지만, macOS DoH는 **DNS 서버 한 항목을 변경 후
복원**한다. 완전 무수정은 아니지만, 종료 시 원복되고 macOS에서 가장 표준적·안정적인
방법이다. (무수정을 고수하려면 결국 Network Extension으로 가야 하므로 1차 범위에서
의식적으로 타협.)

### 검증 (DoH)

```bash
sudo python -m dohproxy.macos.main      # 기동
dig example.com                          # UDP 경로 (시스템 DNS 경유)
dig +tcp example.com                     # TCP 경로
scutil --dns | grep nameserver           # 127.0.0.1 확인
# Ctrl+C 후:
networksetup -getdnsservers Wi-Fi        # 원래 값으로 복원됐는지 확인
```

> **검증됨**: 비특권 포트(5354)·root(:53) 둘 다 `dig` / `dig +tcp` 실제 DoH 해석
> 성공(example.com → HTTP/2 200 → A 레코드). 비-root 실행은 시스템을 건드리지 않고
> 거부(exit 1). root 실행 시 DNS 스왑/복원도 라이브 확인.
>
> **VPN 주의**: VPN은 자체 스코프 리졸버(utun)로 DNS를 처리할 수 있어
> `networksetup -setdnsservers`로 건 값이 VPN 활성 시 무시·충돌할 수 있다. VPN
> 사용 환경 동작은 별도 검증 필요.

---

## 3. SNI/443 우회 — utun + tun2socks + SOCKS5

Network Extension은 Apple Developer 계정이 필요하므로, **utun 방식**으로 간다(root만
필요). 사실상 미니 VPN을 구현하는 셈이라 규모가 크지만 계정 의존성이 없다.

### 큰 그림

```
앱 --TCP--> [utun] --IP--> tun2socks(TCP종단) --SOCKS5--> 127.0.0.1:1080
                                                          (split_hello on :443,
                                                           upstream은 IP_BOUND_IF=en0)
```

성숙한 tun2socks가 utun 읽기·TCP 종단을 맡고, 각 흐름을 로컬 SOCKS5 프록시로
넘긴다. 프록시는 `:443`이면 `dpi.split_hello`로 ClientHello를 2레코드로 분할, 그
외는 패스스루. **TCP 스택 신규 구현 0줄** — 순수 Python으로 TCP 스택을 짜는 건
비현실적이라 성숙한 바이너리에 위임했다.

### 구성 요소

| 단계 | 내용 | 모듈 |
|------|------|------|
| 1. utun 생성·읽기 | `PF_SYSTEM`/`SYSPROTO_CONTROL` + `com.apple.net.utun_control` 제어 소켓으로 utun fd 확보, IP 패킷 read/write(앞 4바이트 AF 헤더) | `tunnel.py` (스파이크 U1로 검증) |
| 2. 라우팅 | 호스트 자기 트래픽을 utun으로. `route add 0/1`+`128/1`(기본 경로 덮어쓰기, VPN 트릭). **DoH 서버 IP·릴레이 upstream은 실 게이트웨이로 제외**(루프 방지) | `tunnel.py` |
| 3. TCP 종단 | utun으로 들어온 SYN을 종단해 바이트 스트림 확보 | **tun2socks 바이너리** |
| 4. 분할·중계 | 스트림에서 ClientHello → `dpi.split_hello` → 실서버 소켓으로 중계 | `socks_proxy.py` ([dpi.py](../dohproxy/dpi.py) 재사용) |
| 5. 비-443 패킷 통과 | 라우팅으로 utun에 들어온 나머지는 SOCKS 패스스루로 실서버 중계 | `socks_proxy.py` |
| 6. 원복 | 종료 시 라우트 삭제 + utun fd close(인터페이스 자동 소멸) | `tunnel.py` |

### ⚠️ 핵심 학습 — IP_BOUND_IF egress와 ifscope 경로

**루프 방지 핵심**: 프록시가 실서버로 나가는 upstream 소켓은 `IP_BOUND_IF` 소켓
옵션으로 물리 인터페이스(en0)에 고정 → default 경로가 utun이어도 우회한다.
(WinDivert 예약 포트 제외 절의 macOS 대응)

처음엔 SOCKS upstream이 전부 `ENETUNREACH`로 실패했다. 진단 결과:
`route get -ifscope en0 <ip>`가 **빈 결과** — 이 머신엔 en0의 ifscope(스코프) 경로가
없었다. `IP_BOUND_IF=en0`은 ifscope 라우팅 테이블을 보는데 거기 경로가 없으니
ENETUNREACH. **해결**: 터널 기동 시 **ifscope default 경로**를 하나 추가
(`route add -ifscope <iface> default <gw>`). 그러면 IP_BOUND_IF upstream 소켓은
ifscope→물리 인터페이스로 나가 utun을 우회하고, 앱 소켓(IP_BOUND_IF 없음)은 전역
`0/1` 경로로 utun에 들어가 분할이 유지된다. 전역 host-route 우회는 앱 트래픽까지
우회시켜 분할을 깨므로 부적합 — **소켓 단위 IP_BOUND_IF + ifscope가 정답**.

### 검증 (SNI/443)

```bash
curl https://example.com            # 앱 트래픽이 utun→tun2socks→SOCKS 경유
python verify_lolps.py [host]       # SNI 분할 동작 확인
```

> **라이브 검증됨 (2026-06-26)**: `curl https://example.com` / `www.cloudflare.com`
> → HTTP 200, SOCKS 로그에 `SNI=example.com ClientHello 321B -> 2 TLS records` 등
> 실제 트래픽 분할 확인. 종료 시 default route(en0)·시스템 DNS(DHCP) 완전 복원.

---

## 4. 통합 main / 생명주기 / 원복

[`macos/main.py`](../dohproxy/macos/main.py): root 체크 → DoH upstream probe(fail-closed,
실패 시 기동 거부) → 리졸버 기동 → DNS 스왑 → (DPI on이면) SOCKS 서버 + utun 터널
기동 → `Ctrl+C`까지 대기 → teardown.

- **DPI는 graceful degrade**: tun2socks 바이너리가 없거나, `DOH_URL`이 리터럴 IP가
  아니거나(=터널에서 DoH 채널을 IP로 제외할 수 없음), 터널 셋업 중 예외가 나면 →
  DPI를 끄고 **DoH-only로 계속** 간다. DNS를 죽이느니 우회를 포기.
- **teardown 순서**: 라우팅 복원 → SOCKS 종료 → **DNS 복원(최우선)**. 각 단계가
  격리·idempotent이라 앞 단계 예외가 DNS 복원을 건너뛰지 못한다. `finally` +
  `signal`(SIGINT/SIGTERM/SIGHUP) + `atexit` 삼중으로 보장.
- **SIGHUP**: `run_macos.sh`를 띄운 터미널을 닫으면 정상 종료·복원.

---

## 5. 배포 / 패키징

- **tun2socks 바이너리**: brew 포뮬러 없음 → GitHub 릴리스(v2.6.0) 바이너리를
  `./bin/tun2socks` 또는 PATH에 두거나 `FREEGSM_TUN2SOCKS`로 지정. `run_macos.sh`
  · `build_macos_app.sh`가 없으면 자동 다운로드.
- ✅ **더블클릭 앱**: [`packaging/build_macos_app.sh`](../packaging/build_macos_app.sh)
  → `dist/FreeGSM.app`. 더블클릭 토글(켜기/끄기). osascript 관리자 권한(=UAC)으로
  승격하되 실제 프로세스는 **launchd로 띄운다** — osascript 환경엔 tty가 없어 nohup
  분리가 실패(`can't detach from console`)하므로, baked LaunchDaemon plist를
  `/Library/LaunchDaemons`에 복사 후 `launchctl bootstrap`(시작)/`bootout`(중지,
  SIGTERM→정상 teardown). 검증 완료(start→`127.0.0.1#53`+200, stop→DHCP 복원).
- ✅ **터미널 종료 시 원복**: main.py가 SIGHUP 처리 → 띄운 터미널을 닫으면 정상 복원.
- ⚠️ **.pkg 빌드 스크립트**: [`packaging/build_macos_pkg.sh`](../packaging/build_macos_pkg.sh)
  작성됨 — ad-hoc 서명(`codesign --sign -`) + `pkgbuild`까지. **Developer ID 서명·
  공증은 미적용** → 타인 배포 시 Gatekeeper 경고(우클릭 > 열기 필요). 공개 배포용
  서명·공증과 **메뉴바 UI**는 남은 과제.

---

## 6. 알려진 차이 / 한계 (Windows 대비)

- **DoH 보호 범위 차이** (가장 중요): Windows는 *모든* 아웃바운드 UDP/53·TCP/53을
  목적지 불문 캡처하므로 DNS 서버를 하드코딩한 앱도 가로챈다. macOS 포팅은 *시스템*
  리졸버를 로컬로 재설정할 뿐이라 **시스템 리졸버를 쓰는 앱만** 커버한다. 평문 DNS
  서버(`8.8.8.8:53` 등)로 직접 말하는 앱은 DoH를 우회하고, **DPI on 시 그 UDP/53은
  깨질 수도** 있다(로컬 SOCKS5는 CONNECT만 구현, UDP ASSOCIATE 없음 → tun2socks가
  그 데이터그램을 못 흘림). 대부분의 앱은 시스템 리졸버를 써서 실사용엔 문제 없지만
  실제 보호 범위 차이다.
- **권한**: root 필요는 동일. pf/Network Extension과 달리 utun·DNS 조작은 코드서명
  없이 root면 가능 (Apple Developer Program 불필요).
- **QUIC/HTTP-3 (UDP/443)**: Windows와 동일하게 미처리.
- **성능**: 443 릴레이가 userspace Python(SOCKS5)을 거치는 점은 동일. 추가로
  tun2socks utun 홉이 더해진다.
- **VPN 공존**: VPN의 utun/스코프 리졸버와 충돌 가능 (2절 참조).

---

# 부록 A — 폐기된 pf rdr 설계(기록)

> 아래는 1차 시도였던 **pf `rdr`** 방식이다. 스파이크 A에서 "로컬 발신 트래픽
> 가로채기 불가"가 확인되어 **폐기**됐고, 위 본문(utun + DNS 스왑)으로 대체됐다.
> 기록 목적으로만 보존한다.

## A.0 스파이크 A 결과 (2026-06-26) — pf rdr 불가

macOS 26.5.1, pf Disabled 상태에서 TEST-NET(198.51.100.1:9999) 대상 로컬 발신
연결이 로컬 리스너로 redirect 되는지 4가지 규칙으로 시험:

| 변형 | 결과 |
|------|------|
| A: `rdr pass on en0` | ❌ redirect 안 됨 |
| B: `rdr pass on lo0` | ❌ redirect 안 됨 |
| C: `rdr pass` (인터페이스 미지정) | ❌ redirect 안 됨 |
| D: `pass out route-to (lo0 127.0.0.1)` | ❌ (애초에 포트 변환 불가, 무효 테스트) |

**결론**: macOS pf의 `rdr`은 인터페이스로 **들어오는(inbound)** 패킷에만 적용되며,
이 호스트가 스스로 만들어내는 아웃바운드 연결에는 매칭되지 않는다. Linux `iptables
OUTPUT REDIRECT` 대응 메커니즘이 macOS pf엔 없고 `divert-to`도 없다(OpenBSD pf
포크라 `divert-to`/`divert-packet` 제거됨). 따라서 **pf 단독으로는 로컬 발신
트래픽의 투명 가로채기 불가** → pf 방식 폐기.

## A.1 원래 pf 설계 개요 (참고)

pf가 동작했다면 의도했던 모델:

| | Windows (WinDivert) | macOS (pf, 폐기) |
|---|---|---|
| 가로채기 | 전 패킷 캡처 후 주소 재작성·재주입 | 커널이 `rdr`로 목적지 재작성 (자동) |
| 복귀 경로 | `_conn_map`으로 응답 src 수동 복원 | pf NAT 상태가 자동 역변환 |
| 원본 목적지 | 패킷에 그대로 있음 | `/dev/pf` `DIOCNATLOOK` ioctl로 조회 |
| 권한 | Administrator (드라이버 로드) | root (`pfctl` + `/dev/pf`) |
| 종료 시 원복 | 핸들 닫으면 끝 | 앵커 flush + pf 원상복구 |

후보였던 rdr 규칙과 원본 목적지 복구(`DIOCNATLOOK`), 전용 앵커(`com.freegsm`)
생명주기 설계 등은 스파이크 A 실패로 구현되지 않았다. 핵심 통찰("로컬 발신 redirect
가부가 전체 설계의 전제")은 검증으로 부정됐고, 그 자리를 utun이 대체했다.
