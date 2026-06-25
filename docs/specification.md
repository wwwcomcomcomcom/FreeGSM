# FreeGSM — 구현 사양 (Specification)

`rustify` 브랜치에 구현된 Rust 버전의 동작·구조 사양. 이 문서는 **현재 코드가
무엇을 어떻게 하는지**를 정의한다(설계 의도/배경은 `migration.md`, 코드 주석 참조).

- 산출물: 단일 네이티브 실행 파일 `FreeGSM.exe` (~1.9 MB) + `WinDivert.dll` +
  `WinDivert64.sys`.
- 원본 Python 구현(`dohproxy/`)은 참조용으로 보존되며, 동작은 1:1로 이식됨.
- 대상 플랫폼: Windows x64, 관리자 권한 필수, **IPv4 전용**.

---

## 1. 개요 (Overview)

FreeGSM은 **시스템 설정을 전혀 바꾸지 않고** 머신의 평문 DNS를
**DNS-over-HTTPS(DoH)** 로 투명하게 업그레이드하고, **SNI 기반 DPI 차단**을
우회한다. 프로세스를 종료하면 모든 것이 즉시 원상 복구된다(되돌릴 상태가 없음 —
WinDivert 핸들이 닫히면 패킷 가로채기가 멈춘다).

단일 **WinDivert 캡처 루프**가 두 개의 독립적인 작업을 구동한다.

1. **DoH** — 아웃바운드 DNS(UDP/53 + TCP/53)를 암호화된 HTTP/2 연결로 DoH 서버에
   재질의한다. 무상태: DNS 질의와 DoH 요청 본문은 *같은 바이트*(RFC 8484)이므로
   DNS 파싱이 없다.
2. **SNI/DPI 우회** — 아웃바운드 TCP/443을 로컬 릴레이로 종단시켜 TLS ClientHello를
   **두 개의 TLS 레코드**로 재전송한다(레코드-레이어 프래그멘테이션, Jigsaw Intra
   이식). 한-레코드 SNI 매처는 호스트명을 못 읽지만 서버는 정상 재조립한다. 토글:
   `FREEGSM_DPI`.

---

## 2. 범위 (Scope)

**지원**
- WinDivert 단일 캡처 루프 + 디스패치 (IPv4)
- DoH 클라이언트: HTTP/2, keep-alive, 리터럴 IP 접속, **IP SAN 검증**, fail-closed
- 기동 시 upstream probe → 도달 불가 시 기동 거부
- UDP/53 응답 합성 (in-place 패킷 변환, inbound 주입)
- TCP/53 투명 리다이렉트 → 로컬 DoH 종단 서버
- TCP/443 SNI 릴레이 + TLS 레코드 프래그멘테이션
- 환경변수 설정 `FREEGSM_DOH_URL` / `FREEGSM_DPI`
- 관리자 권한 확인, release 빌드 UAC 자기상승(manifest), Ctrl+C 정상 종료

**미지원 (의도적)**
- IPv6, QUIC/HTTP-3(UDP/443), DNS 캐시
- `config.yml` (Python 빌드에는 있으나 본 포트는 환경변수만 지원)

---

## 3. 모듈 구조 (`src/`)

| 파일 | 책임 |
|------|------|
| `main.rs` | 진입점. 로거 초기화 → 관리자 확인 → config 초기화 → DoH 시작 → **upstream probe(불가 시 거부)** → TCP/HTTPS 서버 시작 → 캡처 스레드 기동 → Ctrl+C 대기. |
| `config.rs` | 모든 튜너블 + `DIVERT_FILTER` 빌더 + 환경변수 파싱. 전역 `OnceLock<Config>`. **캡처 필터를 이해하려면 여기부터.** |
| `divert.rs` | `Diverter`: 단일 WinDivert 핸들. recv 루프 → `dispatch()`가 패킷을 분류·라우팅. `Injector`(락 직렬화 주입) + `inject_inbound`(방향 전환·체크섬 재계산·주입). |
| `doh.rs` | DoH 클라이언트(공유 `reqwest::blocking::Client`, HTTP/2, rustls). `resolve(query)->Vec<u8>`, `probe()`. 실패 시 `Err` 반환(fail-closed). |
| `udp.rs` | UDP/53: **스레드풀**에서 실행(블로킹 DoH 왕복). 캡처 패킷을 응답으로 in-place 변환 후 inbound 주입. |
| `tcp_proxy.rs` | TCP/53: WinDivert 리다이렉트 → 로컬 DoH 종단 서버(`std::net`, 연결당 스레드). 패킷 재작성은 **캡처 스레드에서 인라인**. |
| `https_proxy.rs` | TCP/443 SNI 릴레이: 같은 리다이렉트 기법으로 종단 → `dpi::split_hello`로 ClientHello 분할 → 양방향 파이프. 예약 업스트림 포트 풀. |
| `dpi.rs` | 순수 TLS 처리: `split_hello`, `tls_record_len`, `sni_name`(로그용). I/O 없음. |
| `dnsutil.rs` | `describe_query` — 로그용 사람이 읽는 질의 문자열. 절대 panic 안 함. |
| `netpkt.rs` | IPv4/TCP/UDP 헤더 필드 접근·변환 헬퍼(슬라이스 기반). pydivert의 파싱 대체. |
| `logging.rs` | 경량 `log::Log` 구현. `GetLocalTime`으로 `%H:%M:%S` 로컬시각. |
| `rng.rs` | 분할 지점용 비암호 PRNG(xorshift64*). `rand` 크레이트 회피. |

빌드 보조: `build.rs`(release에서만 manifest/아이콘 임베드), `freegsm.manifest`,
`freegsm.rc`, `build.ps1`.

---

## 4. 패킷 디스패치 (`divert.rs::dispatch`)

캡처 스레드는 각 패킷에서 `proto / outbound / dst_port / src_port`를 읽어 분류한다.

```
outbound UDP dst:53                              -> udp::handle        (스레드풀)
TCP, DPI 켜짐 그리고
  (outbound dst:443  또는  src == HTTPS_PROXY_PORT) -> https_proxy::handle_packet  (인라인)
그 외 TCP (dst:53 / src == TCP_PROXY_PORT)        -> tcp_proxy::handle_packet    (인라인)
그 외                                            -> 그대로 주입
```

### 리다이렉트 레시피 (TCP/53·443 공통)

두 릴레이 모두 동일한 WinDivert 리다이렉트 기법을 쓴다.

- **아웃바운드 client→server 패킷**: 원래 목적지를 `(src_addr, src_port)` 키로
  기억 → 목적지를 `src_addr:<로컬-포트>`로 재작성 → **INBOUND로 주입**
  (호스트의 실제 인터페이스 IP를 향함 — `127.0.0.1`은 WinDivert에서 동작 안 함).
- **relay→client 응답 패킷**(`src == 로컬-포트`): `(dst_addr, dst_port)` 키로
  원래 서버를 조회 → 소스를 실제 `server:port`로 되돌림 → INBOUND로 주입.

연결 맵 키는 `(Ipv4Addr, u16)` → `(Ipv4Addr, u16)`.

- `tcp_proxy`의 맵은 **캡처 스레드 전용**(로컬 DoH 서버가 원래 목적지를 알 필요
  없음) → 락 없음(`HashMap`, `Diverter::run`의 지역 변수로 소유).
- `https_proxy`의 맵은 캡처 스레드가 쓰고 핸들러 스레드가 읽음(릴레이가 실제
  서버로 업스트림 연결 필요) → `OnceLock<Mutex<HashMap>>`.

### in-place 변환 흐름

`recv` → 변경이 필요한 핸들러는 `packet.data.to_mut()`로 소유권 확보 후 헤더
필드만 수정 → `inject_inbound`가 `address.set_outbound(false)` →
`recalculate_checksums(ChecksumFlags::new())`(전체 재계산) → 락 직렬화 주입.

---

## 5. 동시성 모델 (Concurrency)

| 실행 영역 | 위치 | 규칙 |
|-----------|------|------|
| **캡처 스레드 (단일)** | `Diverter::run` | `WinDivert::recv()` 블로킹 루프. 디스패치 분류 + **TCP 패킷 재작성(인라인, 빠르고 non-blocking)**. tcp 연결 맵은 이 스레드만 소유 → 락 불필요. |
| **DoH 라운드트립 (블로킹)** | `udp.rs` (스레드풀, 기본 32) / `tcp_proxy.rs` (연결당 스레드) | 블로킹 DoH 왕복은 캡처 스레드 밖에서. |
| **443 릴레이** | `https_proxy.rs` (연결당 + 역방향 펌프 스레드) | `std::net` 블로킹 I/O, 양방향 파이프. |
| **주입 직렬화** | `divert::Injector` | `Arc<Handle>` 공유, `Mutex<()>` `send_lock`으로 `WinDivertSend` 직렬화. `recv`는 락 없이 캡처 스레드에서 동시 실행(WinDivert 핸들은 recv/send 동시 호출에 thread-safe). |

- WinDivert 핸들은 `Arc<Handle>`로 공유되며 `Handle`에 `unsafe impl Send + Sync`
  (WinDivert 핸들의 thread-safety가 근거). `Injector`는 `Clone`되어 모든 핸들러에
  전달됨.
- 캡처 스레드에서 주입할 패킷은 `WinDivertPacket<'static>`(`into_owned`)으로 만들어
  스레드풀로 이동(`Send`).
- 종료: 전역 `AtomicBool STOP`. Ctrl+C 핸들러(`ctrlc`)와 캡처 루프 종료 시
  `request_stop()` 설정 → `main`이 폴링 후 종료. 프로세스 종료가 핸들을 닫아 DNS
  복원.

---

## 6. 불변식 (Invariants — 깨지면 조용히 실패)

1. **WinDivert 경로에서 바이트 삽입/삭제 금지.** 주소/포트/페이로드-전체 교체만
   허용(UDP 응답은 페이로드 전체 교체 + IP/UDP 길이 필드 갱신). ClientHello 분할은
   소켓 양쪽을 소유한 userspace 릴레이(`https_proxy`)에서만 수행. 바이트를 끼워넣으면
   클라이언트 커널의 TCP 시퀀스가 어긋나 RST 발생.
2. **Fail-closed.** DoH 실패 시 쿼리 드롭(`FAIL_OPEN = false`). 그래서 기동 시
   `probe()` 실패면 캡처를 시작하지 않고 종료(머신 DNS 무손상).
3. **릴레이 업스트림 소켓은 예약 source-port 범위(30000–32047)에 bind** →
   `DIVERT_FILTER`가 제외 → 재캡처/주입 루프 없음. DoH upstream IP도 동일 제외.
4. **주입 패킷이 필터에 재매치되지 않게.** 리다이렉트 쿼리는 dst==proxy-port(≠53),
   재작성 응답은 src==53 / src==443. 합성한 UDP 응답은 inbound·dst!=53.
5. **루프백 주입 안 됨.** 리다이렉트는 호스트의 실제 인터페이스 IP를 향해 INBOUND.
6. **로그는 절대 panic 금지.** `describe_query`/`sni_name`은 어떤 입력에도 안전한
   문자열 반환(`Option`을 삼키고 fallback). `panic = "abort"`이므로 핸들러 전반이
   panic-free여야 함(모든 인덱싱은 `get()`/길이 가드).

---

## 7. 설정 (`config.rs`)

### 환경변수 (재빌드 불필요)

| 변수 | 기본값 | 의미 |
|------|--------|------|
| `FREEGSM_DOH_URL` | `https://1.0.0.1/dns-query` | DoH upstream. 리터럴 IP로 접속해 DoH 호스트 해석에 DNS가 필요 없게 함(인증서 IP SAN으로 검증). 빈 문자열은 기본값으로 취급. 대안: `https://8.8.8.8/dns-query`, `https://9.9.9.9/dns-query`. |
| `FREEGSM_DPI` | `true` | SNI/443 릴레이 토글. 존재하고 값이 `{0,false,no,off,""}`(대소문자·공백 무시)가 아니면 true; 부재 시 기본 true. |

`DOH_SERVER_IP`는 `FREEGSM_DOH_URL`이 점-4분할 IPv4 리터럴일 때 그 호스트로 도출되며,
DPI 필터에서 우리 자신의 DoH 채널을 제외하는 데 쓰인다(호스트명이면 `None`).

### 컴파일타임 상수

| 상수 | 값 |
|------|----|
| `TCP_BIND_HOST` | `0.0.0.0` |
| `TCP_PROXY_PORT` | `53533` |
| `HTTPS_PROXY_PORT` | `53444` |
| `UPSTREAM_PORT_BASE` / `_COUNT` | `30000` / `2048` (→ 30000–32047) |
| `SPLIT_MIN` / `SPLIT_MAX` | `6` / `64` (첫 레코드 크기 바운드, 5바이트 헤더 포함) |
| `DOH_TIMEOUT` | `5s` |
| `HTTPS_CONNECT_TIMEOUT` / `HTTPS_FIRST_READ_TIMEOUT` | `8s` / `8s` |
| `FAIL_OPEN` | `false` |
| `WORKER_THREADS` | `32` |

### DIVERT_FILTER (Python과 바이트 동일, 단위 테스트로 고정)

기본값(DPI 켜짐, upstream `1.0.0.1`):

```
ip and ((outbound and udp.DstPort == 53)
 or (outbound and tcp.DstPort == 53)
 or (tcp.SrcPort == 53533)
 or (outbound and tcp.DstPort == 443 and ip.DstAddr != 1.0.0.1
     and (tcp.SrcPort < 30000 or tcp.SrcPort > 32047))
 or (tcp.SrcPort == 53444))
```

(실제 문자열은 개행 없는 한 줄.) DPI 꺼짐이면 마지막 두 절이 빠진다. upstream이
호스트명이면 `ip.DstAddr != ...` 절이 빠진다.

WinDivert 핸들은 `WinDivertLayer::Network`, priority `0`, 기본 플래그로 열린다.

---

## 8. DoH 클라이언트 (`doh.rs`)

- 공유 `reqwest::blocking::Client`: `use_rustls_tls()`, HTTP/2(ALPN), 타임아웃
  `DOH_TIMEOUT`, keep-alive 풀(`pool_max_idle_per_host(8)`, idle 90s).
- `resolve(query)`: `POST {DOH_URL}` 본문=질의 바이트, 헤더
  `Content-Type/Accept: application/dns-message` → `error_for_status` → 본문 반환.
  빈 본문은 에러. **어떤 실패든 `Err`** 를 돌려 호출자가 fail-closed 하게 함.
- `probe()`: 고정 `example.com A` 질의로 `resolve` 시도 → `(ok, detail)`.
- **리터럴 IP + IP SAN 검증 + HTTP/2** 가 reqwest+rustls에서 동작함을 라이브
  테스트로 확인(`cargo test -- --ignored live_probe`).

---

## 9. SNI/DPI 우회 (`dpi.rs` + `https_proxy.rs`)

### `split_hello` (Intra 이식, Python과 byte-for-byte 일치)

- 입력이 유효한 TLS 레코드(`0x16` + 레코드 버전 `0x0301..0x0304`)면 **두 개의 유효한
  TLS 레코드**로 재구성(레코드-레이어 프래그멘테이션):
  - 첫 레코드: 원본 5바이트 헤더의 길이 필드를 `split_len-5`로 재기록 + 그만큼의
    핸드셰이크 바이트.
  - 둘째 레코드: 원본 헤더 사본(길이 = 나머지) + 남은 핸드셰이크 바이트.
- `split_len`은 `[SPLIT_MIN, SPLIT_MAX]`에서 무작위, 길이의 절반으로 상한(둘째
  세그먼트가 비지 않도록).
- 분할 불가(비-TLS, 또는 `record_split_len`이 0/범위초과)면 단순 2분할 폴백.
- `sni_name`은 로그용 best-effort(분할은 SNI에 의존하지 않음).

### 릴레이 (`https_proxy.rs`)

- 리다이렉트된 :443 연결을 로컬 서버가 accept. **peer IP == 로컬 IP** 아니면 거부
  (오픈 프록시 방지).
- `(peer_ip, peer_port)`로 원래 서버 조회 → 예약 포트 범위에서 업스트림 소켓
  bind+connect(`socket2`, `connect_timeout`). 포트 사용 중이면 다음 포트, 연결
  실패는 즉시 에러.
- 첫 세그먼트(ClientHello, 단일 `read`로 전량 도착 가정)를 읽어:
  `data[0] == 0x16`이면 `split_hello` 결과 세그먼트들을 업스트림에 각각 write,
  아니면 그대로 전달. 이후 양방향 덤프 파이프(역방향 펌프 스레드 + 현재 스레드).
- 로그: `[HTTPS] ip:port  SNI=<host>  ClientHello <N>B -> 2 TLS records`.

---

## 10. 로깅 (`logging.rs`)

- 포맷: `HH:MM:SS LEVEL<7 target: message` (Python `logging`과 동일,
  `%(levelname)-7s`, `WARNING` 표기).
- 로컬 시각은 `GetLocalTime`(kernel32 FFI). 레벨은 INFO 고정.
- 타깃 네임스페이스: `freegsm`, `freegsm.divert`, `freegsm.udp`, `freegsm.tcp`,
  `freegsm.https`.
- 의미 보존 로그 마커: `[INTERCEPT]` / `[RESOLVED]` / `[FAILED]` / `[HTTPS]`.

---

## 11. 빌드 & 패키징

### 의존성 (`Cargo.toml`)

| 역할 | 크레이트 |
|------|----------|
| WinDivert 바인딩 | `windivert` (features `vendored`) + `windivert-sys` |
| DoH(HTTP/2, TLS) | `reqwest` (default-off, `blocking`+`http2`+`rustls-tls`) |
| 업스트림 소켓 bind | `socket2` |
| URL 파싱 | `url` |
| 로깅 facade | `log` |
| Ctrl+C | `ctrlc` |
| 워커 풀 | `threadpool` |
| 에러 | `anyhow` |
| (빌드) 리소스 임베드 | `embed-resource` |

### release 프로파일 (작은 바이너리)

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### WinDivert 동봉 전략

- `vendored` 피처가 빌드 타임에 번들 C 소스(v2.2.2)에서 **유저모드
  `WinDivert.dll`(+ 링크용 `WinDivert.lib`)** 를 MSVC로 컴파일.
- 커널 드라이버 `WinDivert64.sys`는 **서명 필수**(자가 서명 불가) → WinDivert 공식
  서명본(v2.2.2)을 동봉. pydivert가 번들한 동일 버전 `.sys`를 사용(컴파일된 DLL과
  버전 일치).

### `build.ps1` 산출물 (`dist\`)

```
FreeGSM.exe        # release 빌드, requireAdministrator manifest + 아이콘 임베드
WinDivert.dll      # 컴파일된 유저모드 DLL (target\release\build\...\out)
WinDivert64.sys    # 서명된 커널 드라이버 (pydivert에서 위치 탐색)
```

세 파일은 항상 같은 폴더에 함께 있어야 한다.

### UAC 자기상승

- `build.rs`는 **release 빌드에서만** `freegsm.rc`(manifest + 아이콘)를 임베드.
  → 패키지 exe는 `requireAdministrator`로 실행 시 UAC 프롬프트.
- debug/test 빌드에는 임베드하지 않음 → 비권한에서 `cargo test`/`cargo run` 가능
  (런타임 관리자 확인이 안내 후 코드 1로 종료).

---

## 12. 명령 (Commands)

```powershell
# 소스에서 실행 — 반드시 관리자 권한 터미널 (WinDivert 드라이버 로드)
#   debug 실행 파일은 옆에 WinDivert.dll + WinDivert64.sys 필요
cargo run                       # 비권한이면 안내 후 종료(코드 1)

# 단일 배포 폴더 빌드 -> dist\
powershell -ExecutionPolicy Bypass -File .\build.ps1

# 단위 테스트(비권한 가능)
cargo test
cargo test -- --ignored live_probe   # 라이브 DoH 검증(네트워크 필요)

# 동작 검증 (앱 실행 중, 관리자)
nslookup example.com            # UDP 경로
nslookup -vc example.com        # TCP 경로 강제
python verify_lolps.py [host]   # SNI 우회: "OK HTTP 200" + "-> 2 TLS records" 로그
```

---

## 13. 테스트 (Testing)

`cargo test` — 18개 단위 테스트(비권한). 주요 항목:

- `dpi`: `tls_record_len` 파싱, 2-레코드 분할 구조, 절반 상한, 무작위 분할 재결합,
  **Python `split_hello`와 고정 입력 byte-for-byte 일치**, `sni_name` 추출/안전성.
- `dnsutil`: 이름/타입 파싱, 미지 QTYPE, 가비지 입력 비-panic.
- `config`: `DIVERT_FILTER` Python과 바이트 동일(DPI on/off, 호스트명 upstream),
  리터럴 IPv4 탐지.
- `netpkt`: 필드 읽기, 엔드포인트 스왑, UDP 페이로드 교체 + 길이 갱신, 비-IPv4 거부.
- `doh`(`#[ignore]`): 리터럴 IP + IP SAN + HTTP/2 라이브 probe.

런타임(캡처 루프, UDP/TCP/443 경로)은 **관리자 권한 세션**에서만 검증 가능
(WinDivert 드라이버 필요).

---

## 14. 알려진 한계 (Known gaps)

- QUIC/HTTP-3(UDP/443)은 손대지 않음 — 네트워크가 QUIC SNI를 필터링하면 브라우저
  HTTP/3 비활성화 필요.
- DNS 캐시 없음.
- 443 릴레이는 userspace를 통과(브라우징엔 충분, 대량 전송엔 상대적으로 느림 —
  단, 네이티브 스레드라 Python 대비 빠름).
- 분할은 ClientHello 전체가 첫 `read`에 도착한다고 가정(<16 KB hello에서 참).
- `config.yml` 미지원(환경변수만).
