# FreeGSM — Rust 재작성 Spec & Plan

현재 Python(`dohproxy/`) 구현을 Rust로 포팅하기 위한 설계 문서. 동작 사양은
1:1로 보존하고, 산출물은 **단일 소형 네이티브 실행 파일**로 만든다.

> 상태: **구현 완료(Implemented)** — `rustify` 브랜치. Rust 포트가 루트의
> `Cargo.toml` + `src/`에 있고, Python(`dohproxy/`)은 참조용으로 보존. 빌드/단위
> 테스트/오프라인 검증 통과. WinDivert 캡처 루프·UDP/TCP/443 경로의 **런타임**
> 검증만 관리자 권한 세션에서 별도 필요(아래 §10 참고).

---

## 1. 동기 (Why)

| 항목 | Python 현재 | Rust 목표 |
|------|-------------|-----------|
| 배포 크기 | `dist\FreeGSM.exe` ≈ **35 MB** (CPython + httpx 스택 + PyInstaller 부트로더) | **~3–5 MB** 정적 바이너리 (+ WinDivert DLL/SYS) |
| 443 릴레이 처리량 | userspace Python 파이프 (bulk에 느림) | 네이티브 async I/O |

exe 크기 절감과 443 릴레이 속도 개선이 목적이다.

---

## 2. 범위 (Scope)

**포함 (동작 보존 대상)**
- WinDivert 단일 캡처 루프 + 디스패치
- DoH 클라이언트 (HTTP/2, keep-alive, 리터럴 IP 접속, IP SAN 검증, fail-closed)
- 시작 시 upstream probe → 도달 불가 시 기동 거부
- UDP/53 응답 합성 (in-place 패킷 변환, inbound 주입)
- TCP/53 투명 리다이렉트 → 로컬 DoH 종단 서버
- TCP/443 SNI 릴레이 + TLS 레코드 프래그멘테이션(`split_hello`)
- `FREEGSM_DOH_URL` / `FREEGSM_DPI` 등 환경변수 설정
- 관리자 권한 확인, UAC 자기상승, Ctrl+C 정상 종료
- 로그 포맷(`[INTERCEPT]`/`[RESOLVED]`/`[FAILED]`/`[HTTPS]`)은 의미 보존(문자열 동일 불필요)

**제외 (현재와 동일하게 미지원)**
- IPv6, QUIC/HTTP-3(UDP/443), DNS 캐시

---

## 3. 크레이트 선정 (Dependencies)

| 역할 | 크레이트 | 비고 |
|------|----------|------|
| WinDivert 바인딩 | `windivert` (+ `windivert-sys`) | `recv`/`send`, 패킷 파싱/주입. pydivert의 in-place 헬퍼 대체 |
| 비동기 런타임 | `tokio` (rt-multi-thread, net, io-util, time, sync) | 릴레이/서버/스레드풀 통합 |
| HTTP/2 DoH | `reqwest` (rustls-tls, http2) 또는 `hyper`+`hyper-rustls` | keep-alive 풀, POST `application/dns-message` |
| TLS | `rustls` + `rustls-pki-types` | **IP SAN 검증 필수** (리터럴 IP 접속) |
| 로깅 | `tracing` + `tracing-subscriber` | `%H:%M:%S` 포맷 |
| URL 파싱 | `url` | `DOH_URL`에서 host/IP 추출 |
| 에러 | `anyhow`(앱) / `thiserror`(라이브러리 경계) | |
| Windows API | `windows` (Win32_Security, Shell) | `IsUserAnAdmin`, UAC 상승 |

> **검증 포인트:** `reqwest`로 리터럴 IP(`https://1.0.0.1/...`)에 접속하면서 인증서의
> **IP SAN**으로 검증이 통과하는지 PoC 먼저 확인. 안 되면 `ServerName::IpAddress`를
> 직접 다루는 `hyper` + custom `rustls::ClientConfig` 경로로 전환.

빌드 산출물 추가 절감: `Cargo.toml`에서
```toml
[profile.release]
opt-level = "z"   # 또는 "s"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

---

## 4. 모듈 매핑 (Python → Rust)

```
dohproxy/main.py        -> src/main.rs        진입점, admin 체크, UAC 상승, 기동 시퀀스
dohproxy/config.py      -> src/config.rs      튜너블 + DIVERT_FILTER 빌더 + env 파싱
dohproxy/divert.rs      -> src/divert.rs      WinDivert 핸들 1개, recv 루프, dispatch
dohproxy/doh.py         -> src/doh.rs         DoH 클라이언트, resolve(), probe()
dohproxy/udp_handler.py -> src/udp.rs         UDP/53 in-place 변환 (tokio task)
dohproxy/tcp_proxy.py   -> src/tcp_proxy.rs   TCP/53 리다이렉트 + 로컬 DoH 서버
dohproxy/https_proxy.py -> src/https_proxy.rs TCP/443 릴레이 + 업스트림 포트 풀
dohproxy/dpi.py         -> src/dpi.rs         split_hello / sni_name (순수 함수, I/O 없음)
dohproxy/dnsutil.py     -> src/dnsutil.rs     describe_query (로그용, never panics)
run.py                  -> (불필요)           main.rs가 직접 진입
build.ps1               -> build.ps1          cargo build --release + WinDivert DLL/SYS 동봉
```

`dpi.rs`와 `dnsutil.rs`는 순수 바이트 처리 → **가장 먼저, 단위 테스트와 함께** 포팅한다.

---

## 5. 동시성 모델 (Concurrency)

현재 Python은 두 가지 실행 영역을 가진다. Rust에서도 이 분리를 유지한다.

- **캡처 스레드 (단일)** — `WinDivert::recv()` 블로킹 루프. 디스패치 분류 + TCP
  패킷 재작성(in-place, 빠르고 non-blocking)을 **여기서 직접** 한다. `_conn_map`은
  이 스레드만 만지므로 락 불필요 → Rust에서도 캡처 루프 전용 스레드 + thread-local
  또는 `HashMap`을 캡처 스레드 소유로 둔다.
- **DoH 라운드트립 (블로킹)** — 현재 UDP는 스레드풀, TCP 서버는 핸들러 스레드.
  Rust에서는 tokio 멀티스레드 런타임의 task로 통일. UDP 핸들러는 캡처 스레드에서
  채널로 패킷을 task에 넘기고, 응답 주입은 공유 `WinDivert` 핸들로.
- **주입 동기화** — 현재 `_send_lock`. Rust에서는 `WinDivert` send 핸들을
  `Arc<Mutex<..>>` 또는 전용 주입 task + mpsc 채널(권장: 락 경합 최소화)로 직렬화.

> 캡처 스레드는 동기 블로킹(`recv`)이라 tokio 바깥(`std::thread`)에 두고,
> task 제출은 `tokio::runtime::Handle::spawn` 또는 `mpsc`로 런타임에 넘기는
> 하이브리드 구조가 가장 단순하다.

---

## 6. 불변식 (Invariants — 반드시 보존)

CLAUDE.md의 "Invariants" 섹션을 Rust 구현에서도 동일하게 지킨다. 깨지면 조용히 실패.

1. **WinDivert 경로에서 바이트 삽입/삭제 금지.** 주소/포트/페이로드-전체 교체만 허용.
   ClientHello 분할은 반드시 userspace 릴레이(소켓 양쪽 소유)에서 수행.
2. **Fail-closed.** DoH 실패 시 쿼리 드롭(`FAIL_OPEN=false`). 그래서 기동 시
   `probe()` 실패면 캡처를 시작하지 않고 종료(머신 DNS 무손상).
3. **릴레이 업스트림 소켓은 예약 source-port 범위(30000–32047)에 bind** →
   `DIVERT_FILTER`가 제외 → 재캡처/주입 루프 없음. DoH upstream IP도 동일하게 제외.
4. **주입 패킷이 필터에 재매치되지 않게.** 리다이렉트 쿼리는 dst==proxy-port(≠53),
   재작성 응답은 src==53 / src==443. 핸들러 수정 시 이 성질 유지.
5. **루프백 주입 안 됨.** 리다이렉트는 호스트의 실제 인터페이스 IP를 향해 INBOUND
   주입(127.0.0.1 아님).
6. **로그는 절대 패닉 금지.** `describe_query`/`sni_name`은 어떤 입력에도 안전한
   문자열 반환(`Result`를 삼키고 fallback).

---

## 7. 단계별 계획 (Phased Plan)

각 단계는 독립적으로 검증 가능하게 자른다.

**Phase 0 — 사전 검증 (PoC, 0.5일)**
- `windivert` 크레이트로 elevated에서 `udp.DstPort==53` 캡처/주입 1회 성공
- `reqwest`(rustls)로 `https://1.0.0.1/dns-query`에 IP SAN 검증 통과 + DoH 응답 수신
- ↑ 둘 중 하나라도 막히면 설계 재검토(특히 IP SAN). **여기서 가장 큰 리스크 해소.**

**Phase 1 — 순수 로직 + 테스트**
- `dpi.rs` (`split_hello`, `tls_record_len`, `sni_name`) + `dnsutil.rs`
- Intra 분할 결과를 Python 출력과 대조하는 단위 테스트(고정 ClientHello 샘플)

**Phase 2 — config + DoH**
- `config.rs`: env → default 우선순위, `DIVERT_FILTER` 문자열 생성(현재와
  바이트 동일하게), `DOH_SERVER_IP` 추출
- `doh.rs`: `resolve`, `probe`. fail-closed 시맨틱

**Phase 3 — 캡처 루프 + UDP (DoH 최소 동작)**
- `divert.rs` recv/dispatch, `udp.rs` in-place 변환
- 검증: `nslookup example.com` 통과, 차단 시 plaintext 유출 없음

**Phase 4 — TCP/53**
- `tcp_proxy.rs` 리다이렉트 + 로컬 DoH 종단 서버, `_conn_map`
- 검증: `nslookup -vc example.com`

**Phase 5 — TCP/443 SNI 릴레이**
- `https_proxy.rs` 리다이렉트 + 예약 포트 풀 + ClientHello 분할 + 양방향 파이프
- 검증: `python verify_lolps.py` 대응(또는 Rust 재작성) → `HTTP 200` + 2 records 로그

**Phase 6 — 진입점/패키징**
- `main.rs` admin 체크 + UAC 자기상승(manifest 임베드) + 기동 시퀀스 + Ctrl+C
- `build.ps1`: `cargo build --release` → `target/release/FreeGSM.exe` + WinDivert
  DLL/SYS를 실행 파일 옆에 배치(또는 리소스 임베드 후 첫 실행 시 추출)

---

## 8. 까다로운 포인트 (Risks & Open Questions)

1. **IP SAN 검증 (최우선).** reqwest/rustls가 리터럴 IP에 대한 SAN 검증을 기본
   지원하는지 Phase 0에서 확정. 미지원 시 custom verifier.
2. **WinDivert in-place 변환.** pydivert는 페이로드 재할당 시 길이/체크섬을 자동
   갱신했다. `windivert` 크레이트의 동등 API/수동 체크섬 재계산 여부 확인.
   주소·포트 swap, 페이로드 교체, direction 전환을 동일 패킷 객체에서 수행.
3. **WinDivert DLL/SYS 동봉.** pydivert는 패키지에 번들했다. Rust는 빌드 타임에
   DLL/SYS 경로를 잡아 실행 파일 옆에 복사하거나 리소스 임베드 → 첫 실행 시
   임시 경로 추출 후 로드. (`.sys`는 서명 필요 — WinDivert 공식 서명본 사용.)
4. **UAC 자기상승.** 현재 `--uac-admin`(PyInstaller). Rust는 `app.manifest`에
   `requireAdministrator`를 임베드(`embed-resource`/`winres` 빌드 스크립트).
5. **캡처 스레드 ↔ tokio 브리지.** 동기 블로킹 `recv`와 async task 사이의 패킷
   전달 채널 설계(§5). 주입 직렬화 경합 측정.

---

## 9. 대안: 재작성 없이 크기만 줄이기 (Non-goal이지만 기록)

크기만이 목적이라면 재작성보다 압도적으로 싸다:
- **UPX 설치** (`upx=True`는 이미 켜져 있으나 UPX 바이너리 부재로 무동작):
  35 MB → ~12–15 MB
- **stdlib 제외**: `--exclude-module tkinter,unittest,sqlite3,xml,pydoc,pdb` →
  추가 2–5 MB
- **`optimize=2`** (spec의 `optimize=0`)

→ 합계 **~10–12 MB**, 작업 ~10분, 이미 디버깅 끝난 불변식 재구현 없음.
Rust(~4 MB)와의 차이는 **그 미묘한 패킷 로직을 다시 짤 가치가 있는가**의 문제.
443 릴레이 속도/배포 단순화/학습 동기가 더해질 때만 재작성이 합리적.

---

## 10. 완료 기준 (Definition of Done)

오프라인/비권한 환경에서 검증 가능한 항목은 모두 확인됨. WinDivert 드라이버는
관리자 권한이 필요하므로 캡처 루프 자체의 런타임 검증은 **elevated 세션**에서만
가능(아래 ⏳).

- [x] `dpi`/`dnsutil` 단위 테스트 통과 (Python 출력과 **바이트 동일** 교차검증) —
  `cargo test` 18/18, `split_hello` 고정 입력이 `dohproxy/dpi.py`와 byte-for-byte 일치
- [x] `config` DIVERT_FILTER 문자열이 Python과 바이트 동일 (단위 테스트)
- [x] DoH: **리터럴 IP + IP SAN 검증 + HTTP/2** 라이브 동작 확인
  (`cargo test -- --ignored live_probe`, 8.8.8.8) — 최대 리스크 해소
- [x] `dist` 산출물 ≤ 5 MB — `FreeGSM.exe` **1.89 MB** (+ WinDivert.dll 79 KB +
  WinDivert64.sys 94 KB). Python PyInstaller ≈ 35 MB → ~18배 감소
- [x] UAC 자기상승: release 빌드에 `requireAdministrator` manifest 임베드 확인
  (debug/test 빌드에는 미임베드 → 비권한 실행/테스트 가능)
- [x] 비권한 실행 시 관리자 권한 안내 후 종료(코드 1), 로그 포맷 Python과 동일
- [x] `build.ps1`: `cargo build --release` → `dist\`에 exe + 컴파일된 WinDivert.dll
  + 서명된 WinDivert64.sys(v2.2.2, pydivert 번들) 동봉
- [ ] ⏳ (elevated 필요) `nslookup example.com` / `nslookup -vc example.com` 통과
- [ ] ⏳ (elevated 필요) 차단 환경에서 plaintext DNS 유출 0 (fail-closed)
- [ ] ⏳ (elevated 필요) upstream 도달 불가 시 기동 거부 + 안내 로그 (코드 경로 구현됨)
- [ ] ⏳ (elevated 필요) SNI 우회: 대상 호스트 `HTTP 200` + ClientHello 2개 TLS 레코드
  (`python verify_lolps.py` 그대로 사용 가능)
- [ ] ⏳ (elevated 필요) `FREEGSM_DOH_URL` / `FREEGSM_DPI` 오버라이드 런타임 동작
  (파싱은 단위 테스트로 확인됨)
- [ ] ⏳ (elevated 필요) Ctrl+C 정상 종료 후 일반 DNS 복원
