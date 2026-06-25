//! TLS ClientHello fragmentation primitives for the SNI/DPI bypass.
//!
//! Faithful port of Jigsaw Intra's `splitHello`
//! (`Android/app/src/go/intra/split/retrier.go`), via the Python `dpi.py`.
//!
//! The key idea is **TLS record-layer fragmentation**, not TCP segmentation: the
//! single ClientHello record is re-emitted as TWO valid TLS records (a handshake
//! message may span records). The split point is early -- within the first
//! ~1..59 bytes of the handshake, before the SNI -- so a DPI box that reads the
//! SNI out of the first TLS record finds a short record with no name, while the
//! destination server reassembles and completes the handshake normally.
//!
//! Pure byte processing, no I/O. `sni_name` is best-effort and never panics.

/// Record-layer content type 0x16 == handshake.
pub const TLS_HANDSHAKE: u8 = 0x16;

/// Legal record versions for a ClientHello (TLS 1.0..1.3 record version field).
const TLS_VERSIONS: [u16; 4] = [0x0301, 0x0302, 0x0303, 0x0304];

/// Return `(record_body_len, ok)` for a buffer that begins with a TLS record
/// header, mirroring Intra's `getTLSClientHelloRecordLen`.
pub fn tls_record_len(h: &[u8]) -> (usize, bool) {
    if h.len() < 5 || h[0] != TLS_HANDSHAKE {
        return (0, false);
    }
    let version = u16::from_be_bytes([h[1], h[2]]);
    if !TLS_VERSIONS.contains(&version) {
        return (0, false);
    }
    (u16::from_be_bytes([h[3], h[4]]) as usize, true)
}

/// Split a ClientHello into segments to write in order.
///
/// Port of Intra's `splitHello`. `min_split`/`max_split` bound the size of the
/// first segment (the 5-byte TLS header included). When `hello` is a valid TLS
/// record this produces two records (record-layer fragmentation); otherwise it
/// falls back to a plain two-way byte split.
pub fn split_hello(hello: &[u8], min_split: usize, max_split: usize) -> Vec<Vec<u8>> {
    if hello.len() <= 1 {
        return vec![hello.to_vec()];
    }
    // Random first-segment size in [min_split, max_split], capped at half so the
    // second segment is never empty. split_len counts the 5-byte TLS header.
    let split_len = crate::rng::range_inclusive(min_split, max_split);
    split_hello_at(hello, split_len)
}

/// Deterministic core of [`split_hello`] for a chosen `split_len`. Separated so
/// the fragmentation logic is unit-testable without randomness.
pub fn split_hello_at(hello: &[u8], split_len: usize) -> Vec<Vec<u8>> {
    if hello.len() <= 1 {
        return vec![hello.to_vec()];
    }

    let limit = hello.len() / 2;
    let split_len = if split_len > limit { limit } else { split_len };

    let (record_len, ok) = tls_record_len(hello);
    // record_split_len = split_len - 5, but guard against underflow when
    // split_len < 5 (the byte-split fallback handles those).
    let record_split_len = split_len.wrapping_sub(5);
    if !ok || split_len < 5 || record_split_len == 0 || record_split_len >= record_len {
        // Not a fragmentable TLS record: just split the bytes in two.
        return vec![hello[..split_len].to_vec(), hello[split_len..].to_vec()];
    }

    // First record: the original 5-byte header with its length field rewritten to
    // record_split_len, followed by that many handshake bytes.
    let mut first = hello[..split_len].to_vec();
    first[3..5].copy_from_slice(&(record_split_len as u16).to_be_bytes());

    // Second record: a fresh copy of the original 5-byte header (length rewritten
    // to the remainder) placed right before the leftover handshake bytes. The 5
    // bytes it overwrites were already sent inside the first record.
    let mut second = hello[split_len - 5..].to_vec();
    second[0..5].copy_from_slice(&hello[0..5]);
    second[3..5].copy_from_slice(&((record_len - record_split_len) as u16).to_be_bytes());

    vec![first, second]
}

/// Best-effort SNI host name from a ClientHello, or `"<no-sni>"`. For logging
/// only; the split does not depend on the SNI. Never panics.
pub fn sni_name(payload: &[u8]) -> String {
    sni_name_inner(payload).unwrap_or_else(|| "<unparseable>".to_string())
}

fn sni_name_inner(p: &[u8]) -> Option<String> {
    // Header (5) + handshake type (1 == ClientHello).
    if p.len() < 6 || p[0] != TLS_HANDSHAKE || *p.get(5)? != 0x01 {
        return Some("<no-sni>".to_string());
    }
    let mut pos = 5usize;
    let hs_len = u32::from_be_bytes([0, *p.get(6)?, *p.get(7)?, *p.get(8)?]) as usize;
    let end = (pos + 4 + hs_len).min(p.len());

    pos += 4 + 2 + 32; // handshake header + client_version + random
    pos += 1 + *p.get(pos)? as usize; // session_id
    pos += 2 + u16::from_be_bytes([*p.get(pos)?, *p.get(pos + 1)?]) as usize; // cipher_suites
    pos += 1 + *p.get(pos)? as usize; // compression_methods

    if pos + 2 > end {
        return Some("<no-sni>".to_string());
    }
    let ext_total = u16::from_be_bytes([*p.get(pos)?, *p.get(pos + 1)?]) as usize;
    let ext_end = (pos + 2 + ext_total).min(end);
    pos += 2;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([*p.get(pos)?, *p.get(pos + 1)?]);
        let elen = u16::from_be_bytes([*p.get(pos + 2)?, *p.get(pos + 3)?]) as usize;
        let body = pos + 4;
        if etype == 0x0000 {
            // server_name: list-len(2) + type(1==host_name) + name-len(2) + name
            let np = body + 2;
            if np < ext_end && *p.get(np)? == 0x00 {
                let nlen = u16::from_be_bytes([*p.get(np + 1)?, *p.get(np + 2)?]) as usize;
                let name = p.get(np + 3..np + 3 + nlen)?;
                let s = String::from_utf8_lossy(name).into_owned();
                return Some(if s.is_empty() { "<empty>".to_string() } else { s });
            }
            return Some("<no-sni>".to_string());
        }
        pos = body + elen;
    }
    Some("<no-sni>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but valid TLS ClientHello record carrying the given SNI.
    fn client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        // server_name extension body
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // server_name_list len
        sni_ext.push(0x00); // name type: host_name
        sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type server_name
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id len
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(0x01); // compression methods len
        body.push(0x00); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.extend_from_slice(&[0, (body.len() >> 8) as u8, body.len() as u8]); // 3-byte len
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(TLS_HANDSHAKE);
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn record_len_parsing() {
        let hello = client_hello("example.com");
        let (len, ok) = tls_record_len(&hello);
        assert!(ok);
        assert_eq!(len, hello.len() - 5);
        assert!(!tls_record_len(&[0x17, 0x03, 0x03, 0, 0]).1); // not handshake
        assert!(!tls_record_len(&[0x16, 0x09, 0x09, 0, 0]).1); // bad version
        assert!(!tls_record_len(&[0x16, 0x03]).1); // too short
    }

    #[test]
    fn split_produces_two_valid_records() {
        let hello = client_hello("blocked.example.org");
        let (record_len, _) = tls_record_len(&hello);
        let split_len = 12; // 5-byte header + 7 handshake bytes in the first record
        let segs = split_hello_at(&hello, split_len);
        assert_eq!(segs.len(), 2);

        // Concatenated payloads (record bodies) must equal the original handshake.
        let first_body = &segs[0][5..];
        let second_body = &segs[1][5..];
        let mut rejoined = Vec::new();
        rejoined.extend_from_slice(first_body);
        rejoined.extend_from_slice(second_body);
        assert_eq!(rejoined, hello[5..]);

        // First record: rewritten length == bytes after its header.
        assert_eq!(&segs[0][0..3], &hello[0..3]); // type + version preserved
        let first_len = u16::from_be_bytes([segs[0][3], segs[0][4]]) as usize;
        assert_eq!(first_len, split_len - 5);
        assert_eq!(first_len, segs[0].len() - 5);

        // Second record: same header type/version, length == remainder.
        assert_eq!(&segs[1][0..3], &hello[0..3]);
        let second_len = u16::from_be_bytes([segs[1][3], segs[1][4]]) as usize;
        assert_eq!(second_len, record_len - (split_len - 5));
        assert_eq!(second_len, segs[1].len() - 5);
    }

    #[test]
    fn matches_python_split_hello_byte_for_byte() {
        // Cross-checked against dohproxy/dpi.py with random.randint forced to 12
        // on this exact fixed record (header(5) + bytes 0..44).
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x2D];
        hello.extend(0u8..45);
        let segs = split_hello_at(&hello, 12);
        let seg0 = hex::decode_pairs("160301000700010203040506");
        let seg1 = hex::decode_pairs(
            "16030100260708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c",
        );
        assert_eq!(segs[0], seg0);
        assert_eq!(segs[1], seg1);
    }

    // Tiny hex decoder so the test stays dependency-free.
    mod hex {
        pub fn decode_pairs(s: &str) -> Vec<u8> {
            let b = s.as_bytes();
            (0..b.len() / 2)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
                .collect()
        }
    }

    #[test]
    fn non_tls_falls_back_to_byte_split() {
        let data = vec![0xAAu8; 40];
        let segs = split_hello_at(&data, 10);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].len(), 10);
        assert_eq!(segs[1].len(), 30);
        let mut rejoined = segs[0].clone();
        rejoined.extend_from_slice(&segs[1]);
        assert_eq!(rejoined, data);
    }

    #[test]
    fn split_len_capped_at_half() {
        let hello = client_hello("example.com");
        // Ask for a huge split; it must cap so the second segment is non-empty.
        let segs = split_hello_at(&hello, hello.len() * 2);
        assert_eq!(segs.len(), 2);
        assert!(!segs[1].is_empty());
    }

    #[test]
    fn random_split_stays_in_bounds_and_rejoins() {
        let hello = client_hello("cdn.example.net");
        for _ in 0..200 {
            let segs = split_hello(&hello, 6, 64);
            assert_eq!(segs.len(), 2);
            let first_body = &segs[0][5..];
            let second_body = &segs[1][5..];
            let mut rejoined = Vec::from(first_body);
            rejoined.extend_from_slice(second_body);
            assert_eq!(rejoined, hello[5..]);
        }
    }

    #[test]
    fn sni_extraction() {
        assert_eq!(sni_name(&client_hello("lol.ps")), "lol.ps");
        assert_eq!(sni_name(&client_hello("www.example.com")), "www.example.com");
        // Non-handshake / garbage never panics.
        assert_eq!(sni_name(&[0x17, 0x03, 0x03, 0x00, 0x05]), "<no-sni>");
        assert_eq!(sni_name(&[]), "<no-sni>");
        let _ = sni_name(&[0x16, 0x03, 0x03, 0xff, 0xff, 0x01, 0x00, 0x00]); // truncated, must not panic
    }
}
