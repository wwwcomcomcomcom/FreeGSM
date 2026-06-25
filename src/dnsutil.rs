//! Tiny helper to make DNS queries human-readable for logging. Never panics:
//! any malformed input yields a best-effort fallback string.

/// Common QTYPE numbers -> names (anything else is shown as `TYPE<n>`).
fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        35 => "NAPTR".into(),
        43 => "DS".into(),
        48 => "DNSKEY".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// e.g. `"example.com A"` from a raw DNS query, or a fallback if unparseable.
pub fn describe_query(query: &[u8]) -> String {
    describe_inner(query).unwrap_or_else(|| format!("<unpar? {}B>", query.len()))
}

fn describe_inner(query: &[u8]) -> Option<String> {
    // Skip the 12-byte header, then read the QNAME labels.
    let mut i = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *query.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        let label = query.get(i..i + len)?;
        // On-wire labels are ASCII (IDNs arrive as xn-- punycode already).
        labels.push(String::from_utf8_lossy(label).into_owned());
        i += len;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    let qtype = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
    Some(format!("{name} {}", qtype_name(qtype)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Header (id=0, flags, qd=1) + 7"example"3"com"0 + QTYPE A + QCLASS IN
    const EXAMPLE_A: &[u8] = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
\x07example\x03com\x00\x00\x01\x00\x01";

    #[test]
    fn parses_name_and_type() {
        assert_eq!(describe_query(EXAMPLE_A), "example.com A");
    }

    #[test]
    fn known_and_unknown_qtypes() {
        let mut aaaa = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x00".to_vec();
        aaaa.extend_from_slice(&28u16.to_be_bytes()); // AAAA
        aaaa.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(describe_query(&aaaa), "abc AAAA");

        let mut weird = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc\x00".to_vec();
        weird.extend_from_slice(&999u16.to_be_bytes()); // not in the table
        weird.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(describe_query(&weird), "abc TYPE999");
    }

    #[test]
    fn never_panics_on_garbage() {
        assert!(describe_query(&[]).starts_with("<unpar?"));
        assert!(describe_query(&[0u8; 5]).starts_with("<unpar?"));
        // Truncated label length running past the buffer.
        let q = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xff";
        assert!(describe_query(q).starts_with("<unpar?"));
    }
}
