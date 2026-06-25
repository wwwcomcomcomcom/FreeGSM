//! Minimal IPv4 / TCP / UDP field accessors over a raw packet buffer.
//!
//! The `windivert` crate hands back raw bytes (unlike pydivert, which exposed
//! parsed fields), so we read and mutate the headers ourselves. All functions
//! assume IPv4 and validate lengths; callers must hold the WinDivert invariant
//! of **never inserting/removing bytes on the capture path** (only address/port/
//! whole-payload changes), so checksums can be recomputed by WinDivert on send.

use std::net::Ipv4Addr;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_RST: u8 = 0x04;

/// IPv4 header length in bytes (IHL field * 4), or `None` if the buffer is too
/// short or not IPv4.
pub fn ihl(d: &[u8]) -> Option<usize> {
    let b0 = *d.first()?;
    if b0 >> 4 != 4 {
        return None; // not IPv4
    }
    let len = (b0 & 0x0f) as usize * 4;
    if len < 20 || d.len() < len {
        return None;
    }
    Some(len)
}

pub fn protocol(d: &[u8]) -> Option<u8> {
    d.get(9).copied()
}

pub fn src_addr(d: &[u8]) -> Option<Ipv4Addr> {
    let b = d.get(12..16)?;
    Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

pub fn dst_addr(d: &[u8]) -> Option<Ipv4Addr> {
    let b = d.get(16..20)?;
    Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

pub fn set_src_addr(d: &mut [u8], ip: Ipv4Addr) {
    d[12..16].copy_from_slice(&ip.octets());
}

pub fn set_dst_addr(d: &mut [u8], ip: Ipv4Addr) {
    d[16..20].copy_from_slice(&ip.octets());
}

/// L4 source port (first 2 bytes of the TCP/UDP header, at the IHL offset).
pub fn l4_src_port(d: &[u8]) -> Option<u16> {
    let h = ihl(d)?;
    let b = d.get(h..h + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub fn l4_dst_port(d: &[u8]) -> Option<u16> {
    let h = ihl(d)?;
    let b = d.get(h + 2..h + 4)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub fn set_l4_src_port(d: &mut [u8], port: u16) {
    if let Some(h) = ihl(d) {
        d[h..h + 2].copy_from_slice(&port.to_be_bytes());
    }
}

pub fn set_l4_dst_port(d: &mut [u8], port: u16) {
    if let Some(h) = ihl(d) {
        d[h + 2..h + 4].copy_from_slice(&port.to_be_bytes());
    }
}

/// TCP flags byte (at IHL+13). `0` if not parseable.
pub fn tcp_flags(d: &[u8]) -> u8 {
    match ihl(d) {
        Some(h) => d.get(h + 13).copied().unwrap_or(0),
        None => 0,
    }
}

/// Offset of the UDP payload (IHL + 8-byte UDP header).
pub fn udp_payload_offset(d: &[u8]) -> Option<usize> {
    let h = ihl(d)?;
    let off = h + 8;
    if d.len() >= off {
        Some(off)
    } else {
        None
    }
}

/// Replace a UDP packet's payload in place and fix the IPv4 total-length and UDP
/// length fields. The checksums are left for WinDivert to recompute on send.
pub fn set_udp_payload(d: &mut Vec<u8>, payload: &[u8]) -> bool {
    let Some(h) = ihl(d) else { return false };
    if d.len() < h + 8 {
        return false;
    }
    d.truncate(h + 8);
    d.extend_from_slice(payload);
    let total = d.len() as u16;
    d[2..4].copy_from_slice(&total.to_be_bytes());
    let udp_len = (d.len() - h) as u16;
    d[h + 4..h + 6].copy_from_slice(&udp_len.to_be_bytes());
    true
}

/// Swap source/destination IPv4 addresses and L4 ports (turning a captured query
/// into the shape of its reply).
pub fn swap_endpoints(d: &mut [u8]) {
    let (Some(src), Some(dst)) = (src_addr(d), dst_addr(d)) else {
        return;
    };
    set_src_addr(d, dst);
    set_dst_addr(d, src);
    let (Some(sp), Some(dp)) = (l4_src_port(d), l4_dst_port(d)) else {
        return;
    };
    set_l4_src_port(d, dp);
    set_l4_dst_port(d, sp);
}

#[cfg(test)]
mod tests {
    use super::*;

    // IPv4 (20-byte header) + UDP (8) + 4 payload bytes. src 10.0.0.5:5353 ->
    // dst 8.8.8.8:53.
    fn udp_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + 4];
        p[0] = 0x45; // version 4, IHL 5
        let total = (p.len()) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 5).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
        p[20..22].copy_from_slice(&5353u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        p[24..26].copy_from_slice(&12u16.to_be_bytes()); // udp len
        p[28..32].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        p
    }

    #[test]
    fn reads_fields() {
        let p = udp_packet();
        assert_eq!(ihl(&p), Some(20));
        assert_eq!(protocol(&p), Some(PROTO_UDP));
        assert_eq!(src_addr(&p), Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(dst_addr(&p), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(l4_src_port(&p), Some(5353));
        assert_eq!(l4_dst_port(&p), Some(53));
        assert_eq!(udp_payload_offset(&p), Some(28));
    }

    #[test]
    fn swaps_endpoints() {
        let mut p = udp_packet();
        swap_endpoints(&mut p);
        assert_eq!(src_addr(&p), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(dst_addr(&p), Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(l4_src_port(&p), Some(53));
        assert_eq!(l4_dst_port(&p), Some(5353));
    }

    #[test]
    fn replaces_udp_payload_and_lengths() {
        let mut p = udp_packet();
        let answer = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert!(set_udp_payload(&mut p, &answer));
        assert_eq!(p.len(), 20 + 8 + answer.len());
        let total = u16::from_be_bytes([p[2], p[3]]) as usize;
        assert_eq!(total, p.len());
        let udp_len = u16::from_be_bytes([p[24], p[25]]) as usize;
        assert_eq!(udp_len, 8 + answer.len());
        assert_eq!(&p[28..], &answer[..]);
    }

    #[test]
    fn rejects_non_ipv4() {
        let mut junk = vec![0x60u8; 40]; // version 6
        assert_eq!(ihl(&junk), None);
        junk[0] = 0x45;
        junk.truncate(10); // shorter than header
        assert_eq!(ihl(&junk), None);
    }
}
