//! Transport mode data path (RFC 3193): ESP carries UDP segments of one
//! port. The layer above exchanges whole IPv4/UDP packets with the SA, so
//! that it speaks the same `PacketIo` as a tunnel.

use super::TransportMode;

/// The UDP segment of `packet` if it goes from our port to the
/// gateway's.
pub fn outbound_segment<'a>(packet: &'a [u8], t: &TransportMode) -> Option<&'a [u8]> {
    let ihl = usize::from(packet.first()? & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let segment = packet.get(ihl..)?;
    let (sport, dport) = ports(segment)?;
    (packet[9] == crate::esp::NEXT_HEADER_UDP && packet[16..20] == t.gateway.octets())
        .then_some(segment)
        .filter(|_| sport == t.port && dport == t.port)
}

/// A decrypted UDP segment as an IPv4 packet from the gateway, if it is
/// for the SA's port; its checksum is not checked (ESP authenticates it).
pub fn inbound_packet(segment: &[u8], t: &TransportMode) -> Option<Vec<u8>> {
    let (sport, dport) = ports(segment)?;
    let len = u16::from_be_bytes([segment[4], segment[5]]);
    if sport != t.port || dport != t.port || usize::from(len) > segment.len() || len < 8 {
        return None;
    }
    let segment = &segment[..usize::from(len)];
    let total = u16::try_from(20 + segment.len()).ok()?;
    let mut packet = Vec::with_capacity(usize::from(total));
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, crate::esp::NEXT_HEADER_UDP, 0, 0]);
    packet.extend_from_slice(&t.gateway.octets());
    packet.extend_from_slice(&t.local.octets());
    let sum = checksum(&packet);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(segment);
    // No UDP checksum: it covered the gateway's view of the addresses.
    packet[26..28].copy_from_slice(&[0, 0]);
    Some(packet)
}

fn ports(segment: &[u8]) -> Option<(u16, u16)> {
    (segment.len() >= 8)
        .then(|| (u16::from_be_bytes([segment[0], segment[1]]), u16::from_be_bytes([segment[2], segment[3]])))
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn segments_and_packets() {
        let t = TransportMode {
            local: Ipv4Addr::new(192, 168, 1, 10),
            gateway: Ipv4Addr::new(203, 0, 113, 5),
            port: 1701,
            nat_oa: 21,
        };
        let segment = [0x06, 0xa5, 0x06, 0xa5, 0, 12, 0xab, 0xcd, 1, 2, 3, 4];
        let packet = inbound_packet(&segment, &t).unwrap();
        assert_eq!((packet.len(), checksum(&packet[..20])), (32, 0), "valid IPv4 header");
        assert_eq!(&packet[12..16], &t.gateway.octets());
        assert_eq!(&packet[28..], &[1, 2, 3, 4]);
        // Ours to the gateway: what an L2TP layer builds.
        let mut ours = packet.clone();
        ours[12..16].copy_from_slice(&t.local.octets());
        ours[16..20].copy_from_slice(&t.gateway.octets());
        assert_eq!(outbound_segment(&ours, &t).unwrap().len(), 12);
        ours[22] = 0x13; // another port
        assert!(outbound_segment(&ours, &t).is_none());
        let mut other = segment;
        other[1] = 0x35; // from port 53
        assert!(inbound_packet(&other, &t).is_none());
    }
}
