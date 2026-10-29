//! ESP in tunnel mode (RFC 4303), AES-GCM per RFC 4106. Packets travel
//! UDP-encapsulated (RFC 3948), so no raw socket is needed.

use anyhow::{bail, ensure};

use crate::crypto::Cipher;

pub const NEXT_HEADER_IPV4: u8 = 4;
pub const NEXT_HEADER_UDP: u8 = 17;
pub const NEXT_HEADER_NONE: u8 = 59;

/// Sequence number past which the SA should be rekeyed.
pub const SEQ_REKEY_THRESHOLD: u64 = 0xffff_0000;

pub struct EspSa {
    pub spi: u32,
    cipher: Cipher,
    seq: u64,
    replay: ReplayWindow,
    /// Payload bytes protected so far, for kilobyte lifetimes.
    bytes: u64,
}

impl EspSa {
    pub fn new(spi: u32, cipher: Cipher) -> Self {
        Self { spi, cipher, seq: 0, replay: ReplayWindow::default(), bytes: 0 }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn encapsulate(&mut self, payload: &[u8], next_header: u8) -> anyhow::Result<Vec<u8>> {
        ensure!(self.seq < u64::from(u32::MAX), "ESP sequence number exhausted");
        self.seq += 1;
        self.bytes += payload.len() as u64;
        let align = self.cipher.block_len().max(4);
        let pad = (align - (payload.len() + 2) % align) % align;
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&self.spi.to_be_bytes());
        header[4..].copy_from_slice(&(self.seq as u32).to_be_bytes());
        let iv = self.cipher.make_iv(self.seq);
        // Header, IV, payload and trailer in one buffer, encrypted in place.
        let mut out = Vec::with_capacity(8 + iv.len() + payload.len() + pad + 2 + self.cipher.icv_len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&iv);
        out.extend_from_slice(payload);
        out.extend(1..=pad as u8);
        out.extend_from_slice(&[pad as u8, next_header]);
        self.cipher.seal_in_place(&mut out, header.len(), &header);
        Ok(out)
    }

    /// Returns (next header, inner packet).
    pub fn decapsulate(&mut self, packet: &[u8]) -> anyhow::Result<(u8, Vec<u8>)> {
        ensure!(packet.len() >= 8, "ESP packet too short");
        ensure!(packet[..4] == self.spi.to_be_bytes(), "ESP SPI mismatch");
        let seq = u32::from_be_bytes(packet[4..8].try_into().unwrap());
        self.replay.check(seq)?;
        let mut plain = self.cipher.open(&packet[..8], &packet[8..])?;
        self.replay.update(seq);
        ensure!(plain.len() >= 2, "ESP trailer missing");
        let next_header = plain[plain.len() - 1];
        let pad = plain[plain.len() - 2] as usize;
        ensure!(pad + 2 <= plain.len(), "bad ESP padding");
        plain.truncate(plain.len() - 2 - pad);
        self.bytes += plain.len() as u64;
        Ok((next_header, plain))
    }
}

/// 64-packet anti-replay window (RFC 4303 §3.4.3).
#[derive(Debug, Default)]
pub struct ReplayWindow {
    top: u32,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn check(&self, seq: u32) -> anyhow::Result<()> {
        if seq == 0 {
            bail!("ESP sequence number 0");
        }
        if seq > self.top {
            return Ok(());
        }
        let diff = self.top - seq;
        if diff >= 64 {
            bail!("ESP packet {seq} outside the replay window");
        }
        if self.bitmap & (1 << diff) != 0 {
            bail!("replayed ESP packet {seq}");
        }
        Ok(())
    }

    /// Records `seq`; call only after the packet authenticated.
    pub fn update(&mut self, seq: u32) {
        if seq > self.top {
            let shift = seq - self.top;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.top = seq;
        } else {
            self.bitmap |= 1 << (self.top - seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EncrAlg, IntegAlg};

    fn pair(gcm: bool) -> (EspSa, EspSa) {
        let make = || {
            if gcm {
                Cipher::new(EncrAlg::AesGcm16 { key_bits: 256 }, None, &[3u8; 36], &[]).unwrap()
            } else {
                Cipher::new(
                    EncrAlg::AesCbc { key_bits: 256 },
                    Some(IntegAlg::HmacSha256Trunc128),
                    &[3u8; 32],
                    &[4u8; 32],
                )
                .unwrap()
            }
        };
        (EspSa::new(0x1234, make()), EspSa::new(0x1234, make()))
    }

    #[test]
    fn roundtrip_and_replay() {
        for gcm in [true, false] {
            let (mut tx, mut rx) = pair(gcm);
            for len in [0usize, 1, 20, 61, 1400] {
                let packet: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let esp = tx.encapsulate(&packet, NEXT_HEADER_IPV4).unwrap();
                let (nh, inner) = rx.decapsulate(&esp).unwrap();
                assert_eq!(nh, NEXT_HEADER_IPV4);
                assert_eq!(inner, packet);
                assert!(rx.decapsulate(&esp).is_err(), "replay must be rejected");
            }
            let mut esp = tx.encapsulate(b"hello", NEXT_HEADER_IPV4).unwrap();
            let last = esp.len() - 1;
            esp[last] ^= 1;
            assert!(rx.decapsulate(&esp).is_err());
        }
    }

    #[test]
    fn replay_window_accepts_reordering() {
        let mut w = ReplayWindow::default();
        for seq in [1, 3, 2, 100, 40, 99] {
            w.check(seq).unwrap();
            w.update(seq);
        }
        assert!(w.check(3).is_err());
        assert!(w.check(36).is_err(), "older than the window");
        assert!(w.check(37).is_ok());
        assert!(w.check(0).is_err());
        w.update(1000);
        assert!(w.check(999).is_ok());
        assert!(w.check(100).is_err());
    }
}
