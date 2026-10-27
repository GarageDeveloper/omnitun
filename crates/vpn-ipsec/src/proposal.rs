//! Algorithm proposals written in strongSwan-like syntax, e.g.
//! `aes256gcm16-prfsha256-ecp256` (IKE) or `aes256-sha256-modp2048` (ESP,
//! where the DH group selects PFS for rekeying).

use anyhow::{Context, bail, ensure};

use crate::crypto::{DhGroup, EncrAlg, IntegAlg, PrfAlg};
use crate::ikev2::consts::{protocol, transform};
use crate::ikev2::payload::{Proposal, Transform};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeProposal {
    pub encr: EncrAlg,
    pub integ: Option<IntegAlg>,
    pub prf: PrfAlg,
    pub dh: DhGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspProposal {
    pub encr: EncrAlg,
    pub integ: Option<IntegAlg>,
    /// DH group for PFS when rekeying.
    pub pfs: Option<DhGroup>,
}

#[derive(Default)]
struct Parsed {
    encr: Option<EncrAlg>,
    integ: Option<IntegAlg>,
    prf: Option<PrfAlg>,
    dh: Option<DhGroup>,
}

fn parse_tokens(s: &str) -> anyhow::Result<Parsed> {
    let mut p = Parsed::default();
    for token in s.split('-').map(str::trim).filter(|t| !t.is_empty()) {
        match token.to_ascii_lowercase().as_str() {
            "aes128" => p.encr = Some(EncrAlg::AesCbc { key_bits: 128 }),
            "aes192" => p.encr = Some(EncrAlg::AesCbc { key_bits: 192 }),
            "aes256" => p.encr = Some(EncrAlg::AesCbc { key_bits: 256 }),
            "aes128gcm16" | "aes128gcm128" | "aes128gcm" => p.encr = Some(EncrAlg::AesGcm16 { key_bits: 128 }),
            "aes256gcm16" | "aes256gcm128" | "aes256gcm" => p.encr = Some(EncrAlg::AesGcm16 { key_bits: 256 }),
            "chacha20poly1305" => p.encr = Some(EncrAlg::ChaCha20Poly1305),
            "3des" => p.encr = Some(EncrAlg::TripleDesCbc),
            "sha1" | "sha" => p.integ = Some(IntegAlg::HmacSha1Trunc96),
            "sha256" | "sha2_256" => p.integ = Some(IntegAlg::HmacSha256Trunc128),
            "sha384" | "sha2_384" => p.integ = Some(IntegAlg::HmacSha384Trunc192),
            "sha512" | "sha2_512" => p.integ = Some(IntegAlg::HmacSha512Trunc256),
            "prfsha1" => p.prf = Some(PrfAlg::HmacSha1),
            "prfsha256" => p.prf = Some(PrfAlg::HmacSha256),
            "prfsha384" => p.prf = Some(PrfAlg::HmacSha384),
            "prfsha512" => p.prf = Some(PrfAlg::HmacSha512),
            "modp1024" => p.dh = Some(DhGroup::Modp1024),
            "modp1536" => p.dh = Some(DhGroup::Modp1536),
            "modp2048" => p.dh = Some(DhGroup::Modp2048),
            "modp3072" => p.dh = Some(DhGroup::Modp3072),
            "modp4096" => p.dh = Some(DhGroup::Modp4096),
            "modp6144" => p.dh = Some(DhGroup::Modp6144),
            "modp8192" => p.dh = Some(DhGroup::Modp8192),
            "ecp256" => p.dh = Some(DhGroup::Ecp256),
            "ecp384" => p.dh = Some(DhGroup::Ecp384),
            "ecp521" => p.dh = Some(DhGroup::Ecp521),
            "x25519" | "curve25519" => p.dh = Some(DhGroup::Curve25519),
            "noesn" => {}
            other => bail!("unsupported algorithm '{other}' in proposal '{s}'"),
        }
    }
    Ok(p)
}

pub fn parse_ike(s: &str) -> anyhow::Result<IkeProposal> {
    let p = parse_tokens(s)?;
    let encr = p.encr.with_context(|| format!("IKE proposal '{s}' has no encryption algorithm"))?;
    let dh = p.dh.with_context(|| format!("IKE proposal '{s}' has no DH group"))?;
    let integ = if encr.is_aead() {
        ensure!(p.integ.is_none(), "AEAD proposal '{s}' must not list an integrity algorithm");
        None
    } else {
        Some(p.integ.with_context(|| format!("IKE proposal '{s}' needs an integrity algorithm"))?)
    };
    // Without an explicit PRF, the integrity hash doubles as PRF.
    let prf = p.prf.or(integ.map(IntegAlg::prf)).unwrap_or(PrfAlg::HmacSha256);
    Ok(IkeProposal { encr, integ, prf, dh })
}

/// IKEv1 phase 1 suite: AES-CBC, a hash (whose HMAC is the PRF) and a DH
/// group, e.g. `aes128-sha1-modp1536`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ike1Proposal {
    pub encr: EncrAlg,
    pub prf: PrfAlg,
    pub dh: DhGroup,
}

pub fn parse_ike1(s: &str) -> anyhow::Result<Ike1Proposal> {
    let p = parse_tokens(s)?;
    let encr = p.encr.with_context(|| format!("IKEv1 proposal '{s}' has no encryption algorithm"))?;
    ensure!(
        matches!(encr, EncrAlg::AesCbc { .. } | EncrAlg::TripleDesCbc),
        "IKEv1 proposal '{s}': only AES-CBC (or 3DES) is supported"
    );
    let integ = p.integ.with_context(|| format!("IKEv1 proposal '{s}' needs a hash (sha1, sha256)"))?;
    let dh = p.dh.with_context(|| format!("IKEv1 proposal '{s}' has no DH group"))?;
    Ok(Ike1Proposal { encr, prf: integ.prf(), dh })
}

/// IKEv1 phase 2 suite: AES-CBC (or 3DES) with an HMAC, or AES-GCM, and
/// an optional PFS group, e.g. `aes128-sha1-modp1536`, `aes256gcm16`.
pub fn parse_esp1(s: &str) -> anyhow::Result<EspProposal> {
    let p = parse_esp(s)?;
    ensure!(p.encr != EncrAlg::ChaCha20Poly1305, "IKEv1 proposal '{s}': ChaCha20-Poly1305 needs IKEv2");
    Ok(p)
}

pub fn parse_esp(s: &str) -> anyhow::Result<EspProposal> {
    let p = parse_tokens(s)?;
    ensure!(p.prf.is_none(), "ESP proposal '{s}' must not list a PRF");
    let encr = p.encr.with_context(|| format!("ESP proposal '{s}' has no encryption algorithm"))?;
    let integ = if encr.is_aead() {
        ensure!(p.integ.is_none(), "AEAD proposal '{s}' must not list an integrity algorithm");
        None
    } else {
        Some(p.integ.with_context(|| format!("ESP proposal '{s}' needs an integrity algorithm"))?)
    };
    Ok(EspProposal { encr, integ, pfs: p.dh })
}

fn encr_transform(encr: EncrAlg) -> Transform {
    Transform { kind: transform::ENCR, id: encr.id(), key_len: encr.key_bits() }
}

fn simple(kind: u8, id: u16) -> Transform {
    Transform { kind, id, key_len: None }
}

impl IkeProposal {
    pub fn sa_proposal(self, num: u8) -> Proposal {
        let mut transforms = vec![encr_transform(self.encr), simple(transform::PRF, self.prf.id())];
        if let Some(i) = self.integ {
            transforms.push(simple(transform::INTEG, i.id()));
        }
        transforms.push(simple(transform::DH, self.dh.id()));
        Proposal { num, protocol: protocol::IKE, spi: Vec::new(), transforms }
    }
}

impl EspProposal {
    /// `dh`: DH group to offer (CREATE_CHILD_SA with PFS); IKE_AUTH carries none.
    pub fn sa_proposal(self, num: u8, spi: u32, dh: Option<DhGroup>) -> Proposal {
        let mut transforms = vec![encr_transform(self.encr)];
        if let Some(i) = self.integ {
            transforms.push(simple(transform::INTEG, i.id()));
        }
        if let Some(g) = dh {
            transforms.push(simple(transform::DH, g.id()));
        }
        transforms.push(simple(transform::ESN, 0));
        Proposal { num, protocol: protocol::ESP, spi: spi.to_be_bytes().to_vec(), transforms }
    }
}

fn single(p: &Proposal, kind: u8) -> anyhow::Result<Option<&Transform>> {
    let mut it = p.transforms_of(kind);
    let first = it.next();
    ensure!(it.next().is_none(), "responder chose several transforms of type {kind}");
    Ok(first)
}

/// Validates the responder's chosen IKE proposal against what we offered.
pub fn accept_ike(chosen: &[Proposal], offered: &[IkeProposal]) -> anyhow::Result<IkeProposal> {
    ensure!(chosen.len() == 1, "responder must choose exactly one IKE proposal");
    let p = &chosen[0];
    ensure!(p.protocol == protocol::IKE, "responder chose a non-IKE proposal");
    let encr = single(p, transform::ENCR)?.context("no encryption transform chosen")?;
    let encr = EncrAlg::from_id(encr.id, encr.key_len).context("unsupported encryption transform chosen")?;
    let prf = PrfAlg::from_id(single(p, transform::PRF)?.context("no PRF chosen")?.id).context("unsupported PRF")?;
    let integ = single(p, transform::INTEG)?.map(|t| IntegAlg::from_id(t.id).context("unsupported integrity"));
    let integ = integ.transpose()?;
    let dh = DhGroup::from_id(single(p, transform::DH)?.context("no DH group chosen")?.id).context("unsupported DH")?;
    let accepted = IkeProposal { encr, integ, prf, dh };
    ensure!(offered.contains(&accepted), "responder chose a proposal we did not offer: {accepted:?}");
    Ok(accepted)
}

/// Validates the CHILD SA chosen in IKE_AUTH; returns it with the
/// responder's SPI (our outbound SPI). IKE_AUTH carries no KE, so any DH
/// transform is ignored (RFC 7296 §1.2) and `pfs` is `None`.
pub fn accept_esp(chosen: &[Proposal], offered: &[EspProposal]) -> anyhow::Result<(EspProposal, u32)> {
    let (mut algs, spi) = chosen_esp(chosen)?;
    algs.pfs = None;
    ensure!(
        offered.iter().any(|o| o.encr == algs.encr && o.integ == algs.integ),
        "responder chose an ESP proposal we did not offer"
    );
    Ok((algs, spi))
}

/// Validates the CHILD SA chosen in a CREATE_CHILD_SA we initiated with a
/// KE of `ke_group`. A profile proposal that names a DH group requires
/// exactly that group (no PFS downgrade); one without accepts either our
/// KE group or no DH.
pub fn accept_rekey_esp(
    chosen: &[Proposal],
    offered: &[EspProposal],
    ke_group: DhGroup,
) -> anyhow::Result<(EspProposal, u32)> {
    let (algs, spi) = chosen_esp(chosen)?;
    let acceptable = offered.iter().any(|o| {
        o.encr == algs.encr
            && o.integ == algs.integ
            && match o.pfs {
                Some(required) => algs.pfs == Some(required),
                None => algs.pfs.is_none_or(|g| g == ke_group),
            }
    });
    ensure!(acceptable, "responder chose an ESP proposal we did not offer (PFS downgrade?): {algs:?}");
    Ok((algs, spi))
}

fn chosen_esp(chosen: &[Proposal]) -> anyhow::Result<(EspProposal, u32)> {
    ensure!(chosen.len() == 1, "responder must choose exactly one ESP proposal");
    let p = &chosen[0];
    ensure!(p.protocol == protocol::ESP, "responder chose a non-ESP proposal");
    let spi = u32::from_be_bytes(p.spi.as_slice().try_into().context("ESP SPI must be 4 bytes")?);
    ensure!(spi > 255, "responder chose a reserved ESP SPI");
    let algs = esp_algs(p)?.context("unsupported ESP transforms chosen")?;
    Ok((algs, spi))
}

/// The algorithms of a single-choice ESP proposal, or `None` if unsupported.
fn esp_algs(p: &Proposal) -> anyhow::Result<Option<EspProposal>> {
    let Some(encr) = single(p, transform::ENCR)?.and_then(|t| EncrAlg::from_id(t.id, t.key_len)) else {
        return Ok(None);
    };
    let integ = match single(p, transform::INTEG)? {
        Some(t) if t.id != 0 => match IntegAlg::from_id(t.id) {
            Some(i) => Some(i),
            None => return Ok(None),
        },
        _ => None,
    };
    if encr.is_aead() == integ.is_some() {
        return Ok(None);
    }
    let dh = match single(p, transform::DH)? {
        Some(t) if t.id != 0 => match DhGroup::from_id(t.id) {
            Some(g) => Some(g),
            None => return Ok(None),
        },
        _ => None,
    };
    if single(p, transform::ESN)?.is_some_and(|t| t.id != 0) {
        return Ok(None);
    }
    Ok(Some(EspProposal { encr, integ, pfs: dh }))
}

/// Responder side of a CREATE_CHILD_SA: picks the first peer proposal we
/// support. `peer_ke_group` is the group of the peer's KE payload, if any.
/// A profile proposal that names a DH group only matches with that group.
/// Returns (peer proposal, its SPI, chosen algorithms).
pub fn choose_esp(
    peer: &[Proposal],
    ours: &[EspProposal],
    peer_ke_group: Option<u16>,
) -> Option<(Proposal, u32, EspProposal)> {
    for p in peer.iter().filter(|p| p.protocol == protocol::ESP) {
        let Ok(spi) = <[u8; 4]>::try_from(p.spi.as_slice()).map(u32::from_be_bytes) else {
            continue;
        };
        if spi <= 255 {
            continue;
        }
        for encr_t in p.transforms_of(transform::ENCR) {
            let Some(encr) = EncrAlg::from_id(encr_t.id, encr_t.key_len) else { continue };
            for o in ours.iter().filter(|o| o.encr == encr) {
                let mut integs = p.transforms_of(transform::INTEG).map(|t| t.id);
                let integ_ok = match o.integ {
                    Some(i) => integs.any(|id| id == i.id()),
                    // AEAD: no integrity transform, or "NONE".
                    None => integs.all(|id| id == 0),
                };
                let esn_ok = p.transforms_of(transform::ESN).next().is_none()
                    || p.transforms_of(transform::ESN).any(|t| t.id == 0);
                if !integ_ok || !esn_ok {
                    continue;
                }
                let offered_dh: Vec<u16> = p.transforms_of(transform::DH).map(|t| t.id).collect();
                if let Some(required) = o.pfs
                    && (peer_ke_group != Some(required.id()) || !offered_dh.contains(&required.id()))
                {
                    continue;
                }
                // Without a PFS group of ours, the peer's, unless weak and
                // never offered by us.
                let weak = |g: DhGroup| matches!(g, DhGroup::Modp1024 | DhGroup::Modp1536);
                let dh = match peer_ke_group {
                    Some(g) if offered_dh.contains(&g) => match DhGroup::from_id(g) {
                        Some(group) if weak(group) && !ours.iter().any(|o| o.pfs == Some(group)) => continue,
                        Some(group) => Some(group),
                        None => continue,
                    },
                    Some(_) => continue,
                    None if offered_dh.is_empty() || offered_dh.contains(&0) => None,
                    None => continue,
                };
                let mut transforms = vec![encr_t.clone()];
                if let Some(i) = o.integ {
                    transforms.push(simple(transform::INTEG, i.id()));
                }
                if let Some(g) = dh {
                    transforms.push(simple(transform::DH, g.id()));
                }
                transforms.push(simple(transform::ESN, 0));
                let chosen = Proposal { num: p.num, protocol: protocol::ESP, spi: Vec::new(), transforms };
                return Some((chosen, spi, EspProposal { encr, integ: o.integ, pfs: dh }));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profiles() {
        let p = parse_ike("aes256gcm16-prfsha256-ecp256").unwrap();
        assert_eq!(p.encr, EncrAlg::AesGcm16 { key_bits: 256 });
        assert_eq!(p.integ, None);
        assert_eq!(p.dh, DhGroup::Ecp256);
        let p = parse_ike("aes128-sha256-modp2048").unwrap();
        assert_eq!(p.integ, Some(IntegAlg::HmacSha256Trunc128));
        assert_eq!(p.prf, PrfAlg::HmacSha256);
        assert!(parse_ike("aes256-sha256").is_err());
        assert_eq!(parse_ike("3des-sha1-modp1024").unwrap().encr, EncrAlg::TripleDesCbc);
        assert!(parse_ike("des-sha1-modp1024").is_err());
        let c = parse_ike("chacha20poly1305-prfsha256-x25519").unwrap();
        assert_eq!((c.encr, c.integ), (EncrAlg::ChaCha20Poly1305, None));
        assert!(parse_ike("chacha20poly1305-sha256-x25519").is_err());
        assert_eq!(parse_esp("chacha20poly1305").unwrap().encr.key_bits(), None);
        assert!(parse_ike("aes256gcm16-sha256-ecp256").is_err());
        let e = parse_esp("aes256-sha256-x25519").unwrap();
        assert_eq!(e.pfs, Some(DhGroup::Curve25519));
        assert!(parse_esp("aes256").is_err());
    }

    #[test]
    fn parses_ikev1_profiles() {
        let p = parse_ike1("aes128-sha1-modp1536").unwrap();
        assert_eq!(
            p,
            Ike1Proposal { encr: EncrAlg::AesCbc { key_bits: 128 }, prf: PrfAlg::HmacSha1, dh: DhGroup::Modp1536 }
        );
        let p = parse_ike1("aes256-sha256-modp1024").unwrap();
        assert_eq!(p.prf, PrfAlg::HmacSha256);
        assert_eq!(p.dh, DhGroup::Modp1024);
        assert!(parse_ike1("aes256gcm16-modp2048").is_err());
        assert!(parse_ike1("aes256-modp2048").is_err());
        let e = parse_esp1("aes256-sha1-modp1536").unwrap();
        assert_eq!(e.integ, Some(IntegAlg::HmacSha1Trunc96));
        assert_eq!(e.pfs, Some(DhGroup::Modp1536));
        assert_eq!(parse_esp1("aes256gcm16-modp2048").unwrap().integ, None);
        assert!(parse_esp1("chacha20poly1305").is_err(), "no IKEv1 identifier");
        assert_eq!(parse_ike1("3des-sha1-modp1024").unwrap().encr, EncrAlg::TripleDesCbc);
        assert_eq!(parse_esp1("3des-sha1").unwrap().encr, EncrAlg::TripleDesCbc);
        // IKEv2 with SHA-1 uses PRF-HMAC-SHA1 by default.
        assert_eq!(parse_ike("aes128-sha1-modp2048").unwrap().prf, PrfAlg::HmacSha1);
    }

    #[test]
    fn accepts_offered_only() {
        let offered = vec![parse_ike("aes256gcm16-prfsha256-ecp256").unwrap()];
        assert_eq!(accept_ike(&[offered[0].sa_proposal(1)], &offered).unwrap(), offered[0]);
        let other = parse_ike("aes128gcm16-prfsha256-ecp256").unwrap();
        assert!(accept_ike(&[other.sa_proposal(1)], &offered).is_err());

        let esp = vec![parse_esp("aes256gcm16").unwrap()];
        let (accepted, spi) = accept_esp(&[esp[0].sa_proposal(1, 0xdead_beef, None)], &esp).unwrap();
        assert_eq!(spi, 0xdead_beef);
        assert_eq!(accepted.encr, esp[0].encr);
    }

    #[test]
    fn rejects_pfs_downgrade() {
        let strict = vec![parse_esp("aes256gcm16-ecp256").unwrap()];
        let lax = vec![parse_esp("aes256gcm16").unwrap()];
        let without = parse_esp("aes256gcm16").unwrap().sa_proposal(1, 0x1000, None);
        let other_group = parse_esp("aes256gcm16").unwrap().sa_proposal(1, 0x1000, Some(DhGroup::Modp2048));
        let right_group = parse_esp("aes256gcm16").unwrap().sa_proposal(1, 0x1000, Some(DhGroup::Ecp256));

        // We initiate the rekey.
        assert!(accept_rekey_esp(std::slice::from_ref(&without), &strict, DhGroup::Ecp256).is_err());
        assert!(accept_rekey_esp(std::slice::from_ref(&other_group), &strict, DhGroup::Ecp256).is_err());
        let (algs, _) = accept_rekey_esp(std::slice::from_ref(&right_group), &strict, DhGroup::Ecp256).unwrap();
        assert_eq!(algs.pfs, Some(DhGroup::Ecp256));
        assert!(accept_rekey_esp(std::slice::from_ref(&without), &lax, DhGroup::Ecp256).is_ok());
        assert!(accept_rekey_esp(std::slice::from_ref(&other_group), &lax, DhGroup::Ecp256).is_err());

        // The gateway initiates the rekey.
        assert!(choose_esp(std::slice::from_ref(&without), &strict, None).is_none());
        assert!(choose_esp(std::slice::from_ref(&other_group), &strict, Some(14)).is_none());
        let (_, _, algs) = choose_esp(std::slice::from_ref(&right_group), &strict, Some(19)).unwrap();
        assert_eq!(algs.pfs, Some(DhGroup::Ecp256));
        assert!(choose_esp(std::slice::from_ref(&without), &lax, None).is_some());

        // IKE_AUTH ignores DH transforms.
        assert_eq!(accept_esp(std::slice::from_ref(&right_group), &strict).unwrap().0.pfs, None);
    }

    #[test]
    fn chooses_peer_rekey_proposal() {
        let ours = vec![parse_esp("aes256gcm16").unwrap(), parse_esp("aes128-sha256").unwrap()];
        let peer = parse_esp("aes128-sha256-modp2048").unwrap().sa_proposal(1, 0x1007, Some(DhGroup::Modp2048));
        let (chosen, spi, algs) = choose_esp(std::slice::from_ref(&peer), &ours, Some(14)).unwrap();
        assert_eq!(spi, 0x1007);
        assert_eq!(algs.pfs, Some(DhGroup::Modp2048));
        assert!(chosen.transforms_of(transform::DH).any(|t| t.id == 14));
        // PFS offered but no KE sent: not acceptable.
        assert!(choose_esp(&[peer], &ours, None).is_none());
        let no_pfs = ours[0].sa_proposal(1, 0x1009, None);
        assert!(choose_esp(&[no_pfs], &ours, None).is_some());
        // A reserved SPI, a weak group we never offer.
        assert!(choose_esp(&[ours[0].sa_proposal(1, 9, None)], &ours, None).is_none());
        let weak = parse_esp("aes128-sha256-modp1024").unwrap().sa_proposal(1, 0x1007, Some(DhGroup::Modp1024));
        assert!(choose_esp(&[weak], &ours, Some(2)).is_none());
    }
}
