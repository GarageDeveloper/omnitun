//! Connects to a real gateway with one profile of a profiles file, pings an
//! address through the tunnel, then disconnects: the interoperability check
//! run by `interop/strongswan/run.sh`.
//!
//! `cargo run -p vpn-ipsec --example interop -- <profiles.toml> <name> <ip>`
//!
//! Answers come from the environment: `INTEROP_PSK`, `INTEROP_PASSWORD`;
//! profiles named `*wrong-psk` get a wrong PSK.
//! `@pki:<file>@` in the profiles is replaced by that file of the
//! `INTEROP_PKI` directory (test certificates). A certificate the profile
//! does not trust is refused, as a user would. Signatures with a client
//! certificate use its PKCS#8 key from that directory, where the app would
//! use the Keychain, after the same checks.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpn_core::{Engine, PacketIo, ProfileFile, Prompt, Prompter, ProtocolConfig, SessionContext};
use vpn_ipsec::IpsecEngine;

struct EnvPrompter {
    wrong_psk: bool,
}

#[async_trait]
impl Prompter for EnvPrompter {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<zeroize::Zeroizing<String>> {
        // The test answers, erased like real ones.
        let answer: anyhow::Result<String> = async {
            if let Some(request) = &prompt.sign {
                return sign(request);
            }
            if prompt.key == "psk" && self.wrong_psk {
                return Ok("not-the-interop-psk".into());
            }
            let var = match prompt.key.as_str() {
                "psk" => "INTEROP_PSK",
                "password" => "INTEROP_PASSWORD",
                other => bail!("unexpected question {other:?}: {}", prompt.message),
            };
            std::env::var(var).with_context(|| format!("{var} is not set"))
        }
        .await;
        answer.map(zeroize::Zeroizing::new)
    }

    async fn open_url(&self, _: &str) -> anyhow::Result<()> {
        bail!("no browser")
    }
}

/// Signs with the key of the `client-*.pem` certificate the request names.
fn sign(request: &vpn_core::SignRequest) -> anyhow::Result<String> {
    use ring::signature::{self, EcdsaKeyPair, RsaKeyPair};
    use vpn_core::SignAlgorithm;
    let data = hex::decode(&request.data)?;
    anyhow::ensure!(vpn_core::prompt::is_ike_auth_octets(&data), "asked to sign something else than IKE");
    let dir = std::env::var("INTEROP_PKI").context("INTEROP_PKI is not set")?;
    let mut key = None;
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "sha256")
            && std::fs::read_to_string(&path)?.trim().eq_ignore_ascii_case(&request.certificate)
        {
            key = Some(std::fs::read(path.with_extension("p8")).context("no PKCS#8 key for the certificate")?);
        }
    }
    let key = key.context("unknown client certificate")?;
    let rng = ring::rand::SystemRandom::new();
    let rsa = |padding: &'static dyn signature::RsaEncoding| -> anyhow::Result<Vec<u8>> {
        let pair = RsaKeyPair::from_pkcs8(&key).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut out = vec![0; pair.public().modulus_len()];
        pair.sign(padding, &rng, &data, &mut out).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(out)
    };
    let ecdsa = |alg: &'static signature::EcdsaSigningAlgorithm| -> anyhow::Result<Vec<u8>> {
        let pair = EcdsaKeyPair::from_pkcs8(alg, &key, &rng).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(pair.sign(&rng, &data).map_err(|e| anyhow::anyhow!("{e}"))?.as_ref().to_vec())
    };
    let signature = match request.algorithm {
        SignAlgorithm::RsaPkcs1Sha1 => {
            use rsa::pkcs8::DecodePrivateKey;
            use sha1::Digest;
            let key = rsa::RsaPrivateKey::from_pkcs8_der(&key)?;
            key.sign(rsa::Pkcs1v15Sign::new::<sha1::Sha1>(), &sha1::Sha1::digest(&data))?
        }
        SignAlgorithm::RsaPkcs1Sha256 => rsa(&signature::RSA_PKCS1_SHA256)?,
        SignAlgorithm::RsaPkcs1Sha384 => rsa(&signature::RSA_PKCS1_SHA384)?,
        SignAlgorithm::RsaPkcs1Sha512 => rsa(&signature::RSA_PKCS1_SHA512)?,
        SignAlgorithm::RsaPssSha256 => rsa(&signature::RSA_PSS_SHA256)?,
        SignAlgorithm::RsaPssSha384 => rsa(&signature::RSA_PSS_SHA384)?,
        SignAlgorithm::RsaPssSha512 => rsa(&signature::RSA_PSS_SHA512)?,
        SignAlgorithm::EcdsaSha256 => ecdsa(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)?,
        SignAlgorithm::EcdsaSha384 => ecdsa(&signature::ECDSA_P384_SHA384_ASN1_SIGNING)?,
    };
    Ok(hex::encode(signature))
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x4f, 0x54];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"omnitun interop");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
    ip[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

fn is_echo_reply(packet: &[u8], from: Ipv4Addr) -> bool {
    packet.len() >= 28 && packet[9] == 1 && packet[12..16] == from.octets() && packet[20] == 0
}

fn with_pki(text: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("@pki:") {
        let end = rest[start + 5..].find('@').context("unterminated @pki: placeholder")? + start + 5;
        let dir = std::env::var("INTEROP_PKI").context("INTEROP_PKI is not set")?;
        let path = std::path::Path::new(&dir).join(&rest[start + 5..end]);
        out.push_str(&rest[..start]);
        out.push_str(std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?.trim());
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    let [_, file, name, target] = args.as_slice() else {
        bail!("usage: interop <profiles.toml> <name> <ip to ping>");
    };
    let target: Ipv4Addr = target.parse()?;
    let file: ProfileFile = toml::from_str(&with_pki(&std::fs::read_to_string(file)?)?)?;
    let profile = file.profiles.into_iter().find(|p| &p.name == name).with_context(|| format!("no profile {name}"))?;
    profile.validate()?;
    let ProtocolConfig::Ipsec(ipsec) = profile.protocol else { bail!("{name} is not an IPsec profile") };

    let ctx = SessionContext {
        name: name.clone(),
        prompter: Arc::new(EnvPrompter { wrong_psk: name.ends_with("wrong-psk") }),
        cancel: CancellationToken::new(),
        stats: Arc::default(),
    };
    let mut engine = IpsecEngine::new(ipsec);
    let settings = tokio::time::timeout(Duration::from_secs(30), engine.connect(&ctx)).await.context("timeout")??;
    println!("connected: address {}, routes {:?}", settings.address, settings.routes);

    let (to_tun, mut tun_rx) = mpsc::channel(16);
    let (tun_tx, from_tun) = mpsc::channel(16);
    let run_ctx = ctx.clone();
    let runner = tokio::spawn(async move {
        let result = engine.run(&run_ctx, PacketIo { to_tun, from_tun }).await;
        engine.disconnect().await.ok();
        result
    });
    let mut answered = false;
    for seq in 1..=5u16 {
        tun_tx.send(Bytes::from(echo_request(settings.address, target, seq))).await?;
        if let Ok(Some(packet)) = tokio::time::timeout(Duration::from_secs(1), tun_rx.recv()).await
            && is_echo_reply(&packet, target)
        {
            answered = true;
            break;
        }
    }
    let stats = &ctx.stats;
    let count = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    println!("packets sent {}, received {}", count(&stats.tx_packets), count(&stats.rx_packets));
    ctx.cancel.cancel();
    runner.await??;
    if !answered {
        bail!("no answer from {target} through the tunnel");
    }
    println!("ping {target} through the tunnel: ok");
    Ok(())
}
