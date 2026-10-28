//! `sudo utun-probe`: creates a utun as root, hands it over a Unix socket to
//! an "engine" process running as `nobody` (unsandboxed, then sandboxed),
//! and checks that the engine can read a ping from it and write the reply,
//! while it cannot create an interface or read protected files itself.

use std::io::{BufRead, BufReader, IoSlice, IoSliceMut, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg, sendmsg, socketpair,
};

const LOCAL: &str = "10.255.77.1";
const PEER: &str = "10.255.77.2";
const PINGS: usize = 3;

/// Strict: only what the binary needs to start. The engine must still use
/// the descriptor it was given.
const STRICT: &str = r#"(version 1)
(deny default)
(allow process-exec (literal "@EXE@"))
(allow file-read-metadata)
(allow file-read-data (literal "/"))
(allow file-read* (subpath "/usr/lib") (subpath "/System") (subpath "/private/var/db/dyld")
                  (literal "@EXE@") (literal "/dev/urandom") (literal "/dev/null"))
(allow sysctl-read)
"#;

/// What an engine will need on top: talking to its gateway.
const NETWORK: &str = "(allow network-outbound)\n(allow network-inbound)\n(allow system-socket)\n";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("engine") => engine(args.get(2).context("socket fd")?.parse()?),
        _ => probe(),
    }
}

// ---- root side --------------------------------------------------------------

fn probe() -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("run as root: sudo {}", std::env::args().next().unwrap_or_default());
    }
    let nobody = nix::unistd::User::from_name("nobody")?.context("no user nobody")?;
    // nobody cannot enter the user's home: run the engine from a copy, in
    // a directory of our own (/var/tmp is writable by everyone, who could
    // have left a link or a binary of theirs there).
    let dir = nix::unistd::mkdtemp("/private/var/tmp/utun-probe.XXXXXX").context("cannot create a directory")?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o711))?;
    let path = dir.join("utun-probe");
    if let Err(e) = copy_new(&std::env::current_exe()?, &path) {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e.context("cannot copy the probe to /var/tmp"));
    }
    let exe = path.to_str().context("non-UTF-8 directory")?;
    println!("utun-probe: engine runs as nobody (uid {}), interface {LOCAL} -> {PEER}\n", nobody.uid);

    let mut results = Vec::new();
    for (label, profile) in [
        ("no sandbox", None),
        ("strict sandbox", Some(STRICT.replace("@EXE@", exe))),
        ("strict sandbox + network", Some(STRICT.replace("@EXE@", exe) + NETWORK)),
    ] {
        println!("== {label}");
        let outcome = run_case(exe, &nobody, profile.as_deref());
        match &outcome {
            Ok(report) => {
                for line in report {
                    println!("   {line}");
                }
            }
            Err(e) => println!("   FAILED: {e:#}"),
        }
        results.push((label, outcome));
        println!();
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!("== summary");
    for (label, outcome) in results {
        let ok = outcome.as_ref().is_ok_and(|r| r.iter().any(|l| l.starts_with("ping replies") && !l.contains(" 0/")));
        println!("   {label:<26} {}", if ok { "engine can use the utun" } else { "engine CANNOT use the utun" });
    }
    Ok(())
}

/// Copies `from` to a new file `to`, mode 0755, never through a link.
fn copy_new(from: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(to)?;
    std::io::copy(&mut std::fs::File::open(from)?, &mut out)?;
    Ok(())
}

fn run_case(exe: &str, nobody: &nix::unistd::User, profile: Option<&str>) -> anyhow::Result<Vec<String>> {
    let device = tun_rs::DeviceBuilder::new()
        .ipv4(LOCAL.parse::<std::net::Ipv4Addr>()?, 32, Some(PEER.parse::<std::net::Ipv4Addr>()?))
        .build_sync()
        .context("cannot create a utun as root")?;
    let name = device.name()?;

    let (ours, theirs) = socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty())?;
    nix::fcntl::fcntl(&ours, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
    let their_fd = theirs.as_raw_fd();

    let mut command = match profile {
        None => Command::new(exe),
        Some(profile) => {
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-p").arg(profile).arg(exe);
            c
        }
    };
    command.arg("engine").arg(their_fd.to_string());
    command.uid(nobody.uid.as_raw()).gid(nobody.gid.as_raw()).stdin(Stdio::null()).stderr(Stdio::piped());
    let mut child = command.spawn().context("cannot start the engine")?;
    drop(theirs);

    // Hand over the interface, as omnitund would.
    sendmsg::<()>(
        ours.as_raw_fd(),
        &[IoSlice::new(name.as_bytes())],
        &[ControlMessage::ScmRights(&[device.as_raw_fd()])],
        MsgFlags::empty(),
        None,
    )
    .context("cannot pass the utun")?;

    let stream = UnixStream::from(ours);
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut lines = BufReader::new(stream.try_clone()?).lines();
    let mut report = vec![format!("interface {name}, passed to engine pid {}", child.id())];
    // The engine says when it reads; then the pings go out through the utun.
    match lines.next() {
        Some(Ok(line)) if line == "ready" => {}
        other => {
            let _ = child.kill();
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut stderr);
            }
            bail!("engine did not start ({other:?}) {}", stderr.trim());
        }
    }
    let ping = Command::new("/sbin/ping").args(["-c", &PINGS.to_string(), "-i", "0.2", "-W", "1000", PEER]).output()?;
    let received = String::from_utf8_lossy(&ping.stdout)
        .lines()
        .find(|l| l.contains("packets received"))
        .and_then(|l| l.split(',').nth(1).map(|s| s.trim().split(' ').next().unwrap_or("0").to_owned()))
        .unwrap_or_else(|| "0".into());
    report.push(format!("ping replies {received}/{PINGS} (root pinged {PEER} through {name})"));
    let _ = (&stream).write_all(b"done\n");
    for line in lines.map_while(Result::ok) {
        report.push(line);
    }
    let _ = child.wait();
    Ok(report)
}

// ---- engine side ------------------------------------------------------------

fn engine(socket: RawFd) -> anyhow::Result<()> {
    // SAFETY: the descriptor was inherited from the probe for this purpose.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut name = [0u8; 64];
    let mut space = nix::cmsg_space!([RawFd; 1]);
    let (tun, name) = {
        let mut iov = [IoSliceMut::new(&mut name)];
        let msg = recvmsg::<()>(socket.as_raw_fd(), &mut iov, Some(&mut space), MsgFlags::empty())?;
        let fd = msg
            .cmsgs()?
            .find_map(|c| match c {
                ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
                _ => None,
            })
            .context("no descriptor received")?;
        let len = msg.bytes;
        // SAFETY: received through SCM_RIGHTS, owned by this process now.
        (unsafe { OwnedFd::from_raw_fd(fd) }, String::from_utf8_lossy(&iov_bytes(&name, len)).into_owned())
    };
    let mut out = UnixStream::from(socket);
    out.write_all(b"ready\n")?;

    let mut lines = vec![format!("engine uid {} received {name}", nix::unistd::getuid())];
    let (mut read, mut written) = (0, 0);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut buf = [0u8; 2048];
    while written < PINGS && Instant::now() < deadline {
        let mut fds = [nix::poll::PollFd::new(tun.as_fd(), nix::poll::PollFlags::POLLIN)];
        if nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(200u16))? == 0 {
            continue;
        }
        let n = match nix::unistd::read(&tun, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                lines.push(format!("read on utun: FAILED {e}"));
                break;
            }
        };
        read += 1;
        if let Some(reply) = echo_reply(&buf[..n]) {
            match nix::unistd::write(&tun, &reply) {
                Ok(_) => written += 1,
                Err(e) => {
                    lines.push(format!("write on utun: FAILED {e}"));
                    break;
                }
            }
        }
    }
    lines.push(format!("packets read {read}, replies written {written}"));

    // What the engine must not be able to do on its own.
    let own = tun_rs::DeviceBuilder::new().ipv4("10.255.78.1".parse::<std::net::Ipv4Addr>()?, 32, None).build_sync();
    lines.push(format!("create its own utun: {}", if own.is_ok() { "ALLOWED (bad)" } else { "refused (good)" }));
    let secret = std::fs::read("/etc/master.passwd");
    lines.push(format!("read /etc/master.passwd: {}", if secret.is_ok() { "ALLOWED (bad)" } else { "refused (good)" }));
    let home = std::fs::read_dir("/Users");
    lines.push(format!("list /Users: {}", if home.is_ok() { "allowed" } else { "refused" }));
    let udp = std::net::UdpSocket::bind("0.0.0.0:0").and_then(|s| s.send_to(b"x", "127.0.0.1:9"));
    lines.push(format!("send UDP (needed to reach a gateway): {}", if udp.is_ok() { "allowed" } else { "refused" }));

    // Wait for the probe to finish pinging, then report.
    let mut done = String::new();
    let _ = BufReader::new(out.try_clone()?).read_line(&mut done);
    for line in lines {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

fn iov_bytes(buf: &[u8], len: usize) -> Vec<u8> {
    buf[..len.min(buf.len())].to_vec()
}

/// An ICMP echo reply to an echo request, keeping the utun's 4-byte
/// address family header when there is one.
fn echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
    let (head, ip) = if packet.first().is_some_and(|b| b >> 4 == 4) { (&[][..], packet) } else { packet.split_at(4) };
    if ip.len() < 28 || ip[0] >> 4 != 4 || ip[9] != 1 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ip.len() < ihl + 8 || ip[ihl] != 8 {
        return None;
    }
    let mut reply = ip.to_vec();
    reply[12..16].copy_from_slice(&ip[16..20]);
    reply[16..20].copy_from_slice(&ip[12..16]);
    reply[ihl] = 0;
    reply[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let sum = checksum(&reply[ihl..]);
    reply[ihl + 2..ihl + 4].copy_from_slice(&sum.to_be_bytes());
    reply[10..12].copy_from_slice(&[0, 0]);
    let sum = checksum(&reply[..ihl]);
    reply[10..12].copy_from_slice(&sum.to_be_bytes());
    Some([head, &reply].concat())
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_to_an_echo_request() {
        // 10.255.77.1 -> 10.255.77.2, ICMP echo request, utun header AF_INET.
        let mut ip =
            vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 255, 77, 1, 10, 255, 77, 2, 8, 0, 0, 0, 0, 1, 0, 1];
        let sum = checksum(&ip[20..]);
        ip[22..24].copy_from_slice(&sum.to_be_bytes());
        let sum = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        let packet = [&[0, 0, 0, 2][..], &ip].concat();
        let reply = echo_reply(&packet).unwrap();
        assert_eq!(&reply[..4], &[0, 0, 0, 2]);
        let r = &reply[4..];
        assert_eq!((&r[12..16], &r[16..20], r[20]), (&[10, 255, 77, 2][..], &[10, 255, 77, 1][..], 0));
        assert_eq!(checksum(&r[..20]), 0);
        assert_eq!(checksum(&r[20..]), 0);
    }
}
