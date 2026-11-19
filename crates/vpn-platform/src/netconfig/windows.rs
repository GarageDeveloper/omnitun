//! Windows: routes through the IP Helper API; the tunnel's DNS servers on
//! its interface (full tunnel) and, for the names they answer, a rule of
//! the Name Resolution Policy Table (NRPT). The rules live in volatile
//! registry keys, which a reboot clears like the routes.
//!
//! Interfaces: a tunnel is named by its alias (what `tun-rs` reports), the
//! uplink by its index, which fits the route journal.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr::{null, null_mut};

use anyhow::{Context, bail};
use ipnet::{Ipv4Net, Ipv6Net};
use vpn_core::TunnelSettings;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST,
    DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2, GetIpInterfaceEntry, IP_ADDRESS_PREFIX,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW, SetInterfaceDnsSettings,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_OPTION_VOLATILE,
    REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegEnumKeyExW, RegSetValueExW,
};

use super::{Uplink, Via, check_domains};

pub(super) fn unsupported<T>() -> anyhow::Result<T> {
    bail!("routes by domain are not supported on Windows yet")
}

/// The default route with the lowest metric, route and interface added
/// as Windows ranks them.
pub(super) async fn uplink() -> anyhow::Result<Uplink> {
    let table = ForwardTable::new(AF_INET)?;
    let mut best: Option<(u32, Uplink)> = None;
    for row in table.rows() {
        if row.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let Some(metric) = interface_metric(row.InterfaceLuid).map(|m| m.saturating_add(row.Metric)) else {
            continue;
        };
        if best.as_ref().is_some_and(|(m, _)| *m <= metric) {
            continue;
        }
        let gateway = match ip_of(&row.NextHop) {
            Some(IpAddr::V4(g)) if !g.is_unspecified() => Some(g),
            _ => None,
        };
        best = Some((metric, Uplink { gateway, interface: row.InterfaceIndex.to_string() }));
    }
    best.map(|(_, uplink)| uplink).context("no default route")
}

pub(super) async fn os_add_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let row = route_row(net, via)?;
    // SAFETY: a complete row, read by the call.
    check(unsafe { CreateIpForwardEntry2(&row) }).with_context(|| format!("cannot add the route to {net}"))
}

pub(super) async fn os_delete_route(net: Ipv4Net, via: &Via) -> anyhow::Result<()> {
    let row = route_row(net, via)?;
    // SAFETY: as above.
    check(unsafe { DeleteIpForwardEntry2(&row) }).with_context(|| format!("cannot delete the route to {net}"))
}

/// IPv6 is on for every interface: nothing to prepare.
pub(super) async fn ipv6_capable(_interface: &str) -> anyhow::Result<()> {
    Ok(())
}

/// Through the tunnel, which carries no IPv6: the packets go nowhere.
pub(super) async fn block_ipv6(net: Ipv6Net, interface: &str) -> anyhow::Result<()> {
    let row = row(IpAddr::V6(net.addr()), net.prefix_len(), index_of(interface)?, Ipv6Addr::UNSPECIFIED.into());
    // SAFETY: a complete row.
    check(unsafe { CreateIpForwardEntry2(&row) }).with_context(|| format!("cannot block {net}"))
}

pub(super) async fn unblock_ipv6(net: Ipv6Net, interface: &str) -> anyhow::Result<()> {
    let row = row(IpAddr::V6(net.addr()), net.prefix_len(), index_of(interface)?, Ipv6Addr::UNSPECIFIED.into());
    // SAFETY: a complete row.
    check(unsafe { DeleteIpForwardEntry2(&row) }).with_context(|| format!("cannot unblock {net}"))
}

/// A split tunnel's servers answer only its domains, through an NRPT rule:
/// on the interface, Windows would ask them any name. A full tunnel's take
/// every name, with a rule for all of them.
pub(super) async fn set_dns(session: &str, interface: &str, settings: &TunnelSettings) -> anyhow::Result<()> {
    check_domains(settings)?;
    let dns = &settings.dns;
    let servers: Vec<String> = dns.servers.iter().map(|s| s.to_string()).collect();
    let on_interface = if settings.full_tunnel { servers.join(",") } else { String::new() };
    set_interface_dns(interface, &on_interface, &dns.search_domains.join(","))?;
    let names: Vec<String> = if settings.full_tunnel {
        vec![".".into()]
    } else {
        let domains = if dns.match_domains.is_empty() { &dns.search_domains } else { &dns.match_domains };
        if domains.is_empty() {
            tracing::warn!(session, "split tunnel without DNS domains: tunnel DNS servers left unused");
            return Ok(());
        }
        // The domain itself and the names under it.
        domains.iter().flat_map(|d| [d.clone(), format!(".{d}")]).collect()
    };
    nrpt::set(&nrpt::rule(session), &names, &servers)?;
    flush_dns_cache().await;
    Ok(())
}

pub(super) async fn clear_dns(session: &str, interface: &str) -> anyhow::Result<()> {
    let removed = nrpt::remove(&nrpt::rule(session));
    // Gone with the interface, often.
    let _ = set_interface_dns(interface, "", "");
    flush_dns_cache().await;
    removed
}

pub(super) async fn set_proxy_dns(
    _session: &str,
    _interface: &str,
    _settings: &TunnelSettings,
    _port: u16,
    _domains: &[String],
) -> anyhow::Result<()> {
    unsupported()
}

pub(super) async fn clear_proxy_dns(
    _session: &str,
    _interface: &str,
    _settings: &TunnelSettings,
    _restore: bool,
) -> anyhow::Result<()> {
    unsupported()
}

pub(super) async fn current_resolvers(_ignore: &[String]) -> anyhow::Result<Vec<SocketAddr>> {
    unsupported()
}

pub(super) async fn flush_dns_cache() {
    #[link(name = "dnsapi", kind = "raw-dylib")]
    unsafe extern "system" {
        /// Exported by dnsapi.dll, as `ipconfig /flushdns` uses it.
        fn DnsFlushResolverCache() -> i32;
    }
    // SAFETY: no argument.
    unsafe { DnsFlushResolverCache() };
}

/// The NRPT rules of a daemon that did not shut down cleanly.
pub(super) async fn cleanup_stale_dns() {
    match nrpt::ours() {
        Ok(rules) if !rules.is_empty() => {
            tracing::info!("removing {} stale resolver rules", rules.len());
            for rule in rules {
                if let Err(e) = nrpt::remove(&rule) {
                    tracing::warn!("stale resolver rule {rule}: {e:#}");
                }
            }
            flush_dns_cache().await;
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("cannot list the resolver rules: {e:#}"),
    }
}

fn check(status: WIN32_ERROR) -> std::io::Result<()> {
    if status == 0 { Ok(()) } else { Err(std::io::Error::from_raw_os_error(status as i32)) }
}

fn route_row(net: Ipv4Net, via: &Via) -> anyhow::Result<MIB_IPFORWARD_ROW2> {
    let (index, next_hop) = match via {
        Via::Interface(alias) => (index_of(alias)?, Ipv4Addr::UNSPECIFIED),
        Via::Physical(Uplink { gateway, interface }) => {
            let index = interface.parse().with_context(|| format!("bad interface index {interface}"))?;
            // A destination on the uplink's own network (a gateway on the
            // LAN) is reached directly, not through the router.
            let next_hop = if on_link(index, net.addr()) { None } else { *gateway };
            (index, next_hop.unwrap_or(Ipv4Addr::UNSPECIFIED))
        }
    };
    Ok(row(IpAddr::V4(net.addr()), net.prefix_len(), index, next_hop.into()))
}

/// Whether `address` is on the network of interface `index`: its best
/// route there has no next hop. A host route this module added on the link
/// says the same, so a route is deleted as it was added.
fn on_link(index: u32, address: Ipv4Addr) -> bool {
    let destination = sockaddr(IpAddr::V4(address));
    let (mut best, mut source) = (MIB_IPFORWARD_ROW2::default(), SOCKADDR_INET::default());
    // SAFETY: valid pointers for the call's duration.
    let found = unsafe { GetBestRoute2(null(), index, null(), &destination, 0, &mut best, &mut source) } == 0;
    found && ip_of(&best.NextHop).is_some_and(|hop| hop.is_unspecified())
}

/// A route to `prefix/len` through interface `index`; an unspecified next
/// hop means on the link.
fn row(prefix: IpAddr, len: u8, index: u32, next_hop: IpAddr) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: fills in the defaults (lifetimes, origin) of a row.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX { Prefix: sockaddr(prefix), PrefixLength: len };
    row.NextHop = sockaddr(next_hop);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            address.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(v4.octets()) } },
                sin_zero: [0; 8],
            }
        }
        IpAddr::V6(v6) => {
            address.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: v6.octets() } },
                ..Default::default()
            }
        }
    }
    address
}

fn ip_of(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family says which member is set.
    unsafe {
        match address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// The IPv4 metric of an interface; `None` if it has no IPv4.
fn interface_metric(luid: NET_LUID_LH) -> Option<u32> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: an initialized row naming the interface.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    // SAFETY: as above.
    (unsafe { GetIpInterfaceEntry(&mut row) } == 0).then_some(row.Metric)
}

fn luid_of(alias: &str) -> anyhow::Result<NET_LUID_LH> {
    let wide = wide(alias);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: a NUL-terminated alias.
    check(unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) })
        .with_context(|| format!("no interface {alias}"))?;
    Ok(luid)
}

fn index_of(alias: &str) -> anyhow::Result<u32> {
    let luid = luid_of(alias)?;
    let mut index = 0;
    // SAFETY: a valid LUID.
    check(unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) })?;
    Ok(index)
}

/// `servers` and `search`: comma-separated, empty to clear.
fn set_interface_dns(alias: &str, servers: &str, search: &str) -> anyhow::Result<()> {
    let luid = luid_of(alias)?;
    let mut guid = Default::default();
    // SAFETY: a valid LUID.
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    let (mut servers, mut search) = (wide(servers), wide(search));
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST) as u64,
        NameServer: servers.as_mut_ptr(),
        SearchList: search.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: the strings outlive the call.
    check(unsafe { SetInterfaceDnsSettings(guid, &settings) })
        .with_context(|| format!("cannot set the DNS servers of {alias}"))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The routing table of one address family.
struct ForwardTable(*mut MIB_IPFORWARD_TABLE2);

impl ForwardTable {
    fn new(family: u16) -> anyhow::Result<Self> {
        let mut table = null_mut();
        // SAFETY: the table is freed on drop.
        check(unsafe { GetIpForwardTable2(family, &mut table) }).context("cannot read the routing table")?;
        Ok(Self(table))
    }

    fn rows(&self) -> &[MIB_IPFORWARD_ROW2] {
        // SAFETY: `NumEntries` rows follow the header.
        unsafe { std::slice::from_raw_parts((*self.0).Table.as_ptr(), (*self.0).NumEntries as usize) }
    }
}

impl Drop for ForwardTable {
    fn drop(&mut self) {
        // SAFETY: allocated by GetIpForwardTable2.
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

/// Rules of the local NRPT (`DnsPolicyConfig`), which the DNS client reads
/// from the registry. A Group Policy NRPT, where there is one, takes
/// precedence over it.
mod nrpt {
    use super::*;

    const TABLE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    /// `ConfigOptions`: the rule names its own DNS servers.
    const GENERIC_DNS_SERVERS: u32 = 0x8;

    /// The rule of a session.
    pub(super) fn rule(session: &str) -> String {
        format!("{}-{session}", vpn_core::brand::ID)
    }

    /// Sends `names` (`corp.example`, `.corp.example` for the names under
    /// it, `.` for all) to `servers`.
    pub(super) fn set(rule: &str, names: &[String], servers: &[String]) -> anyhow::Result<()> {
        let table = Key::create(HKEY_LOCAL_MACHINE, TABLE, false)?;
        let key = Key::create(table.0, rule, true)?;
        key.set_dword("Version", 2)?;
        key.set_multi_sz("Name", names)?;
        key.set_sz("GenericDNSServers", &servers.join(";"))?;
        key.set_dword("ConfigOptions", GENERIC_DNS_SERVERS)?;
        key.set_sz("IPSECCARestriction", "")?;
        key.set_sz("Comment", vpn_core::brand::PRODUCT)
            .with_context(|| format!("cannot write the resolver rule {rule}"))
    }

    pub(super) fn remove(rule: &str) -> anyhow::Result<()> {
        let path = wide(&format!(r"{TABLE}\{rule}"));
        // SAFETY: a NUL-terminated path.
        match unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr()) } {
            0 | ERROR_FILE_NOT_FOUND => Ok(()),
            e => Err(std::io::Error::from_raw_os_error(e as i32)).with_context(|| format!("cannot remove {rule}")),
        }
    }

    /// The rules of this program, whichever session they were for.
    pub(super) fn ours() -> anyhow::Result<Vec<String>> {
        let table = Key::create(HKEY_LOCAL_MACHINE, TABLE, false)?;
        let prefix = format!("{}-", vpn_core::brand::ID);
        let mut rules = Vec::new();
        for i in 0.. {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            // SAFETY: the buffer holds `len` characters.
            let status = unsafe {
                RegEnumKeyExW(table.0, i, name.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut())
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            check(status).context("cannot list the resolver rules")?;
            let name = String::from_utf16_lossy(&name[..len as usize]);
            if name.starts_with(&prefix) {
                rules.push(name);
            }
        }
        Ok(rules)
    }

    struct Key(HKEY);

    impl Key {
        /// Opens `path` under `parent`, creating it if needed; a volatile
        /// key is gone after a reboot.
        fn create(parent: HKEY, path: &str, volatile: bool) -> anyhow::Result<Self> {
            let path16 = wide(path);
            let options = if volatile { REG_OPTION_VOLATILE } else { REG_OPTION_NON_VOLATILE };
            let mut key = null_mut();
            // SAFETY: a NUL-terminated path; the key is closed on drop.
            let status = unsafe {
                RegCreateKeyExW(
                    parent,
                    path16.as_ptr(),
                    0,
                    null(),
                    options,
                    KEY_ALL_ACCESS,
                    null(),
                    &mut key,
                    null_mut(),
                )
            };
            check(status).with_context(|| format!("cannot open {path}"))?;
            Ok(Self(key))
        }

        fn set(&self, name: &str, kind: u32, data: &[u8]) -> anyhow::Result<()> {
            let name16 = wide(name);
            // SAFETY: `data` holds `len` bytes.
            check(unsafe { RegSetValueExW(self.0, name16.as_ptr(), 0, kind, data.as_ptr(), data.len() as u32) })
                .with_context(|| format!("cannot write {name}"))
        }

        fn set_dword(&self, name: &str, value: u32) -> anyhow::Result<()> {
            self.set(name, REG_DWORD, &value.to_le_bytes())
        }

        fn set_sz(&self, name: &str, value: &str) -> anyhow::Result<()> {
            self.set(name, REG_SZ, &bytes(&wide(value)))
        }

        /// Strings each ended by a NUL, then one more.
        fn set_multi_sz(&self, name: &str, values: &[String]) -> anyhow::Result<()> {
            let mut data: Vec<u16> = values.iter().flat_map(|v| wide(v)).collect();
            data.push(0);
            self.set(name, REG_MULTI_SZ, &bytes(&data))
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: a key this value opened.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn bytes(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|u| u.to_le_bytes()).collect()
    }
}
