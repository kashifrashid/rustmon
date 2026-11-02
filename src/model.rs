//! Plain data types shared by the collector, detection engine and UI.

use chrono::{DateTime, Local};
use serde::Serialize;
use std::net::IpAddr;

/// Alert severity. Ordering is meaningful: `Critical > High > Medium > Low > Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MED",
            Severity::High => "HIGH",
            Severity::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiskStat {
    pub name: String,
    pub mount: String,
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub hostname: String,
    pub os: String,
    pub uptime_secs: u64,
    pub cpu_total: f32,
    pub cpu_per_core: Vec<f32>,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disks: Vec<DiskStat>,
    pub process_count: usize,
}

/// Per-interface throughput. Rates are bytes per second over the last sample.
#[derive(Debug, Clone, Default)]
pub struct IfaceStat {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_total: u64,
    pub tx_total: u64,
}

#[derive(Debug, Clone)]
pub struct ProcRow {
    pub pid: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cpu: f32,
    pub mem: u64,
    /// Number of sockets owned by this process in the current sample.
    pub conns: usize,
}

/// One TCP or UDP socket with its owning process resolved.
#[derive(Debug, Clone)]
pub struct ConnRow {
    pub proto: &'static str,
    pub local_ip: Option<IpAddr>,
    pub local_port: u16,
    /// `None` for listeners and unconnected UDP sockets.
    pub remote_ip: Option<IpAddr>,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process: String,
    pub exe: Option<String>,
}

impl ConnRow {
    pub fn local_str(&self) -> String {
        addr_str(self.local_ip, self.local_port)
    }

    pub fn remote_str(&self) -> String {
        match self.remote_ip {
            Some(ip) if self.remote_port != 0 => addr_str(Some(ip), self.remote_port),
            _ => "*".to_string(),
        }
    }

    /// TCP in LISTEN state, or a UDP socket without a connected peer.
    pub fn is_listening(&self) -> bool {
        self.state.eq_ignore_ascii_case("listen") || (self.proto == "UDP" && self.remote_ip.is_none())
    }

    /// Bound to all interfaces (0.0.0.0 / ::), i.e. reachable from the network.
    pub fn wildcard_listener(&self) -> bool {
        self.is_listening() && self.local_ip.is_some_and(|ip| ip.is_unspecified())
    }

    /// A connected socket whose peer is known and which is not already closed.
    pub fn is_outbound(&self) -> bool {
        if self.is_listening() {
            return false;
        }
        let Some(ip) = self.remote_ip else { return false };
        if self.remote_port == 0 || ip.is_unspecified() || ip.is_loopback() {
            return false;
        }
        !matches!(
            self.state.to_ascii_lowercase().as_str(),
            "closed" | "timewait" | "deletetcb" | "unknown" | "-"
        )
    }

    pub fn remote_public(&self) -> bool {
        self.remote_ip.is_some_and(is_public_ip)
    }
}

fn addr_str(ip: Option<IpAddr>, port: u16) -> String {
    match ip {
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Some(ip) => format!("{ip}:{port}"),
        None => format!("*:{port}"),
    }
}

/// True for globally routable addresses. Private, loopback, link-local, CGNAT,
/// multicast and unspecified ranges are not public.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 0
                || cgnat)
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s0 & 0xfe00) == 0xfc00 // unique local
                || (s0 & 0xffc0) == 0xfe80) // link local
        }
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub taken_at: DateTime<Local>,
    pub system: SystemStats,
    pub ifaces: Vec<IfaceStat>,
    pub procs: Vec<ProcRow>,
    pub conns: Vec<ConnRow>,
}

/// Human readable byte count, e.g. `1.5 MiB`.
pub fn human_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes.max(0.0);
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn human_rate(bps: f64) -> String {
    format!("{}/s", human_bytes(bps))
}

pub fn fmt_uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    if d > 0 {
        format!("{d}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_classification() {
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("192.168.1.10".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_ip("fe80::1".parse().unwrap()));
        assert!(!is_public_ip("fd00::1".parse().unwrap()));
        assert!(is_public_ip("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn human_formatting() {
        assert_eq!(human_bytes(512.0), "512 B");
        assert_eq!(human_bytes(1536.0), "1.5 KiB");
        assert_eq!(fmt_uptime(90_061), "1d 01:01:01");
    }
}
