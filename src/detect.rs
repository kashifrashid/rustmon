//! Heuristic detection engine for suspicious / possibly-exfiltrating activity.
//!
//! The engine is pure logic over [`Snapshot`]s (plus a little rolling state for
//! sustained-upload detection), so it is unit-testable without touching the OS.
//!
//! Alerts are *episodes*: an alert fires when a condition first becomes true,
//! its `ticks` counter grows while it stays true, and it is closed once the
//! condition disappears. Only new episodes are returned from [`Detector::evaluate`],
//! which is what the log file receives.

use crate::model::{human_rate, is_public_ip, ConnRow, IfaceStat, Severity, Snapshot};
use crate::platform;
use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Thresholds {
    /// Sustained upload rate (bytes/s) on one interface that counts as a spike.
    pub upload_bps: f64,
    /// Minimum tx/rx ratio for a spike to be considered one-way (exfiltration-like).
    pub upload_ratio: f64,
    /// Consecutive samples a spike must persist before alerting.
    pub sustain_ticks: u32,
    /// Distinct public hosts contacted by one process before "fan-out" fires.
    pub fanout: usize,
    /// Open sockets per process before "connection flood" fires.
    pub conn_flood: usize,
    /// Number of alerts kept in memory.
    pub history_cap: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            upload_bps: 5.0 * 1024.0 * 1024.0,
            upload_ratio: 4.0,
            sustain_ticks: 3,
            fanout: 50,
            conn_flood: 300,
            history_cap: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: u64,
    pub rule: &'static str,
    pub severity: Severity,
    pub pid: Option<u32>,
    pub process: String,
    pub title: String,
    pub detail: String,
    pub first_seen: DateTime<Local>,
    pub last_seen: DateTime<Local>,
    /// Number of samples during which this episode stayed active.
    pub ticks: u32,
}

struct Hit {
    key: String,
    rule: &'static str,
    severity: Severity,
    pid: Option<u32>,
    process: String,
    title: String,
    detail: String,
}

fn hit(
    key: String,
    rule: &'static str,
    severity: Severity,
    pid: Option<u32>,
    process: &str,
    title: String,
    detail: String,
) -> Hit {
    Hit { key, rule, severity, pid, process: process.to_string(), title, detail }
}

pub struct Detector {
    pub th: Thresholds,
    history: VecDeque<Alert>,
    /// Active episode key -> id of its history entry.
    active: HashMap<String, u64>,
    spike_ticks: HashMap<String, u32>,
    next_id: u64,
}

impl Detector {
    pub fn new(th: Thresholds) -> Self {
        Self {
            th,
            history: VecDeque::new(),
            active: HashMap::new(),
            spike_ticks: HashMap::new(),
            next_id: 1,
        }
    }

    /// Runs all rules over `snap`. Returns alerts for episodes that *started* in this sample.
    pub fn evaluate(&mut self, snap: &Snapshot) -> Vec<Alert> {
        let now = snap.taken_at;
        let mut seen: HashSet<String> = HashSet::new();
        let mut fresh = Vec::new();

        for h in self.collect_hits(snap) {
            if !seen.insert(h.key.clone()) {
                continue;
            }
            if let Some(&id) = self.active.get(&h.key) {
                if let Some(a) = self.history.iter_mut().rev().find(|a| a.id == id) {
                    a.ticks += 1;
                    a.last_seen = now;
                    if h.severity > a.severity {
                        a.severity = h.severity;
                    }
                }
            } else {
                let id = self.next_id;
                self.next_id += 1;
                let alert = Alert {
                    id,
                    rule: h.rule,
                    severity: h.severity,
                    pid: h.pid,
                    process: h.process,
                    title: h.title,
                    detail: h.detail,
                    first_seen: now,
                    last_seen: now,
                    ticks: 1,
                };
                self.history.push_back(alert.clone());
                while self.history.len() > self.th.history_cap {
                    self.history.pop_front();
                }
                self.active.insert(h.key, id);
                fresh.push(alert);
            }
        }

        // Episodes whose condition vanished this sample end here.
        self.active.retain(|k, _| seen.contains(k));
        fresh
    }

    /// All alerts in history, newest first.
    pub fn alerts(&self) -> impl Iterator<Item = &Alert> {
        self.history.iter().rev()
    }

    /// Alerts whose condition is still true in the latest sample.
    pub fn active_alerts(&self) -> Vec<&Alert> {
        let ids: HashSet<u64> = self.active.values().copied().collect();
        self.history.iter().filter(|a| ids.contains(&a.id)).collect()
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }

    fn collect_hits(&mut self, snap: &Snapshot) -> Vec<Hit> {
        let th = self.th.clone();
        let mut hits = Vec::new();
        let names: HashMap<u32, &str> = snap.procs.iter().map(|p| (p.pid, p.name.as_str())).collect();

        // ---- per-process rules
        for p in &snap.procs {
            let exe = p.exe.as_deref().unwrap_or("");
            if platform::masquerades_as_core(&p.name, p.exe.as_deref()) {
                hits.push(hit(
                    format!("masq|{}", p.pid),
                    "masquerade",
                    Severity::Critical,
                    Some(p.pid),
                    &p.name,
                    format!("'{}' impersonates a Windows core process", p.name),
                    format!("running from {exe}"),
                ));
            }
            if exe.contains("(deleted)") {
                hits.push(hit(
                    format!("deleted|{}", p.pid),
                    "deleted-binary",
                    Severity::High,
                    Some(p.pid),
                    &p.name,
                    format!("'{}' runs from an executable that was deleted on disk", p.name),
                    format!("exe={exe}"),
                ));
            }
            if p.conns >= th.conn_flood {
                hits.push(hit(
                    format!("flood|{}", p.pid),
                    "conn-flood",
                    Severity::Low,
                    Some(p.pid),
                    &p.name,
                    format!("{} holds {} open sockets", p.name, p.conns),
                    "possible scanner, worm, or proxy".to_string(),
                ));
            }
        }

        // ---- per-connection rules
        let mut public_ips: HashMap<u32, HashSet<IpAddr>> = HashMap::new();
        let mut public_counts: HashMap<u32, usize> = HashMap::new();
        for c in &snap.conns {
            let Some(pid) = c.pid else {
                if c.is_outbound() && c.remote_public() {
                    hits.push(hit(
                        format!("unowned|{}", c.remote_str()),
                        "unowned-socket",
                        Severity::Low,
                        None,
                        "-",
                        format!("socket with no visible owner talks to {}", c.remote_str()),
                        format!("local {} state {}", c.local_str(), c.state),
                    ));
                }
                continue;
            };
            let name = c.process.as_str();
            let exe = c.exe.as_deref().unwrap_or("");
            let location = platform::suspicious_location(exe);
            let lolbin = platform::is_lolbin(name);

            if c.is_listening() {
                if c.wildcard_listener() && (location.is_some() || lolbin || exe.contains("(deleted)")) {
                    hits.push(hit(
                        format!("listen|{pid}|{}", c.local_port),
                        "exposed-listener",
                        Severity::High,
                        Some(pid),
                        name,
                        format!("{name} accepts connections on all interfaces, port {}", c.local_port),
                        format!("exe={exe}"),
                    ));
                }
                continue;
            }
            if !c.is_outbound() {
                continue;
            }

            let remote = c.remote_str();
            let public = c.remote_public();
            let detail = format!(
                "{} -> {} [{}] exe={}",
                c.local_str(),
                remote,
                c.state,
                if exe.is_empty() { "?" } else { exe }
            );
            if public {
                public_ips.entry(pid).or_default().extend(c.remote_ip);
                *public_counts.entry(pid).or_default() += 1;
            }
            if let Some(why) = location {
                let sev = if public { Severity::High } else { Severity::Medium };
                hits.push(hit(
                    format!("susp-path|{pid}|{remote}"),
                    "suspicious-path",
                    sev,
                    Some(pid),
                    name,
                    format!("{name} runs from {why} and has an outbound connection"),
                    detail.clone(),
                ));
            }
            if lolbin && public {
                hits.push(hit(
                    format!("lolbin|{pid}|{remote}"),
                    "scripting-egress",
                    Severity::Medium,
                    Some(pid),
                    name,
                    format!("{name} (scripting / LOLBin) sends traffic to a public host"),
                    detail.clone(),
                ));
            }
            if let Some(why) = platform::suspicious_port(c.remote_port) {
                hits.push(hit(
                    format!("port|{pid}|{remote}"),
                    "suspicious-port",
                    Severity::Medium,
                    Some(pid),
                    name,
                    format!("outbound connection to port {} ({why})", c.remote_port),
                    detail,
                ));
            }
        }

        // ---- fan-out: one process talking to many public hosts
        for (pid, ips) in &public_ips {
            if ips.len() >= th.fanout {
                let name = names.get(pid).copied().unwrap_or("-");
                hits.push(hit(
                    format!("fanout|{pid}"),
                    "fan-out",
                    Severity::Medium,
                    Some(*pid),
                    name,
                    format!("{name} contacts {} distinct public hosts", ips.len()),
                    format!("threshold {}", th.fanout),
                ));
            }
        }

        // ---- sustained one-way upload per interface (exfiltration signal)
        for i in &snap.ifaces {
            if is_loopback(&i.name) {
                continue;
            }
            if let Some(h) = self.upload_hit(i, &th, &public_counts, &names) {
                hits.push(h);
            }
        }
        hits
    }

    fn upload_hit(
        &mut self,
        i: &IfaceStat,
        th: &Thresholds,
        public_counts: &HashMap<u32, usize>,
        names: &HashMap<u32, &str>,
    ) -> Option<Hit> {
        let ratio = if i.rx_bps < 1.0 { f64::INFINITY } else { i.tx_bps / i.rx_bps };
        let spiking = i.tx_bps >= th.upload_bps && ratio >= th.upload_ratio;
        if !spiking {
            self.spike_ticks.remove(&i.name);
            return None;
        }
        let ticks = self.spike_ticks.entry(i.name.clone()).or_insert(0);
        *ticks += 1;
        if *ticks < th.sustain_ticks {
            return None;
        }

        // Best-effort attribution: the process with the most public connections.
        let top = public_counts
            .iter()
            .max_by_key(|(pid, n)| (**n, std::cmp::Reverse(**pid)))
            .map(|(pid, n)| (*pid, *n));
        let (pid, pname, source) = match top {
            Some((p, n)) => {
                let name = names.get(&p).copied().unwrap_or("-");
                (Some(p), name, format!("{name} (pid {p}, {n} public connections)"))
            }
            None => (None, "-", "no attributable process".to_string()),
        };
        let ratio_txt = if ratio.is_finite() { format!("{ratio:.1}") } else { "inf".to_string() };
        let sev = if ratio >= th.upload_ratio * 2.0 { Severity::High } else { Severity::Medium };
        Some(hit(
            format!("upload|{}", i.name),
            "upload-spike",
            sev,
            pid,
            pname,
            format!("sustained upload on {}: {} (rx {})", i.name, human_rate(i.tx_bps), human_rate(i.rx_bps)),
            format!("tx/rx ratio {ratio_txt}; likely source: {source}"),
        ))
    }
}

fn is_loopback(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo" || n.contains("loopback")
}

/// Public so the UI can explain why a connection is flagged.
pub fn remote_scope(c: &ConnRow) -> &'static str {
    match c.remote_ip {
        None => "-",
        Some(ip) if is_public_ip(ip) => "PUB",
        Some(_) => "LAN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcRow, SystemStats};
    use chrono::Local;

    fn conn(pid: u32, process: &str, exe: &str, remote: &str, port: u16) -> ConnRow {
        ConnRow {
            proto: "TCP",
            local_ip: Some("192.168.1.5".parse().unwrap()),
            local_port: 50000,
            remote_ip: Some(remote.parse().unwrap()),
            remote_port: port,
            state: "Established".into(),
            pid: Some(pid),
            process: process.into(),
            exe: Some(exe.into()),
        }
    }

    fn snap(procs: Vec<ProcRow>, conns: Vec<ConnRow>, ifaces: Vec<IfaceStat>) -> Snapshot {
        Snapshot { taken_at: Local::now(), system: SystemStats::default(), ifaces, procs, conns }
    }

    fn proc_row(pid: u32, name: &str, exe: &str) -> ProcRow {
        ProcRow { pid, parent: None, name: name.into(), exe: Some(exe.into()), cpu: 0.0, mem: 0, conns: 0 }
    }

    #[test]
    fn temp_binary_talking_to_internet_is_high() {
        let mut d = Detector::new(Thresholds::default());
        let exe = "/tmp/payload";
        let s = snap(
            vec![proc_row(42, "payload", exe)],
            vec![conn(42, "payload", exe, "203.0.113.7", 443)],
            vec![],
        );
        let fresh = d.evaluate(&s);
        let a = fresh.iter().find(|a| a.rule == "suspicious-path").expect("alert");
        assert_eq!(a.severity, Severity::High);
    }

    #[test]
    fn episodes_fire_once_and_count_ticks() {
        let mut d = Detector::new(Thresholds::default());
        let exe = "/tmp/payload";
        let s = snap(vec![proc_row(42, "payload", exe)], vec![conn(42, "payload", exe, "203.0.113.7", 443)], vec![]);
        let first = d.evaluate(&s).len();
        let second = d.evaluate(&s).len();
        assert!(first >= 1);
        assert_eq!(second, 0, "same episode must not re-fire");
        assert!(d.active_alerts().iter().any(|a| a.ticks >= 2));
    }

    #[test]
    fn sustained_one_way_upload_fires_after_sustain_ticks() {
        let mut d = Detector::new(Thresholds::default());
        let iface = IfaceStat {
            name: "eth0".into(),
            rx_bps: 1000.0,
            tx_bps: 50.0 * 1024.0 * 1024.0,
            rx_total: 0,
            tx_total: 0,
        };
        let mut fired = 0;
        for _ in 0..3 {
            let s = snap(vec![], vec![], vec![iface.clone()]);
            fired += d.evaluate(&s).iter().filter(|a| a.rule == "upload-spike").count();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn masquerading_svchost_is_critical() {
        let mut d = Detector::new(Thresholds::default());
        let s = snap(vec![proc_row(7, "svchost.exe", r"C:\Users\bob\svchost.exe")], vec![], vec![]);
        let fresh = d.evaluate(&s);
        assert!(fresh.iter().any(|a| a.rule == "masquerade" && a.severity == Severity::Critical));
    }
}
