//! Samples the OS: CPU/memory/disks, per-interface throughput, processes and
//! TCP/UDP sockets (with owning PID). Cross-platform via `sysinfo` + `netstat2`.

use crate::model::{ConnRow, DiskStat, IfaceStat, ProcRow, Snapshot, SystemStats};
use chrono::Local;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use sysinfo::{Disks, Networks, Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub struct Collector {
    sys: System,
    networks: Networks,
    disks: Disks,
    last: Instant,
}

impl Collector {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_all();
        sys.refresh_memory();
        Self {
            sys,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            last: Instant::now(),
        }
    }

    /// Takes one sample. Rates are computed against the previous call.
    pub fn collect(&mut self) -> Snapshot {
        let elapsed = self.last.elapsed().as_secs_f64().max(0.001);
        self.last = Instant::now();

        self.sys.refresh_cpu_all();
        self.sys.refresh_memory();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, process_refresh());
        self.networks.refresh(true);
        self.disks.refresh(true);

        let conns = read_connections(&self.sys);
        let mut conn_counts: HashMap<u32, usize> = HashMap::new();
        for c in &conns {
            if let Some(pid) = c.pid {
                *conn_counts.entry(pid).or_default() += 1;
            }
        }

        let procs = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| ProcRow {
                pid: pid.as_u32(),
                parent: p.parent().map(|x| x.as_u32()),
                name: p.name().to_string_lossy().into_owned(),
                exe: p.exe().map(|e| e.display().to_string()),
                cpu: p.cpu_usage(),
                mem: p.memory(),
                conns: conn_counts.get(&pid.as_u32()).copied().unwrap_or(0),
            })
            .collect();

        let ifaces = self
            .networks
            .iter()
            .map(|(name, d)| IfaceStat {
                name: name.clone(),
                rx_bps: d.received() as f64 / elapsed,
                tx_bps: d.transmitted() as f64 / elapsed,
                rx_total: d.total_received(),
                tx_total: d.total_transmitted(),
            })
            .collect();

        let disks = self
            .disks
            .list()
            .iter()
            .map(|d| DiskStat {
                name: d.name().to_string_lossy().into_owned(),
                mount: d.mount_point().display().to_string(),
                total: d.total_space(),
                available: d.available_space(),
            })
            .collect();

        let system = SystemStats {
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            os: System::long_os_version().unwrap_or_else(|| std::env::consts::OS.into()),
            uptime_secs: System::uptime(),
            cpu_total: self.sys.global_cpu_usage(),
            cpu_per_core: self.sys.cpus().iter().map(|c| c.cpu_usage()).collect(),
            mem_total: self.sys.total_memory(),
            mem_used: self.sys.used_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
            disks,
            process_count: self.sys.processes().len(),
        };

        Snapshot { taken_at: Local::now(), system, ifaces, procs, conns }
    }
}

fn process_refresh() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_exe(UpdateKind::OnlyIfNotSet)
}

/// Enumerates TCP and UDP sockets for IPv4 and IPv6 and resolves owners.
/// Returns an empty list (instead of failing the whole tick) if the OS call fails,
/// e.g. due to missing privileges.
fn read_connections(sys: &System) -> Vec<ConnRow> {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let pf = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = match get_sockets_info(af, pf) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    sockets
        .into_iter()
        .map(|si| {
            let pid = si.associated_pids.first().copied();
            let (process, exe) = match pid.and_then(|p| sys.process(Pid::from_u32(p))) {
                Some(p) => (
                    p.name().to_string_lossy().into_owned(),
                    p.exe().map(|e| e.display().to_string()),
                ),
                None => ("-".to_string(), None),
            };
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(t) => ConnRow {
                    proto: "TCP",
                    local_ip: Some(t.local_addr),
                    local_port: t.local_port,
                    remote_ip: unspecified_to_none(t.remote_addr),
                    remote_port: t.remote_port,
                    state: format!("{:?}", t.state),
                    pid,
                    process,
                    exe,
                },
                ProtocolSocketInfo::Udp(u) => ConnRow {
                    proto: "UDP",
                    local_ip: Some(u.local_addr),
                    local_port: u.local_port,
                    remote_ip: None,
                    remote_port: 0,
                    state: "-".to_string(),
                    pid,
                    process,
                    exe,
                },
            }
        })
        .collect()
}

fn unspecified_to_none(ip: IpAddr) -> Option<IpAddr> {
    if ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}
