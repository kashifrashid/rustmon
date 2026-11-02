//! Application state, key handling, the TUI event loop and the `--once` report.

use crate::collector::Collector;
use crate::detect::{Alert, Detector, Thresholds};
use crate::model::{human_bytes, fmt_uptime, ConnRow, ProcRow, Severity, Snapshot};
use crate::ui;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use ratatui::DefaultTerminal;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

/// Samples kept for the sparkline graphs.
pub const HISTORY_LEN: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Processes,
    Network,
    Alerts,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Overview, Tab::Processes, Tab::Network, Tab::Alerts];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Processes => "Processes",
            Tab::Network => "Network",
            Tab::Alerts => "Alerts",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortBy {
    Cpu,
    Memory,
    Pid,
    Name,
}

impl SortBy {
    pub fn next(self) -> Self {
        match self {
            SortBy::Cpu => SortBy::Memory,
            SortBy::Memory => SortBy::Pid,
            SortBy::Pid => SortBy::Name,
            SortBy::Name => SortBy::Cpu,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortBy::Cpu => "CPU",
            SortBy::Memory => "MEM",
            SortBy::Pid => "PID",
            SortBy::Name => "NAME",
        }
    }
}

pub struct App {
    pub tab: Tab,
    pub snap: Option<Snapshot>,
    pub paused: bool,
    pub filter: String,
    pub editing_filter: bool,
    pub sort: SortBy,
    pub outbound_only: bool,
    pub show_help: bool,
    pub proc_state: TableState,
    pub conn_state: TableState,
    pub alert_state: TableState,
    pub cpu_hist: VecDeque<u64>,
    pub net_hist: VecDeque<u64>,
    pub status: String,
    pub quit: bool,
    pub interval: Duration,
    pub detector: Detector,
    collector: Collector,
    log: Option<File>,
    last_tick: Instant,
}

impl App {
    pub fn new(th: Thresholds, interval: Duration, log: Option<File>) -> Self {
        Self {
            tab: Tab::Overview,
            snap: None,
            paused: false,
            filter: String::new(),
            editing_filter: false,
            sort: SortBy::Cpu,
            outbound_only: false,
            show_help: false,
            proc_state: TableState::default(),
            conn_state: TableState::default(),
            alert_state: TableState::default(),
            cpu_hist: VecDeque::with_capacity(HISTORY_LEN),
            net_hist: VecDeque::with_capacity(HISTORY_LEN),
            status: "collecting first sample...".to_string(),
            quit: false,
            interval,
            detector: Detector::new(th),
            collector: Collector::new(),
            log,
            last_tick: Instant::now(),
        }
    }

    /// Takes a sample, updates histories and runs detection.
    pub fn tick(&mut self) {
        if self.paused {
            return;
        }
        self.last_tick = Instant::now();
        let snap = self.collector.collect();

        push_bounded(&mut self.cpu_hist, snap.system.cpu_total as u64);
        let net_bps: f64 = snap
            .ifaces
            .iter()
            .filter(|i| !i.name.eq_ignore_ascii_case("lo"))
            .map(|i| i.rx_bps + i.tx_bps)
            .sum();
        push_bounded(&mut self.net_hist, (net_bps / 1024.0) as u64);

        let fresh = self.detector.evaluate(&snap);
        if !fresh.is_empty() {
            self.status = format!("{} new alert(s) - press 4 to view", fresh.len());
            for a in &fresh {
                if let Err(e) = write_alert(&mut self.log, a) {
                    self.status = format!("log write failed: {e}");
                }
            }
        }
        self.snap = Some(snap);
    }

    pub fn visible_procs(&self) -> Vec<&ProcRow> {
        let Some(snap) = &self.snap else { return Vec::new() };
        let needle = self.filter.to_ascii_lowercase();
        let mut v: Vec<&ProcRow> = snap
            .procs
            .iter()
            .filter(|p| {
                needle.is_empty()
                    || p.name.to_ascii_lowercase().contains(&needle)
                    || p.pid.to_string() == needle
                    || p.exe.as_deref().is_some_and(|e| e.to_ascii_lowercase().contains(&needle))
            })
            .collect();
        match self.sort {
            SortBy::Cpu => v.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(Ordering::Equal)),
            SortBy::Memory => v.sort_by(|a, b| b.mem.cmp(&a.mem)),
            SortBy::Pid => v.sort_by_key(|p| p.pid),
            SortBy::Name => v.sort_by_key(|p| p.name.to_ascii_lowercase()),
        }
        v
    }

    pub fn visible_conns(&self) -> Vec<&ConnRow> {
        let Some(snap) = &self.snap else { return Vec::new() };
        let needle = self.filter.to_ascii_lowercase();
        let mut v: Vec<&ConnRow> = snap
            .conns
            .iter()
            .filter(|c| !self.outbound_only || c.is_outbound())
            .filter(|c| {
                needle.is_empty()
                    || c.process.to_ascii_lowercase().contains(&needle)
                    || c.remote_str().contains(&needle)
                    || c.local_str().contains(&needle)
                    || c.state.to_ascii_lowercase().contains(&needle)
                    || c.pid.is_some_and(|p| p.to_string() == needle)
            })
            .collect();
        v.sort_by_key(|c| (c.process.to_ascii_lowercase(), c.remote_port));
        v
    }

    fn list_len(&self) -> usize {
        match self.tab {
            Tab::Overview => 0,
            Tab::Processes => self.visible_procs().len(),
            Tab::Network => self.visible_conns().len(),
            Tab::Alerts => self.detector.alerts().count(),
        }
    }

    fn move_sel(&mut self, delta: isize) {
        let len = self.list_len();
        let state = match self.tab {
            Tab::Processes => &mut self.proc_state,
            Tab::Network => &mut self.conn_state,
            Tab::Alerts => &mut self.alert_state,
            Tab::Overview => return,
        };
        if len == 0 {
            state.select(None);
            return;
        }
        let cur = state.selected().unwrap_or(0) as isize;
        state.select(Some((cur + delta).clamp(0, len as isize - 1) as usize));
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.show_help = false;
    }

    fn cycle_tab(&mut self, forward: bool) {
        let n = Tab::ALL.len();
        let i = self.tab.index();
        let next = if forward { (i + 1) % n } else { (i + n - 1) % n };
        self.set_tab(Tab::ALL[next]);
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }
        if self.editing_filter {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.editing_filter = false;
                }
                KeyCode::Enter => self.editing_filter = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('/') => {
                if matches!(self.tab, Tab::Overview | Tab::Alerts) {
                    self.set_tab(Tab::Processes);
                }
                self.editing_filter = true;
            }
            KeyCode::Tab | KeyCode::Right => self.cycle_tab(true),
            KeyCode::BackTab | KeyCode::Left => self.cycle_tab(false),
            KeyCode::Char(c @ '1'..='4') => {
                let idx = c as usize - '1' as usize;
                self.set_tab(Tab::ALL[idx]);
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::PageUp => self.move_sel(-10),
            KeyCode::PageDown => self.move_sel(10),
            KeyCode::Home => self.move_sel(isize::MIN / 2),
            KeyCode::End => self.move_sel(isize::MAX / 2),
            KeyCode::Char('s') => self.sort = self.sort.next(),
            KeyCode::Char('o') => self.outbound_only = !self.outbound_only,
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                self.status = if self.paused { "paused".into() } else { "resumed".into() };
            }
            KeyCode::Char('c') => {
                self.detector.clear();
                self.status = "alert history cleared".into();
            }
            _ => {}
        }
    }
}

fn push_bounded<T>(q: &mut VecDeque<T>, v: T) {
    if q.len() >= HISTORY_LEN {
        q.pop_front();
    }
    q.push_back(v);
}

/// Appends one alert as a JSON line (no-op when logging is disabled).
pub fn write_alert(log: &mut Option<File>, alert: &Alert) -> Result<()> {
    if let Some(f) = log.as_mut() {
        writeln!(f, "{}", serde_json::to_string(alert)?)?;
        f.flush()?;
    }
    Ok(())
}

pub fn run_tui(app: &mut App) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, app);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    app.tick();
    loop {
        terminal.draw(|f| ui::draw(f, app))?;
        if app.quit {
            break;
        }
        let wait = app.interval.saturating_sub(app.last_tick.elapsed());
        if event::poll(wait)? {
            if let Event::Key(key) = event::read()? {
                app.on_key(key);
            }
        }
        if app.last_tick.elapsed() >= app.interval {
            app.tick();
        }
    }
    Ok(())
}

/// Non-interactive mode: samples for a few seconds, prints a report and returns an
/// exit code (2 when a High or Critical alert is active, 0 otherwise).
pub fn run_once(th: Thresholds, mut log: Option<File>) -> Result<i32> {
    const SAMPLES: u32 = 3;
    let mut collector = Collector::new();
    let mut detector = Detector::new(th);
    let mut last: Option<Snapshot> = None;
    for _ in 0..SAMPLES {
        thread::sleep(Duration::from_millis(1000));
        let snap = collector.collect();
        for a in detector.evaluate(&snap) {
            write_alert(&mut log, &a)?;
        }
        last = Some(snap);
    }
    let Some(snap) = last else { return Ok(0) };
    print_report(&snap, &detector);

    let worst = detector.active_alerts().iter().map(|a| a.severity).max();
    Ok(if worst.is_some_and(|s| s >= Severity::High) { 2 } else { 0 })
}

fn print_report(snap: &Snapshot, detector: &Detector) {
    let s = &snap.system;
    println!("rustmon report  host={}  os={}  uptime={}", s.hostname, s.os, fmt_uptime(s.uptime_secs));
    println!(
        "CPU {:.1}%   MEM {} / {}   SWAP {} / {}   processes {}   sockets {}",
        s.cpu_total,
        human_bytes(s.mem_used as f64),
        human_bytes(s.mem_total as f64),
        human_bytes(s.swap_used as f64),
        human_bytes(s.swap_total as f64),
        s.process_count,
        snap.conns.len()
    );

    println!("\nTop processes by CPU:");
    let mut procs: Vec<&ProcRow> = snap.procs.iter().collect();
    procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(Ordering::Equal));
    for p in procs.iter().take(10) {
        println!(
            "  pid {:>7}  cpu {:>5.1}%  mem {:>10}  {:<24} {}",
            p.pid,
            p.cpu,
            human_bytes(p.mem as f64),
            p.name,
            p.exe.as_deref().unwrap_or("-")
        );
    }

    let outbound: Vec<&ConnRow> = snap.conns.iter().filter(|c| c.is_outbound()).collect();
    println!("\nOutbound connections: {}", outbound.len());
    for c in outbound.iter().take(40) {
        println!(
            "  {:<4} {:<26} -> {:<26} {:<12} pid={:<7} {}",
            c.proto,
            c.local_str(),
            c.remote_str(),
            c.state,
            c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            c.process
        );
    }

    let alerts: Vec<&Alert> = detector.alerts().collect();
    println!("\nAlerts: {}", alerts.len());
    for a in &alerts {
        println!(
            "  [{:<4}] {} {:<16} {}",
            a.severity.label(),
            a.first_seen.format("%H:%M:%S"),
            a.rule,
            a.title
        );
        println!("         {}", a.detail);
    }
}
