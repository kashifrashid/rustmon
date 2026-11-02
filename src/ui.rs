//! Rendering. Pure presentation: reads `App`, never mutates it except table selection state.

use crate::app::{App, Tab};
use crate::detect::{remote_scope, Alert};
use crate::model::{fmt_uptime, human_bytes, human_rate, ConnRow, ProcRow, Severity};
use ratatui::{
    layout::{
        Constraint::{Length, Min, Percentage},
        Layout, Rect,
    },
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Clear, Gauge, Paragraph, Row, Sparkline, Table, TableState, Tabs, Wrap},
    Frame,
};
use std::collections::HashMap;

pub fn draw(f: &mut Frame, app: &mut App) {
    let [header, tabs, body, footer] = Layout::vertical([Length(1), Length(3), Min(0), Length(1)]).areas(f.area());

    draw_header(f, header, app);

    let titles = Tab::ALL.iter().map(|t| format!(" {} ", t.title()));
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .block(Block::bordered().title(" rustmon "))
            .highlight_style(Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        tabs,
    );

    match app.tab {
        Tab::Overview => draw_overview(f, body, app),
        Tab::Processes => draw_processes(f, body, app),
        Tab::Network => draw_network(f, body, app),
        Tab::Alerts => draw_alerts(f, body, app),
    }

    draw_footer(f, footer, app);
    if app.show_help {
        draw_help(f, f.area());
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let badge = Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD);
    let mut spans = vec![Span::styled(" rustmon ", badge)];
    if let Some(snap) = &app.snap {
        let s = &snap.system;
        spans.push(Span::raw(format!(
            "  {}  {}  up {}  ",
            s.hostname,
            s.os,
            fmt_uptime(s.uptime_secs)
        )));
        spans.push(Span::styled(
            format!("CPU {:.0}%", s.cpu_total),
            usage_style(s.cpu_total),
        ));
        spans.push(Span::raw(format!(
            "  MEM {}/{}  ",
            human_bytes(s.mem_used as f64),
            human_bytes(s.mem_total as f64)
        )));
    }
    let active = app.detector.active_alerts();
    let worst = active.iter().map(|a| a.severity).max();
    let alert_style = match worst {
        Some(s) => sev_style(s).add_modifier(Modifier::REVERSED),
        None => Style::new().fg(Color::Green),
    };
    spans.push(Span::styled(format!(" ALERTS {} ", active.len()), alert_style));
    if app.paused {
        spans.push(Span::styled(
            " PAUSED ",
            Style::new().fg(Color::Black).bg(Color::Yellow),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let line = if app.editing_filter {
        Line::from(vec![
            Span::styled(" filter: ", Style::new().fg(Color::Yellow)),
            Span::raw(format!("{}_", app.filter)),
            Span::styled("   Enter apply · Esc clear", Style::new().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                " q quit · Tab/←→/1-4 tabs · ↑↓ jk move · / filter · s sort · o outbound · p pause · c clear alerts · ? help",
                Style::new().fg(Color::DarkGray),
            ),
            Span::styled(format!("  {}", app.status), Style::new().fg(Color::Yellow)),
        ])
    };
    f.render_widget(Paragraph::new(line), area);
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    let Some(snap) = &app.snap else {
        f.render_widget(Paragraph::new("collecting first sample..."), area);
        return;
    };
    let s = &snap.system;
    let core_lines = s.cpu_per_core.len().div_ceil(4) as u16;
    let [top, cores_area, ifaces_area, disks_area] = Layout::vertical([
        Length(8),
        Length(core_lines.max(1) + 2),
        Min(5),
        Length(s.disks.len() as u16 + 3),
    ])
    .areas(area);

    // CPU: gauge + history sparkline. Memory: gauges + system details.
    let [cpu_area, mem_area] = Layout::horizontal([Percentage(50), Percentage(50)]).areas(top);

    let cpu_block = Block::bordered().title(format!(" CPU {:.1}% ", s.cpu_total));
    let inner = cpu_block.inner(cpu_area);
    f.render_widget(cpu_block, cpu_area);
    let [gauge_area, spark_area] = Layout::vertical([Length(1), Min(1)]).areas(inner);
    f.render_widget(gauge(s.cpu_total as f64), gauge_area);
    let data: Vec<u64> = app.cpu_hist.iter().copied().collect();
    f.render_widget(
        Sparkline::default()
            .data(data)
            .max(100)
            .style(Style::new().fg(Color::Cyan)),
        spark_area,
    );

    let mem_pct = pct(s.mem_used, s.mem_total);
    let swap_pct = pct(s.swap_used, s.swap_total);
    let mem_block = Block::bordered().title(" Memory ");
    let inner = mem_block.inner(mem_area);
    f.render_widget(mem_block, mem_area);
    let [mg, sg, info, net_spark] = Layout::vertical([Length(1), Length(1), Length(3), Length(2)]).areas(inner);
    f.render_widget(gauge(mem_pct).label(format!(
        "RAM {} / {}",
        human_bytes(s.mem_used as f64),
        human_bytes(s.mem_total as f64)
    )), mg);
    f.render_widget(gauge(swap_pct).label(format!(
        "SWAP {} / {}",
        human_bytes(s.swap_used as f64),
        human_bytes(s.swap_total as f64)
    )), sg);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!("host {}  procs {}", s.hostname, s.process_count)),
            Line::from(format!("interval {} ms", app.interval.as_millis())),
        ]),
        info,
    );
    let net: Vec<u64> = app.net_hist.iter().copied().collect();
    f.render_widget(
        Sparkline::default()
            .data(net)
            .style(Style::new().fg(Color::Magenta))
            .block(Block::default().title(" net KiB/s ")),
        net_spark,
    );

    // Per-core usage, four cores per line.
    let mut lines: Vec<Line> = Vec::new();
    for chunk in s.cpu_per_core.chunks(4) {
        let mut spans = Vec::new();
        for (i, usage) in chunk.iter().enumerate() {
            let idx = lines.len() * 4 + i;
            spans.push(Span::styled(format!("C{idx:<2} "), Style::new().fg(Color::DarkGray)));
            spans.push(Span::styled(bar(*usage, 12), usage_style(*usage)));
            spans.push(Span::raw(format!(" {usage:>5.1}%   ")));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Cores ")),
        cores_area,
    );

    // Interfaces.
    let th_upload = app.detector.th.upload_bps;
    let rows: Vec<Row> = snap
        .ifaces
        .iter()
        .map(|i| {
            let style = if i.tx_bps >= th_upload {
                Style::new().fg(Color::Red)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(i.name.clone()),
                Cell::from(human_rate(i.rx_bps)),
                Cell::from(human_rate(i.tx_bps)),
                Cell::from(human_bytes(i.rx_total as f64)),
                Cell::from(human_bytes(i.tx_total as f64)),
            ])
            .style(style)
        })
        .collect();
    let table = Table::new(rows, [Min(16), Length(14), Length(14), Length(12), Length(12)])
        .header(header_row(["INTERFACE", "RX/s", "TX/s", "RX TOTAL", "TX TOTAL"]))
        .block(Block::bordered().title(" Network interfaces "));
    f.render_widget(table, ifaces_area);

    // Disks.
    let rows: Vec<Row> = s
        .disks
        .iter()
        .map(|d| {
            let used = d.total.saturating_sub(d.available);
            Row::new(vec![
                Cell::from(d.mount.clone()),
                Cell::from(d.name.clone()),
                Cell::from(human_bytes(d.total as f64)),
                Cell::from(human_bytes(d.available as f64)),
                Cell::from(format!("{:.0}%", pct(used, d.total))),
            ])
        })
        .collect();
    let table = Table::new(rows, [Min(12), Min(12), Length(12), Length(12), Length(8)])
        .header(header_row(["MOUNT", "NAME", "TOTAL", "FREE", "USED"]))
        .block(Block::bordered().title(" Disks "));
    f.render_widget(table, disks_area);
}

fn draw_processes(f: &mut Frame, area: Rect, app: &mut App) {
    let [filter_area, table_area] = Layout::vertical([Length(3), Min(0)]).areas(area);
    draw_filter(f, filter_area, app);

    let sev = pid_severity(app);
    let rows: Vec<Row> = app
        .visible_procs()
        .iter()
        .map(|p| proc_row(p, sev.get(&p.pid).copied()))
        .collect();
    let n = rows.len();
    clamp_state(&mut app.proc_state, n);

    let table = Table::new(
        rows,
        [Length(8), Length(8), Length(24), Length(7), Length(11), Length(6), Min(10)],
    )
    .header(header_row(["PID", "PPID", "NAME", "CPU%", "MEM", "CONN", "PATH"]))
    .block(Block::bordered().title(format!(" Processes ({n}) · sort: {} ", app.sort.label())))
    .row_highlight_style(highlight())
    .highlight_symbol("▶ ");
    f.render_stateful_widget(table, table_area, &mut app.proc_state);
}

fn proc_row(p: &ProcRow, sev: Option<Severity>) -> Row<'static> {
    let row = Row::new(vec![
        Cell::from(p.pid.to_string()),
        Cell::from(p.parent.map(|x| x.to_string()).unwrap_or_else(|| "-".into())),
        Cell::from(p.name.clone()),
        Cell::from(format!("{:.1}", p.cpu)),
        Cell::from(human_bytes(p.mem as f64)),
        Cell::from(p.conns.to_string()),
        Cell::from(p.exe.clone().unwrap_or_else(|| "-".into())),
    ]);
    match sev {
        Some(s) => row.style(sev_style(s)),
        None => row,
    }
}

fn draw_network(f: &mut Frame, area: Rect, app: &mut App) {
    let [filter_area, table_area] = Layout::vertical([Length(3), Min(0)]).areas(area);
    draw_filter(f, filter_area, app);

    let sev = pid_severity(app);
    let conns = app.visible_conns();
    let n = conns.len();
    let rows: Vec<Row> = conns
        .iter()
        .map(|c| conn_row(c, c.pid.and_then(|p| sev.get(&p).copied())))
        .collect();
    clamp_state(&mut app.conn_state, n);

    let outbound = if app.outbound_only { "outbound only" } else { "all sockets" };
    let table = Table::new(
        rows,
        [
            Length(5),
            Length(24),
            Length(26),
            Length(12),
            Length(8),
            Length(18),
            Length(5),
        ],
    )
    .header(header_row(["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS", "SCOPE"]))
    .block(Block::bordered().title(format!(" Network ({n}) · {outbound} ")))
    .row_highlight_style(highlight())
    .highlight_symbol("▶ ");
    f.render_stateful_widget(table, table_area, &mut app.conn_state);
}

fn conn_row(c: &ConnRow, sev: Option<Severity>) -> Row<'static> {
    let row = Row::new(vec![
        Cell::from(c.proto),
        Cell::from(c.local_str()),
        Cell::from(c.remote_str()),
        Cell::from(c.state.clone()),
        Cell::from(c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
        Cell::from(c.process.clone()),
        Cell::from(remote_scope(c)),
    ]);
    match sev {
        Some(s) => row.style(sev_style(s)),
        None => row,
    }
}

fn draw_alerts(f: &mut Frame, area: Rect, app: &mut App) {
    let [table_area, detail_area] = Layout::vertical([Min(0), Length(6)]).areas(area);
    let alerts: Vec<&Alert> = app.detector.alerts().collect();
    clamp_state(&mut app.alert_state, alerts.len());

    let rows: Vec<Row> = alerts
        .iter()
        .map(|a| {
            Row::new(vec![
                Cell::from(a.first_seen.format("%H:%M:%S").to_string()),
                Cell::from(a.severity.label()).style(sev_style(a.severity)),
                Cell::from(a.rule),
                Cell::from(match a.pid {
                    Some(p) => format!("{} ({p})", a.process),
                    None => a.process.clone(),
                }),
                Cell::from(a.ticks.to_string()),
                Cell::from(a.title.clone()),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [Length(9), Length(6), Length(16), Length(26), Length(6), Min(20)],
    )
    .header(header_row(["TIME", "SEV", "RULE", "PROCESS", "TICKS", "TITLE"]))
    .block(Block::bordered().title(format!(" Alerts ({}) · c clears history ", alerts.len())))
    .row_highlight_style(highlight())
    .highlight_symbol("▶ ");
    f.render_stateful_widget(table, table_area, &mut app.alert_state);

    let selected = app.alert_state.selected().and_then(|i| alerts.get(i)).copied();
    let text = match selected {
        Some(a) => vec![
            Line::from(Span::styled(
                format!("[{}] {}", a.severity.label(), a.title),
                sev_style(a.severity),
            )),
            Line::from(a.detail.clone()),
            Line::from(Span::styled(
                format!(
                    "rule={}  first={}  last={}  samples={}",
                    a.rule,
                    a.first_seen.format("%H:%M:%S"),
                    a.last_seen.format("%H:%M:%S"),
                    a.ticks
                ),
                Style::new().fg(Color::DarkGray),
            )),
        ],
        None => vec![Line::from(Span::styled(
            "No alerts. Suspicious activity (e.g. temp-folder binaries talking to the internet, sustained one-way uploads) appears here.",
            Style::new().fg(Color::DarkGray),
        ))],
    };
    f.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" Detail ")),
        detail_area,
    );
}

fn draw_filter(f: &mut Frame, area: Rect, app: &App) {
    let style = if app.editing_filter {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let text = if app.filter.is_empty() && !app.editing_filter {
        "press / to filter by name, pid, path, address or state".to_string()
    } else {
        format!("{}{}", app.filter, if app.editing_filter { "_" } else { "" })
    };
    f.render_widget(
        Paragraph::new(text).style(style).block(Block::bordered().title(" Filter ")),
        area,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled("Keys", Style::new().add_modifier(Modifier::BOLD))),
        Line::from("  q / Esc / Ctrl+C    quit"),
        Line::from("  Tab, ←/→, 1-4       switch tab"),
        Line::from("  ↑/↓ or j/k          move selection (PgUp/PgDn/Home/End too)"),
        Line::from("  /                   filter processes / connections (Enter apply, Esc clear)"),
        Line::from("  s                   cycle process sort: CPU, MEM, PID, NAME"),
        Line::from("  o                   network tab: outbound connections only"),
        Line::from("  p                   pause / resume sampling"),
        Line::from("  c                   clear alert history"),
        Line::from("  ?                   toggle this help"),
        Line::from(""),
        Line::from(Span::styled("Detection rules", Style::new().add_modifier(Modifier::BOLD))),
        Line::from("  masquerade       protected Windows process running outside \\Windows (CRIT)"),
        Line::from("  deleted-binary   process runs from a deleted executable (HIGH)"),
        Line::from("  suspicious-path  temp/Downloads/public/tmp binary with network I/O (HIGH/MED)"),
        Line::from("  exposed-listener risky process listening on all interfaces (HIGH)"),
        Line::from("  scripting-egress shell / LOLBin talking to a public host (MED)"),
        Line::from("  suspicious-port  connection to backdoor / IRC / Tor ports (MED)"),
        Line::from("  upload-spike     sustained one-way upload on an interface (HIGH/MED)"),
        Line::from("  fan-out          one process contacting many public hosts (MED)"),
        Line::from("  conn-flood       huge socket count for one process (LOW)"),
        Line::from("  unowned-socket   public connection with no visible owner (LOW)"),
        Line::from(""),
        Line::from(Span::styled(
            "Run as Administrator (Windows) or root (Linux) for full process and socket visibility.",
            Style::new().fg(Color::Yellow),
        )),
        Line::from(Span::styled("Press any key to close.", Style::new().fg(Color::DarkGray))),
    ];
    let w = 92.min(area.width);
    let h = (lines.len() as u16 + 2).min(area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Help ")),
        rect,
    );
}

/// Highest active severity per PID, used to colour table rows.
fn pid_severity(app: &App) -> HashMap<u32, Severity> {
    let mut m: HashMap<u32, Severity> = HashMap::new();
    for a in app.detector.active_alerts() {
        if let Some(pid) = a.pid {
            let e = m.entry(pid).or_insert(a.severity);
            if a.severity > *e {
                *e = a.severity;
            }
        }
    }
    m
}

/// Keeps the table selection inside `[0, len)`.
fn clamp_state(state: &mut TableState, len: usize) {
    if len == 0 {
        state.select(None);
        return;
    }
    match state.selected() {
        Some(i) if i < len => {}
        Some(_) => state.select(Some(len - 1)),
        None => state.select(Some(0)),
    }
}

fn header_row<const N: usize>(cols: [&'static str; N]) -> Row<'static> {
    Row::new(cols).style(
        Style::new()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn highlight() -> Style {
    Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
}

fn sev_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        Severity::High => Style::new().fg(Color::Red),
        Severity::Medium => Style::new().fg(Color::Yellow),
        Severity::Low => Style::new().fg(Color::Cyan),
    }
}

fn usage_style(pct: f32) -> Style {
    let color = if pct >= 90.0 {
        Color::Red
    } else if pct >= 70.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    Style::new().fg(color)
}

fn gauge(percent: f64) -> Gauge<'static> {
    let p = percent.clamp(0.0, 100.0);
    let color = usage_style(p as f32).fg.unwrap_or(Color::Green);
    Gauge::default()
        .gauge_style(Style::new().fg(color).bg(Color::Black))
        .ratio(p / 100.0)
        .label(format!("{p:.1}%"))
}

fn bar(pct: f32, width: usize) -> String {
    let filled = ((pct.clamp(0.0, 100.0) / 100.0) * width as f32).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn pct(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::detect::Thresholds;
    use ratatui::{backend::TestBackend, Terminal};
    use ratatui::crossterm::event::{KeyCode, KeyEvent};
    use std::time::Duration;

    /// Renders every tab (and the help overlay) against live data to catch panics
    /// and layout arithmetic errors without needing a real terminal.
    #[test]
    fn all_tabs_render_without_panicking() {
        let mut app = App::new(Thresholds::default(), Duration::from_secs(1), None);
        app.tick();
        let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
        for key in ['1', '2', '3', '4', '?'] {
            app.on_key(KeyEvent::new(KeyCode::Char(key), ratatui::crossterm::event::KeyModifiers::NONE));
            if key == '?' {
                app.on_key(KeyEvent::new(KeyCode::Null, ratatui::crossterm::event::KeyModifiers::NONE));
            }
            terminal.draw(|f| draw(f, &mut app)).unwrap();
        }
        // Tiny terminal must not panic either.
        let mut small = Terminal::new(TestBackend::new(30, 8)).unwrap();
        small.draw(|f| draw(f, &mut app)).unwrap();
    }
}
