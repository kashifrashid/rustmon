# CLAUDE.md — rustmon project memory

Read this first. It is the single source of truth for working on this repository.
Keep it current when you change architecture, rules, keys, or conventions.

## 1. What this project is

`rustmon` is a Rust CLI/TUI that monitors a Windows or Linux machine in realtime:

- resources: CPU (total + per core), RAM, swap, disks, process list;
- networking: every TCP/UDP socket with its owning process, per-interface throughput;
- security: a heuristic engine that flags suspicious activity, especially programs that
  run from temp folders, abuse scripting tools, or push large one-way uploads (possible
  data exfiltration).

Hard requirements from the owner:
1. Works on **both Windows and Linux** from the same codebase (no OS-only features in the core path).
2. **Interactive TUI** (ratatui) as the primary interface.
3. Detection is **read-only**: the tool never kills processes, blocks traffic, or modifies the system.
   Keep it that way unless the owner explicitly asks for response actions.

## 2. Status (as of 2026-11-01)

- v0.1.0, first complete version.
- `cargo build` (Windows, x86_64-pc-windows-msvc/gnu host) — clean, no warnings.
- `cargo test` — 10 unit tests pass, including a TUI render smoke test over all tabs (`TestBackend`).
- `cargo check --target x86_64-unknown-linux-gnu` — passes (checked from Windows; the Linux
  *runtime* has not been exercised yet — no WSL distro is installed on the dev box).
- End-to-end positive test on Windows: a copy of `curl.exe` in `%TEMP%` making a live HTTPS
  connection raised `suspicious-path` (HIGH) and `scripting-egress` (MED) and wrote them to the JSON log.
- Clean machine baseline: `rustmon --once` raised 0 alerts (no false positives on the dev box).
- Not yet done: manual TUI check in a real terminal, release-binary size/perf measurement,
  Linux runtime test, CI pipeline, signed Windows binaries.

## 3. Repository layout

```
Cargo.toml                 deps: ratatui 0.29 (+crossterm via ratatui::crossterm), sysinfo 0.33,
                           netstat2 0.11, clap 4, chrono 0.4, serde/serde_json, anyhow
src/main.rs                CLI (clap), opens log file, builds Thresholds, dispatches TUI vs --once
src/model.rs               plain data: Snapshot, SystemStats, IfaceStat, ProcRow, ConnRow, Severity,
                           is_public_ip, human_bytes/human_rate/fmt_uptime (+ unit tests)
src/collector.rs           Collector: sysinfo refresh + netstat2 socket enumeration -> Snapshot
src/platform.rs            OS-knowledge tables: core Windows processes, LOLBins, suspicious dirs,
                           suspicious ports, path normalization (+ unit tests)
src/detect.rs              Thresholds, Detector (episode tracking), all rules (+ unit tests)
src/app.rs                 App state, key handling, tick(), TUI event loop, run_once() report
src/ui.rs                  All rendering (ratatui widgets), colour mapping, render smoke test
.claude/skills/rustmon-dev/SKILL.md   task recipes for agents (add rule, add tab, test on Linux)
README.md                  user documentation
```

## 4. Architecture and data flow

```
            every `interval` ms (App::tick)
Collector::collect() ──► Snapshot { system, ifaces, procs, conns }
                                   │
                    Detector::evaluate(&Snapshot)
                       ├─ collect_hits(): pure rules -> Vec<Hit{key, rule, severity, ...}>
                       ├─ episode bookkeeping: new key => new Alert (returned, logged)
                       │                       existing key => ticks += 1, escalate severity
                       └─ keys not seen this sample are dropped from `active`
                                   │
          App { snap, cpu_hist, net_hist, detector, status, tab state... }
                                   │
                ui::draw(frame, &mut App)   (reads App; only TableState is mutated)
```

- Single-threaded. The event loop polls input with a timeout equal to the time until the next tick.
- Sampling a full process/socket table is done on the UI thread; typical cost is well under 100 ms.
  If that changes, move `Collector::collect` onto a worker thread with an `mpsc` channel.
- `Snapshot` is cloned nowhere; `App` holds the latest one. Histories are bounded (`HISTORY_LEN = 120`).
- Alert history is bounded by `Thresholds::history_cap` (1000).

### 4.1 OS abstraction

- `sysinfo` gives CPU, memory, disks, networks, processes and exe paths on both OSes.
- `netstat2` gives sockets + owning PIDs on both OSes (IPv4 and IPv6, TCP and UDP).
- `platform.rs` holds the only place where OS naming/path knowledge lives. Paths are normalized to
  lower-case with `\` before matching, so one rule set covers `C:\...\AppData\Local\Temp` and `/tmp`.
- Never add `#[cfg(windows)]` logic to the detection path. If an OS difference is unavoidable, put it
  behind a function in `collector.rs` or `platform.rs` and document it here.

### 4.2 Known OS quirks

- Windows: many system socket owners need Administrator; `exe` is `None` for protected processes.
  PID 0/4 "System" can own sockets with no name; these show as `-`.
- Linux: `exe` for kernel threads is `None`; a running binary that was deleted has ` (deleted)` appended
  to its path, which the `deleted-binary` rule checks. Socket→PID mapping needs read access to `/proc/<pid>/fd`.
- `netstat2` returns no peer for UDP; `ConnRow::is_listening()` treats a UDP socket with no peer as bound.
- ProtonVPN-style tunnels make remote addresses look like `10.x` LAN addresses; those are scored as LAN.

## 5. Detection rules (src/detect.rs, src/platform.rs)

Every rule produces a `Hit` whose `key` identifies the episode (rule + pid + remote, etc.).

| rule | where | fires when | severity |
| --- | --- | --- | --- |
| `masquerade` | per process | name in `WINDOWS_CORE_PROCESSES` and exe not under `\windows\` | Critical |
| `deleted-binary` | per process | exe contains `(deleted)` | High |
| `conn-flood` | per process | `conns >= th.conn_flood` (300) | Low |
| `exposed-listener` | per conn | wildcard listener AND (suspicious location OR LOLBin OR deleted) | High |
| `suspicious-path` | per conn | outbound AND exe in `SUSPICIOUS_DIRS` | High if public, Medium if LAN |
| `scripting-egress` | per conn | outbound AND LOLBin AND public remote | Medium |
| `suspicious-port` | per conn | outbound AND remote port in `SUSPICIOUS_PORTS` | Medium |
| `unowned-socket` | per conn | no PID AND outbound AND public | Low |
| `fan-out` | per process | ≥ `th.fanout` (50) distinct public remote IPs in this sample | Medium |
| `upload-spike` | per interface | tx ≥ `th.upload_bps` (5 MiB/s) AND tx/rx ≥ `th.upload_ratio` (4) for `th.sustain_ticks` (3) samples | High if ratio ≥ 8, else Medium |

Definitions:
- `is_outbound()`: connected socket, remote known and not loopback/unspecified, state not closed/timewait.
- `is_public_ip()`: not private, loopback, link-local, CGNAT (100.64/10), multicast, broadcast, unspecified (v4);
  not loopback/unspecified/multicast/ULA/link-local (v6).
- Loopback interfaces (`lo`, `*Loopback*`) are excluded from `upload-spike`.

Tuning: thresholds are in `Thresholds::default()`; the upload threshold can be set with `--upload-threshold`.
Lists (core processes, LOLBins, dirs, ports) are `const` slices at the top of `platform.rs`.

Adding false-positive control (allow-list) is NOT implemented yet — see §9.

## 6. TUI (src/app.rs, src/ui.rs)

- Tabs: Overview (gauges, CPU/net sparklines, per-core bars, interfaces, disks), Processes, Network, Alerts.
- Alert severity colours rows in Processes and Network by PID.
- Keys are handled in `App::on_key`. Filter mode (`editing_filter`) swallows all keys except Esc/Enter/Backspace.
  Key press filtering: only `KeyEventKind::Press` is handled (required on Windows to avoid double input).
- Terminal lifecycle: `ratatui::init()` / `ratatui::restore()` (installs a panic hook that restores the terminal).
- Only `TableState` selection is mutated during draw (`clamp_state`).

## 7. CLI

```
rustmon [--interval MS] [--log FILE] [--upload-threshold MIB_PER_S] [--once]
```
`--once`: 3 samples at 1 s spacing, prints a report, exit code 2 if a High/Critical alert is active.

## 8. Build, run, test

```bash
cargo build                       # debug
cargo build --release             # LTO, stripped
cargo test                        # unit tests + TUI render smoke test
cargo run -- --once               # headless check on the current machine
cargo check --target x86_64-unknown-linux-gnu   # cross-check Linux (needs: rustup target add x86_64-unknown-linux-gnu)
```

Positive detection test (Windows, PowerShell) — expect HIGH `suspicious-path` + MED `scripting-egress`:

```powershell
$dst = Join-Path $env:TEMP "curl.exe"; Copy-Item C:\Windows\System32\curl.exe $dst -Force
$p = Start-Process $dst -ArgumentList "-s","-m","40","--limit-rate","4k","-o","NUL","https://www.microsoft.com/" -PassThru -WindowStyle Hidden
Start-Sleep 3; cargo run -q -- --once; Stop-Process -Id $p.Id -Force; Remove-Item $dst
```

Timing matters: a transfer that finishes before the 3-second sampling window is invisible. Use a rate-limited download.

## 9. Known gaps / roadmap (ordered by value)

1. Allow-list / suppression file (e.g. `rustmon.toml`) so known-good updaters stop alerting.
2. Per-process network throughput: Linux via `/proc/<pid>/net/dev` is per-namespace, not per-process;
   realistic options are eBPF (Linux) and ETW/`GetPerTcpConnectionEStats` (Windows). Not started.
3. Worker thread for collection so a slow socket enumeration cannot stall the UI.
4. Signature/publisher check of executables (Authenticode on Windows, package ownership on Linux).
5. Config for thresholds beyond `--upload-threshold`.
6. CI workflow building Windows and Linux binaries and running `cargo test`.
7. Real-terminal QA of the TUI on Windows Terminal and a Linux terminal.

## 10. Conventions for agents

- Keep the detection path pure: `Detector::evaluate` must depend only on `Snapshot` + its own state.
  That is what makes it testable — add a unit test in `detect.rs` for every new rule.
- New OS-specific tables go in `platform.rs`, lower-case, normalized with `normalize()`.
- Never block the UI thread with a new network call (DNS lookups, reputation APIs). If added, do it on a worker thread.
- Do not add process-kill, firewall or quarantine actions without an explicit request from the owner.
- Do not log secrets. The alert log includes process paths and remote addresses by design.
- Keep `README.md` (user-facing) and this file (agent-facing) consistent with the code when rules, keys or flags change.
- Run `cargo test` and `cargo build` (no new warnings) before reporting work as done. For Linux-facing
  changes also run `cargo check --target x86_64-unknown-linux-gnu`.
- Report what was verified and what was not. The TUI interaction on a real terminal has not been verified by an automated test.

## 11. Memory notes for future sessions

- The owner's machine is Windows 11 (DESKTOP host, 8 GB RAM); the dev shell is PowerShell 7.
- Toolchain: rustc/cargo 1.99.x stable. The `x86_64-unknown-linux-gnu` target is installed for cross-checks.
- A ProtonVPN tunnel is active on the dev box, so many outbound sockets show `10.x` remotes.
- Benign background noise on the dev box that can look suspicious but is fine: `MsMpEng.exe`
  (Defender) and Electron/Chromium apps with many sockets. Expect `conn-flood`/`fan-out` candidates from browsers.
