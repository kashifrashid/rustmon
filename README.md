# rustmon

A realtime **resource and network monitor** for **Windows and Linux**, written in Rust.
It shows CPU, memory, disks, interface throughput, processes and every TCP/UDP socket with
its owning process, and it **flags suspicious activity** — in particular programs sending
data out in ways that look like malware or exfiltration.

- Interactive TUI (tabs, live graphs, filter, sort, keyboard navigation)
- Heuristic detection engine with severity levels and de-duplicated "episodes"
- Optional JSON-lines alert log for SIEM/ingestion
- One-shot report mode for scripts and CI (exit code 2 on High/Critical)

## Build

Requires a recent stable Rust toolchain (`rustup`).

```bash
cargo build --release
```

Binary: `target/release/rustmon` (Linux) or `target\release\rustmon.exe` (Windows).

## Run

```bash
rustmon                          # interactive TUI, 1 s refresh
rustmon --interval 500           # faster refresh (200..=60000 ms)
rustmon --log alerts.jsonl       # also append new alerts as JSON lines
rustmon --upload-threshold 2     # flag sustained uploads above 2 MiB/s
rustmon --once                   # 3-second text report, exit code 0 / 2
```

For complete visibility run as **Administrator** (Windows) or **root** (Linux): without it the
OS hides the owning process of some sockets and the executable path of other users' processes.

## Tabs and keys

| Key | Action |
| --- | --- |
| `q`, `Esc`, `Ctrl+C` | quit |
| `Tab` / `→`, `Shift+Tab` / `←`, `1`–`4` | switch tab (Overview, Processes, Network, Alerts) |
| `↑`/`↓`, `j`/`k`, `PgUp`/`PgDn`, `Home`/`End` | move selection |
| `/` | filter (name, PID, path, address, state); `Enter` apply, `Esc` clear |
| `s` | cycle process sort: CPU → MEM → PID → NAME |
| `o` | Network tab: outbound connections only |
| `p` | pause / resume sampling |
| `c` | clear alert history |
| `?` | help overlay |

Rows are coloured by the highest active alert severity for that process.

## What is flagged

| Rule | Severity | Meaning |
| --- | --- | --- |
| `masquerade` | CRIT | A protected Windows process (`svchost.exe`, `lsass.exe`, …) runs outside `\Windows`. |
| `deleted-binary` | HIGH | Process runs from an executable deleted on disk (common after dropping a payload). |
| `suspicious-path` | HIGH (public) / MED (LAN) | Binary in a temp/Downloads/Public/`/tmp`/`/dev/shm` folder has an outbound connection. |
| `exposed-listener` | HIGH | Risky process (suspicious path or LOLBin) listens on all interfaces. |
| `scripting-egress` | MED | Scripting engine or LOLBin (`powershell`, `certutil`, `curl`, `nc`, `python`, …) sends to a public host. |
| `suspicious-port` | MED | Outbound connection to backdoor / IRC / Tor ports (4444, 1337, 6667, 9050, …). |
| `upload-spike` | HIGH / MED | An interface sustains ≥ threshold upload (default 5 MiB/s) for 3 samples, tx/rx ≥ 4 (HIGH if ≥ 8). Attributed to the process with the most public connections. |
| `fan-out` | MED | One process contacts ≥ 50 distinct public hosts. |
| `conn-flood` | LOW | One process holds ≥ 300 sockets. |
| `unowned-socket` | LOW | Public connection whose owning PID could not be resolved. |

Each alert is an *episode*: it fires once when the condition starts, its sample counter grows while
it persists, and it closes when the condition clears. The log only receives new episodes.

### Limitations (read before trusting an alert)

- Heuristics, not verdicts. Legitimate software (updaters, installers, backup tools, `curl` in scripts)
  can match. Use the detail line to decide.
- There are no per-process byte counters on either OS without kernel/ETW instrumentation, so
  "who is uploading" is inferred from the interface spike plus connection counts (best effort).
- UDP sockets on Windows expose no peer address, so UDP egress is not analysed.
- Connections that finish between two samples (a few seconds apart) can be missed.

## Output and exit codes

`--once` prints a report (top processes, outbound connections, alerts) and exits:
`0` nothing High/Critical active, `2` at least one High/Critical alert, `1` on error.

Alert log line (JSON Lines):

```json
{"id":1,"rule":"suspicious-path","severity":"high","pid":6376,"process":"curl.exe","title":"curl.exe runs from a user temp directory and has an outbound connection","detail":"10.2.0.2:58009 -> 23.52.181.212:443 [Established] exe=C:\\Users\\vg\\AppData\\Local\\Temp\\curl.exe","first_seen":"2026-11-01T21:04:38Z","last_seen":"2026-11-01T21:04:38Z","ticks":1}
```

## Platform notes

- **Windows**: sockets via `GetExtendedTcpTable`/`GetExtendedUdpTable` (through `netstat2`);
  processes and CPU via `sysinfo`. Works in Windows Terminal and classic conhost.
- **Linux**: sockets via `/proc/net/{tcp,tcp6,udp,udp6}` plus `/proc/<pid>/fd` for ownership (through `netstat2`).
- Terminal must support the alternate screen and UTF-8 box-drawing characters.

## Project layout

See [CLAUDE.md](CLAUDE.md) for architecture, the data flow, how to add a rule, testing, and
agent-facing notes.

## License

MIT
