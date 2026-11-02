---
name: rustmon-dev
description: Task recipes for working on the rustmon Rust TUI (Windows/Linux resource and network monitor with suspicious-activity detection). Use when adding or tuning a detection rule, adding a TUI tab or key, changing collection, or verifying the build on Windows and Linux.
---

# rustmon development recipes

Read `CLAUDE.md` at the repo root first for architecture, rule table and conventions.

## Verify a change (always)

```bash
cargo build
cargo test
cargo check --target x86_64-unknown-linux-gnu   # Linux cross-check; run `rustup target add x86_64-unknown-linux-gnu` once
```

No new warnings are acceptable. Report what was run and what passed.

## Add a detection rule

1. Decide the rule's signal using only `Snapshot` data (`ConnRow`, `ProcRow`, `IfaceStat`). Do not call the OS from `detect.rs`.
2. Put any new name/path/port lists in `src/platform.rs` as `const` slices. Compare paths via `platform::normalize`.
3. In `Detector::collect_hits` (`src/detect.rs`), push a `hit(key, rule, severity, pid, process, title, detail)`.
   - Key must be stable across samples for the same episode, e.g. `format!("rule|{pid}|{remote}")`.
   - Keep `rule` a `&'static str` kebab-case name.
4. Add a unit test in the `tests` module of `detect.rs` that builds a `Snapshot` and asserts the alert and its severity.
   Also assert benign input does not fire.
5. Add the rule to the table in `CLAUDE.md` §5, to the help text in `src/ui.rs` (`draw_help`), and to the rule list in `README.md`.

## Tune a threshold

- Defaults live in `Thresholds::default()` (`src/detect.rs`). The upload threshold is also a CLI flag (`--upload-threshold`, MiB/s).
- Change one value at a time and confirm with `cargo run -- --once` on a quiet machine (expect 0 alerts) and with a deliberate test (see CLAUDE.md §8).

## Add a TUI key or tab

- Tabs: extend `Tab` and `Tab::ALL` in `src/app.rs`, add a `draw_*` function in `src/ui.rs`, and add the match arm in `ui::draw`.
- Keys: add an arm in `App::on_key`. Respect filter-edit mode, which returns early before the normal key match.
- If the tab has a selectable list, add a `TableState` field, a `list_len` arm and a `move_sel` arm, and call `clamp_state` before rendering.
- Extend the render smoke test in `ui.rs` so the new tab is drawn at 140x45 and at 30x8.

## Diagnose "no alert appeared"

1. Confirm the process is alive during sampling. `--once` samples for about 3 seconds.
2. Confirm the socket is visible: run `cargo run -- --once` and look for the PID in the "Outbound connections" section.
3. If the socket is listed but no alert fired, check `is_outbound()` (loopback and closed states are excluded) and `suspicious_location()` for the exe path.

## Platform cautions

- Windows: `netstat2` needs no admin for the user's own sockets, but other users' PIDs and some `exe` paths require elevation. Do not treat `None` for `exe` as an error.
- Linux: `/proc/<pid>/fd` reads fail for other users' processes without root. Degrade gracefully (`-` owner), never panic.
- Never use `unwrap()` on sysinfo or netstat2 results in the collection path.
