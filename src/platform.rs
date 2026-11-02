//! Platform knowledge (process names, risky locations, ports) kept in one place
//! so the detection engine stays OS-agnostic. Every path comparison goes through
//! [`normalize`], so the same rules match `C:\Users\x\AppData\Local\Temp\a.exe`
//! and `/tmp/a` alike.

/// Windows processes that must only ever run from `%SystemRoot%`.
/// A process with one of these names running from anywhere else is a
/// classic masquerading indicator.
const WINDOWS_CORE_PROCESSES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "lsaiso.exe",
    "dwm.exe",
    "taskhostw.exe",
    "conhost.exe",
    "spoolsv.exe",
    "explorer.exe",
    "sihost.exe",
    "fontdrvhost.exe",
];

/// Legitimate tools that attackers routinely abuse to download or exfiltrate data
/// ("living off the land"). Stored without `.exe`, lower-case.
const LOLBINS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msbuild",
    "installutil",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "perl",
    "ruby",
    "php",
    "bash",
    "sh",
    "dash",
    "zsh",
    "openssl",
];

/// Locations where legitimate software rarely keeps long-lived network clients.
/// Patterns are matched against the normalized (lower-case, `\`) path.
const SUSPICIOUS_DIRS: &[(&str, &str)] = &[
    ("\\appdata\\local\\temp\\", "a user temp directory"),
    ("\\windows\\temp\\", "the Windows temp directory"),
    ("\\users\\public\\", "the public user folder"),
    ("\\downloads\\", "a Downloads folder"),
    ("\\$recycle.bin\\", "the recycle bin"),
    ("\\var\\tmp\\", "/var/tmp"),
    ("\\tmp\\", "/tmp"),
    ("\\dev\\shm\\", "/dev/shm (shared memory)"),
];

/// Remote ports commonly used by backdoors, reverse shells, IRC C2 and Tor.
const SUSPICIOUS_PORTS: &[(u16, &str)] = &[
    (1337, "common backdoor port"),
    (4444, "Metasploit default listener"),
    (4445, "reverse-shell port"),
    (5555, "common backdoor / ADB port"),
    (6666, "common backdoor port"),
    (6667, "IRC (frequent C2 channel)"),
    (6697, "IRC over TLS (frequent C2 channel)"),
    (9001, "Tor ORPort"),
    (9050, "Tor SOCKS proxy"),
    (9051, "Tor control port"),
    (31337, "Back Orifice / elite backdoor port"),
];

/// Lower-case, forward slashes turned into backslashes.
pub fn normalize(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

/// Returns a human reason when the executable lives in a risky location.
pub fn suspicious_location(exe: &str) -> Option<&'static str> {
    if exe.is_empty() {
        return None;
    }
    let p = normalize(exe);
    SUSPICIOUS_DIRS
        .iter()
        .find(|(pat, _)| p.contains(pat))
        .map(|(_, why)| *why)
}

/// True when `name` is a protected Windows process that runs outside `\Windows\`.
pub fn masquerades_as_core(name: &str, exe: Option<&str>) -> bool {
    let lower = name.to_ascii_lowercase();
    if !WINDOWS_CORE_PROCESSES.contains(&lower.as_str()) {
        return false;
    }
    match exe {
        Some(path) if !path.is_empty() => !normalize(path).contains("\\windows\\"),
        _ => false,
    }
}

pub fn is_lolbin(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let base = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
    LOLBINS.contains(&base) || base.starts_with("python")
}

pub fn suspicious_port(port: u16) -> Option<&'static str> {
    SUSPICIOUS_PORTS.iter().find(|(p, _)| *p == port).map(|(_, why)| *why)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_temp_execution_on_both_platforms() {
        assert!(suspicious_location(r"C:\Users\bob\AppData\Local\Temp\x.exe").is_some());
        assert!(suspicious_location("/tmp/evil").is_some());
        assert!(suspicious_location("/dev/shm/.x").is_some());
        assert!(suspicious_location(r"C:\Program Files\App\app.exe").is_none());
        assert!(suspicious_location("/usr/bin/ssh").is_none());
        assert!(suspicious_location("").is_none());
    }

    #[test]
    fn masquerading_core_process() {
        assert!(masquerades_as_core("svchost.exe", Some(r"C:\Users\bob\svchost.exe")));
        assert!(!masquerades_as_core("svchost.exe", Some(r"C:\Windows\System32\svchost.exe")));
        assert!(!masquerades_as_core("svchost.exe", None));
        assert!(!masquerades_as_core("notepad.exe", Some(r"C:\x\notepad.exe")));
    }

    #[test]
    fn lolbins_and_ports() {
        assert!(is_lolbin("powershell.exe"));
        assert!(is_lolbin("PowerShell.EXE"));
        assert!(is_lolbin("python3.12"));
        assert!(!is_lolbin("firefox"));
        assert_eq!(suspicious_port(4444), Some("Metasploit default listener"));
        assert_eq!(suspicious_port(443), None);
    }
}
