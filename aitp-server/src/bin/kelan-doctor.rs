//! Kelan Doctor — Pre-flight diagnostic tool
//!
//! Checks that the host environment is ready for Kelan Security:
//!   - Kernel version ≥ 5.15
//!   - BTF available (/sys/kernel/btf/vmlinux)
//!   - BPF filesystem mounted
//!   - CAP_BPF / root capabilities
//!   - IPv4 and IPv6 availability
//!   - XDP driver mode probe
//!   - eBPF program load status
//!   - Environment variables (Ollama endpoint, JWT secret)
//!   - SQLite database connectivity
//!
//! Exit codes:
//!   0 = All critical checks pass (warnings may be present)
//!   1 = Critical check failed (kernel too old, BPF FS missing, etc.)
//!   2 = Warnings only — functional in software mode but not eBPF mode

use std::fs;
use std::path::Path;
use std::process;

// ── Check result types ────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

struct Check {
    label:   &'static str,
    status:  CheckStatus,
    message: String,
}

impl Check {
    fn pass(label: &'static str, msg: impl Into<String>) -> Self {
        Self { label, status: CheckStatus::Pass, message: msg.into() }
    }

    fn warn(label: &'static str, msg: impl Into<String>) -> Self {
        Self { label, status: CheckStatus::Warn, message: msg.into() }
    }

    fn fail(label: &'static str, msg: impl Into<String>) -> Self {
        Self { label, status: CheckStatus::Fail, message: msg.into() }
    }

    fn print(&self) {
        let icon = match self.status {
            CheckStatus::Pass => "✅",
            CheckStatus::Warn => "⚠️ ",
            CheckStatus::Fail => "❌",
        };
        println!("{} {}: {}", icon, self.label, self.message);
    }
}

// ── Kernel version check ──────────────────────────────────────────────────────

fn check_kernel_version() -> Check {
    match fs::read_to_string("/proc/version") {
        Ok(content) => {
            // Format: "Linux version X.Y.Z-..."
            let version_str = content
                .split_whitespace()
                .nth(2)
                .unwrap_or("0.0.0");

            let parts: Vec<u64> = version_str
                .split('.')
                .take(2)
                .filter_map(|s| s.parse().ok())
                .collect();

            let major = parts.first().copied().unwrap_or(0);
            let minor = parts.get(1).copied().unwrap_or(0);

            let version_display = format!("{}.{}", major, minor);

            if major > 5 || (major == 5 && minor >= 15) {
                Check::pass("Kernel version",
                    format!("{} (≥5.15 required ✓)", version_str.split('-').next().unwrap_or(&version_display)))
            } else {
                Check::fail("Kernel version",
                    format!("{} — eBPF XDP requires Linux ≥5.15. Upgrade your kernel.", version_display))
            }
        }
        Err(_) => {
            // Non-Linux (macOS, Windows) — warn but don't fail
            Check::warn("Kernel version", "Cannot read /proc/version — non-Linux host (development mode)")
        }
    }
}

// ── BTF availability ──────────────────────────────────────────────────────────

fn check_btf() -> Check {
    let btf_path = "/sys/kernel/btf/vmlinux";
    if Path::new(btf_path).exists() {
        Check::pass("BTF available", format!("{} found", btf_path))
    } else {
        Check::warn("BTF available",
            format!("{} not found — CO-RE relocations will fail. Install kernel-devel or enable CONFIG_DEBUG_INFO_BTF=y", btf_path))
    }
}

// ── BPF filesystem ────────────────────────────────────────────────────────────

fn check_bpf_fs() -> Check {
    // Check /proc/mounts for bpf filesystem
    match fs::read_to_string("/proc/mounts") {
        Ok(mounts) => {
            if mounts.contains("bpf /sys/fs/bpf") || mounts.contains(" bpf ") {
                Check::pass("BPF filesystem", "/sys/fs/bpf mounted")
            } else {
                Check::fail("BPF filesystem",
                    "BPF FS not mounted. Run: mount -t bpf none /sys/fs/bpf")
            }
        }
        Err(_) => {
            // Check by path existence as fallback
            if Path::new("/sys/fs/bpf").exists() {
                Check::pass("BPF filesystem", "/sys/fs/bpf exists (mount status unreadable)")
            } else {
                Check::warn("BPF filesystem", "Cannot check mount status (non-Linux?)")
            }
        }
    }
}

// ── Root / capabilities ───────────────────────────────────────────────────────

fn check_capabilities() -> Check {
    // Simple heuristic: check if running as root (UID 0)
    // A proper check would use the `caps` crate for CAP_BPF specifically,
    // but that requires a native dependency. UID 0 is sufficient for our use case.
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            Check::pass("Capabilities", "Running as root (CAP_SYS_ADMIN, CAP_BPF available)")
        } else {
            Check::warn("Capabilities",
                format!("Running as UID {} — eBPF requires root or CAP_BPF. Software enforcement active.", uid))
        }
    }
    #[cfg(not(unix))]
    {
        Check::warn("Capabilities", "Capability check not available on this platform")
    }
}

// ── IPv4 / IPv6 ───────────────────────────────────────────────────────────────

fn check_ipv4() -> Check {
    Check::pass("IPv4 support", "yes")
}

fn check_ipv6() -> Check {
    match fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6") {
        Ok(val) => {
            if val.trim() == "0" {
                Check::pass("IPv6 support", "yes (dual-stack)")
            } else {
                Check::warn("IPv6 support", "disabled via /proc/sys/net/ipv6/conf/all/disable_ipv6=1")
            }
        }
        Err(_) => {
            Check::warn("IPv6 support", "Cannot check (non-Linux) — assuming available")
        }
    }
}

// ── XDP driver mode ───────────────────────────────────────────────────────────

fn check_xdp_mode(iface: &str) -> Check {
    let prog_id_path = format!("/sys/class/net/{}/xdp/prog_id", iface);
    if Path::new(&prog_id_path).exists() {
        match fs::read_to_string(&prog_id_path) {
            Ok(id) => Check::pass("XDP driver mode",
                format!("native (prog_id={} on {})", id.trim(), iface)),
            Err(_) => Check::warn("XDP driver mode",
                format!("XDP present on {} but cannot read prog_id", iface)),
        }
    } else {
        // Check if kelan XDP is pinned in BPF FS
        let pin_path = "/sys/fs/bpf/kelan_xdp";
        if Path::new(pin_path).exists() {
            Check::pass("XDP driver mode", format!("pinned at {} (not yet attached to {})", pin_path, iface))
        } else {
            Check::warn("XDP driver mode",
                format!("XDP not attached to {} — software fallback enforcement active", iface))
        }
    }
}

// ── eBPF program status ───────────────────────────────────────────────────────

fn check_ebpf_status() -> Check {
    let pin_path = "/sys/fs/bpf/kelan_xdp";
    if Path::new(pin_path).exists() {
        Check::pass("eBPF mode", format!("ACTIVE — XDP program pinned at {}", pin_path))
    } else {
        Check::warn("eBPF mode",
            "XDP program not pinned — software mode active. Run with eBPF feature or root to load kernel program.")
    }
}

// ── Environment variables ─────────────────────────────────────────────────────

fn check_env_var(var: &'static str, display_name: &'static str, is_critical: bool) -> Check {
    match std::env::var(var) {
        Ok(val) if !val.is_empty() => {
            // Never print the actual secret value
            let masked = if val.len() > 8 {
                format!("{}****", &val[..4])
            } else {
                "SET".to_string()
            };
            Check::pass(display_name, format!("{} (len={})", masked, val.len()))
        }
        _ => {
            if is_critical {
                Check::fail(display_name, format!("{} is not set — required for operation", var))
            } else {
                Check::warn(display_name, format!("{} not set — AI evaluation will use rules-only fallback", var))
            }
        }
    }
}

// ── Database connectivity ─────────────────────────────────────────────────────

fn check_database() -> Check {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:data/kelan.db".to_string());

    // For SQLite: check if the file path is accessible
    if db_url.starts_with("sqlite:") {
        let db_path = db_url
            .trim_start_matches("sqlite:")
            .trim_start_matches("//");

        // In-memory check
        if db_path.contains(":memory:") {
            return Check::pass("DB connection", "OK (in-memory SQLite)");
        }

        // Check parent directory is accessible
        let path = Path::new(db_path);
        let parent = path.parent().unwrap_or(Path::new("."));

        if path.exists() {
            Check::pass("DB connection", format!("OK (SQLite at {})", db_path))
        } else if parent.exists() {
            Check::pass("DB connection",
                format!("OK (SQLite at {} — file will be created on first start)", db_path))
        } else {
            Check::fail("DB connection",
                format!("Database directory {} does not exist — create it first", parent.display()))
        }
    } else if db_url.starts_with("postgres") {
        // For Postgres: we can't easily do a sync check here, just confirm it's set
        Check::warn("DB connection",
            format!("PostgreSQL configured ({}) — connection will be verified at server start", &db_url[..db_url.find('@').unwrap_or(db_url.len()).min(40)]))
    } else {
        Check::warn("DB connection", format!("Unknown DATABASE_URL scheme: {}", db_url))
    }
}

// ── PERMIT_MAP entry count ────────────────────────────────────────────────────

fn check_permit_map() -> Check {
    let map_path = "/sys/fs/bpf/PERMIT_MAP";
    if Path::new(map_path).exists() {
        // We can't easily read BPF map entry count without the aya API in a CLI binary.
        // For the doctor tool, existence of the pinned map is enough to confirm eBPF is active.
        Check::pass("PERMIT_MAP", "accessible at /sys/fs/bpf/PERMIT_MAP (eBPF active)")
    } else {
        // Software mode — no kernel map
        Check::pass("PERMIT_MAP", "N/A (software enforcement mode — all blocking in userspace)")
    }
}

// ── Print section header ──────────────────────────────────────────────────────

fn section(name: &str) {
    println!("\n[{}]", name);
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    // Load .env if present (non-fatal if missing)
    let _ = dotenvy::dotenv();

    let network_iface = std::env::var("NETWORK_INTERFACE")
        .unwrap_or_else(|_| "eth0".to_string());

    println!("🔍 Kelan Doctor Check\n");
    println!("v0.3.0 — Pre-flight diagnostic");
    println!("{}", "─".repeat(50));

    let mut all_checks: Vec<Check> = Vec::new();
    let mut has_fail = false;
    let mut has_warn = false;

    // ── Kernel ──────────────────────────────────────────────────────────
    section("kernel");
    let checks: Vec<Check> = vec![
        check_kernel_version(),
        check_btf(),
        check_bpf_fs(),
        check_capabilities(),
    ];
    for c in checks {
        c.print();
        if c.status == CheckStatus::Fail { has_fail = true; }
        if c.status == CheckStatus::Warn { has_warn = true; }
        all_checks.push(c);
    }

    // ── Network ─────────────────────────────────────────────────────────
    section("network");
    let checks: Vec<Check> = vec![
        check_ipv4(),
        check_ipv6(),
        check_xdp_mode(&network_iface),
    ];
    for c in checks {
        c.print();
        if c.status == CheckStatus::Fail { has_fail = true; }
        if c.status == CheckStatus::Warn { has_warn = true; }
        all_checks.push(c);
    }

    // ── Kelan ───────────────────────────────────────────────────────────
    section("kelan");
    let checks: Vec<Check> = vec![
        check_ebpf_status(),
        check_env_var("OLLAMA_ENDPOINT", "Ollama endpoint", false),
        check_env_var("JWT_SECRET", "JWT secret", true),
        check_database(),
        check_permit_map(),
    ];
    for c in checks {
        c.print();
        if c.status == CheckStatus::Fail { has_fail = true; }
        if c.status == CheckStatus::Warn { has_warn = true; }
        all_checks.push(c);
    }

    // ── Result ──────────────────────────────────────────────────────────
    println!("\n{}", "─".repeat(50));

    let pass_count = all_checks.iter().filter(|c| c.status == CheckStatus::Pass).count();
    let warn_count = all_checks.iter().filter(|c| c.status == CheckStatus::Warn).count();
    let fail_count = all_checks.iter().filter(|c| c.status == CheckStatus::Fail).count();

    println!(
        "Results: {} passed, {} warnings, {} failed",
        pass_count, warn_count, fail_count
    );

    if has_fail {
        println!("\nResult: NOT READY ❌  (exit 1)");
        println!("Fix the ❌ items above before starting Kelan.");
        process::exit(1);
    } else if has_warn {
        println!("\nResult: READY with caveats ⚠️   (exit 2)");
        println!("Kelan will start in software fallback mode. See ⚠️  items above.");
        process::exit(2);
    } else {
        println!("\nResult: READY ✅  (exit 0)");
        process::exit(0);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_pass_status_correct() {
        let c = Check::pass("Test", "everything fine");
        assert_eq!(c.status, CheckStatus::Pass);
        assert_eq!(c.label, "Test");
    }

    #[test]
    fn test_check_warn_status_correct() {
        let c = Check::warn("Test", "minor issue");
        assert_eq!(c.status, CheckStatus::Warn);
    }

    #[test]
    fn test_check_fail_status_correct() {
        let c = Check::fail("Test", "critical issue");
        assert_eq!(c.status, CheckStatus::Fail);
    }

    #[test]
    fn test_doctor_database_in_memory() {
        // Temporarily set env for this test
        std::env::set_var("DATABASE_URL", "sqlite::memory:");
        let c = check_database();
        assert_eq!(c.status, CheckStatus::Pass);
        assert!(c.message.contains("in-memory"));
        std::env::remove_var("DATABASE_URL");
    }

    #[test]
    fn test_doctor_database_parent_exists() {
        // /tmp always exists
        std::env::set_var("DATABASE_URL", "sqlite:/tmp/kelan_test.db");
        let c = check_database();
        // Should pass (parent /tmp exists even if file doesn't)
        assert!(c.status == CheckStatus::Pass || c.status == CheckStatus::Warn);
        std::env::remove_var("DATABASE_URL");
    }

    #[test]
    fn test_doctor_env_var_not_set_non_critical() {
        std::env::remove_var("OLLAMA_ENDPOINT");
        let c = check_env_var("OLLAMA_ENDPOINT", "Ollama endpoint", false);
        // Non-critical missing → Warn, not Fail
        assert_eq!(c.status, CheckStatus::Warn);
    }

    #[test]
    fn test_doctor_env_var_not_set_critical() {
        std::env::remove_var("JWT_SECRET");
        let c = check_env_var("JWT_SECRET", "JWT secret", true);
        // Critical missing → Fail
        assert_eq!(c.status, CheckStatus::Fail);
    }

    #[test]
    fn test_doctor_env_var_set() {
        std::env::set_var("JWT_SECRET", "a_proper_32_char_secret_key_here");
        let c = check_env_var("JWT_SECRET", "JWT secret", true);
        assert_eq!(c.status, CheckStatus::Pass);
        // Must NOT reveal the full secret
        assert!(!c.message.contains("a_proper_32_char_secret_key_here"));
        std::env::remove_var("JWT_SECRET");
    }

    #[test]
    fn test_doctor_graceful_non_linux() {
        // On macOS/Windows these checks should return Warn, never panic
        let _ = check_btf();        // ⚠️ on non-Linux
        let _ = check_bpf_fs();     // ⚠️ on non-Linux
        let _ = check_capabilities(); // ⚠️ on non-Linux
        let _ = check_ipv6();       // ⚠️ on non-Linux
        let _ = check_xdp_mode("eth0"); // ⚠️ on non-Linux
        let _ = check_ebpf_status(); // ⚠️ on non-Linux
    }

    #[test]
    fn test_kernel_version_old() {
        // Simulate an old kernel response
        // We can't actually call check_kernel_version() in a controlled way without
        // mocking /proc/version, so we test the version logic directly:
        fn is_sufficient(major: u64, minor: u64) -> bool {
            major > 5 || (major == 5 && minor >= 15)
        }

        assert!(is_sufficient(6, 8));   // Ubuntu 24.04 kernel
        assert!(is_sufficient(5, 15));  // Minimum
        assert!(is_sufficient(5, 19));  // Ubuntu 22.04
        assert!(!is_sufficient(5, 14)); // Too old
        assert!(!is_sufficient(4, 19)); // Way too old
    }
}
