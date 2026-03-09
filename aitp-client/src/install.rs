// AITP Client Agent — install.rs
// systemd (Linux) and launchd (macOS) service installation helpers.

use anyhow::Result;
use std::path::PathBuf;

pub fn install_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    return install_systemd();

    #[cfg(target_os = "macos")]
    return install_launchd();

    #[cfg(target_os = "windows")]
    return install_windows_service();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("Service installation not supported on this platform");
}

pub fn uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    return uninstall_systemd();

    #[cfg(target_os = "macos")]
    return uninstall_launchd();

    #[cfg(target_os = "windows")]
    return uninstall_windows_service();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("Service uninstallation not supported on this platform");
}

// ─── Linux (systemd) ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_systemd() -> Result<()> {
    let exe = std::env::current_exe()?;
    let unit_path = PathBuf::from("/etc/systemd/system/aitp-client.service");

    let unit = format!(
        r#"[Unit]
Description=AITP Client Agent — Identity-First Connection Guard
Documentation=https://github.com/aitp-protocol/aitp
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} start
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aitp-client
# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"#,
        exe = exe.display()
    );

    std::fs::write(&unit_path, unit)?;
    println!("✓ Installed: {}", unit_path.display());

    // Enable and start
    for cmd in &[
        "systemctl daemon-reload",
        "systemctl enable aitp-client",
        "systemctl start aitp-client",
    ] {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let status = std::process::Command::new(parts[0])
            .args(&parts[1..])
            .status()?;
        if !status.success() {
            anyhow::bail!("Command failed: {}", cmd);
        }
    }

    println!("✓ AITP Client service enabled and started");
    println!("  Check status: systemctl status aitp-client");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> Result<()> {
    for cmd in &[
        "systemctl stop aitp-client",
        "systemctl disable aitp-client",
    ] {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let _ = std::process::Command::new(parts[0])
            .args(&parts[1..])
            .status();
    }
    let unit_path = PathBuf::from("/etc/systemd/system/aitp-client.service");
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)?;
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status();
    }
    println!("✓ AITP Client service removed");
    Ok(())
}

// ─── macOS (launchd) ─────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_launchd() -> Result<()> {
    let exe = std::env::current_exe()?;
    let plist_path = PathBuf::from("/Library/LaunchDaemons/dev.aitp.client.plist");
    let log_path = PathBuf::from("/var/log/aitp-client.log");

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.aitp.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        exe = exe.display(),
        log = log_path.display()
    );

    std::fs::write(&plist_path, plist)?;
    println!("✓ Installed: {}", plist_path.display());

    let status = std::process::Command::new("launchctl")
        .args(["load", "-w", plist_path.to_str().unwrap()])
        .status()?;

    if !status.success() {
        anyhow::bail!("launchctl load failed");
    }

    println!("✓ AITP Client launchd service loaded");
    println!("  Check status: launchctl list | grep aitp");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> Result<()> {
    let plist_path = PathBuf::from("/Library/LaunchDaemons/dev.aitp.client.plist");
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap()])
            .status();
        std::fs::remove_file(&plist_path)?;
    }
    println!("✓ AITP Client launchd service removed");
    Ok(())
}

// ─── Windows ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_windows_service() -> Result<()> {
    let exe = std::env::current_exe()?;
    let status = std::process::Command::new("sc")
        .args([
            "create",
            "AitpClient",
            "binpath=",
            &format!("\"{}\" start", exe.display()),
            "DisplayName=",
            "AITP Client Agent",
            "start=",
            "auto",
            "description=",
            "AITP identity-first connection guard",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("sc create failed — run as Administrator");
    }
    let _ = std::process::Command::new("sc")
        .args(["start", "AitpClient"])
        .status();
    println!("✓ AITP Client Windows service installed and started");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows_service() -> Result<()> {
    let _ = std::process::Command::new("sc")
        .args(["stop", "AitpClient"])
        .status();
    std::process::Command::new("sc")
        .args(["delete", "AitpClient"])
        .status()?;
    println!("✓ AITP Client Windows service removed");
    Ok(())
}
