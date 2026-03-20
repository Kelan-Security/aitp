// Kelan Security Client Agent — install.rs
// System service install helpers: systemd (Linux), launchd (macOS).

pub fn install_service() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    install_systemd()?;

    #[cfg(target_os = "macos")]
    install_launchd()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        println!("Service installation not supported on this platform.");
        println!("Run manually: kelan-agent start");
    }

    Ok(())
}

pub fn uninstall_service() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    uninstall_systemd()?;

    #[cfg(target_os = "macos")]
    uninstall_launchd()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    println!("Service uninstallation not supported on this platform.");

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd() -> anyhow::Result<()> {
    let binary = std::env::current_exe()?;
    let unit = format!(
        r#"[Unit]
Description=Kelan Security Client Agent
Documentation=https://docs.kelansecurtity.io/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} --config /etc/kelan/kelan-agent.toml start
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
User=root
PIDFile=/var/run/kelan-agent.pid

# Allow iptables manipulation
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"#,
        bin = binary.display()
    );

    std::fs::write("/etc/systemd/system/kelan-agent.service", unit)?;
    std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status()?;
    std::process::Command::new("systemctl")
        .args(["enable", "kelan-agent"])
        .status()?;

    println!("systemd service installed and enabled");
    println!("Start: sudo systemctl start kelan-agent");
    println!("Logs:  sudo journalctl -u kelan-agent -f");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> anyhow::Result<()> {
    let _ = std::process::Command::new("systemctl")
        .args(["stop", "kelan-agent"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["disable", "kelan-agent"])
        .status();
    let _ = std::fs::remove_file("/etc/systemd/system/kelan-agent.service");
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    println!("systemd service removed");
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd() -> anyhow::Result<()> {
    let binary = std::env::current_exe()?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>io.kelan.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>--config</string>
    <string>/etc/kelan/kelan-agent.toml</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>/var/log/kelan/agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/kelan/agent-err.log</string>
</dict>
</plist>
"#,
        bin = binary.display()
    );

    std::fs::create_dir_all("/var/log/kelan")?;
    std::fs::write(
        "/Library/LaunchDaemons/io.kelan.agent.plist",
        plist,
    )?;
    std::process::Command::new("launchctl")
        .args(["load", "/Library/LaunchDaemons/io.kelan.agent.plist"])
        .status()?;
    println!("launchd daemon installed");
    println!("Logs: /var/log/kelan/agent.log");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> anyhow::Result<()> {
    let _ = std::process::Command::new("launchctl")
        .args(["unload", "/Library/LaunchDaemons/io.kelan.agent.plist"])
        .status();
    let _ = std::fs::remove_file("/Library/LaunchDaemons/io.kelan.agent.plist");
    println!("launchd daemon removed");
    Ok(())
}
