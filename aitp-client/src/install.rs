// Kernex Client Agent — install.rs
// System service install helpers: systemd (Linux), launchd (macOS).

pub fn install_service() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    install_systemd()?;

    #[cfg(target_os = "macos")]
    install_launchd()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        println!("Service installation not supported on this platform.");
        println!("Run manually: kernex-agent start");
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
Description=Kernex Client Agent
Documentation=https://docs.kernex.io/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} --config /etc/kernex/kernex-agent.toml start
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
User=root
PIDFile=/var/run/kernex-agent.pid

# Allow iptables manipulation
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"#,
        bin = binary.display()
    );

    std::fs::write("/etc/systemd/system/kernex-agent.service", unit)?;
    std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status()?;
    std::process::Command::new("systemctl")
        .args(["enable", "kernex-agent"])
        .status()?;

    println!("systemd service installed and enabled");
    println!("Start: sudo systemctl start kernex-agent");
    println!("Logs:  sudo journalctl -u kernex-agent -f");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> anyhow::Result<()> {
    let _ = std::process::Command::new("systemctl")
        .args(["stop", "kernex-agent"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["disable", "kernex-agent"])
        .status();
    let _ = std::fs::remove_file("/etc/systemd/system/kernex-agent.service");
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
  <key>Label</key>            <string>io.kernex.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>--config</string>
    <string>/etc/kernex/kernex-agent.toml</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>/var/log/kernex/agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/kernex/agent-err.log</string>
</dict>
</plist>
"#,
        bin = binary.display()
    );

    std::fs::create_dir_all("/var/log/kernex")?;
    std::fs::write(
        "/Library/LaunchDaemons/io.kernex.agent.plist",
        plist,
    )?;
    std::process::Command::new("launchctl")
        .args(["load", "/Library/LaunchDaemons/io.kernex.agent.plist"])
        .status()?;
    println!("launchd daemon installed");
    println!("Logs: /var/log/kernex/agent.log");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> anyhow::Result<()> {
    let _ = std::process::Command::new("launchctl")
        .args(["unload", "/Library/LaunchDaemons/io.kernex.agent.plist"])
        .status();
    let _ = std::fs::remove_file("/Library/LaunchDaemons/io.kernex.agent.plist");
    println!("launchd daemon removed");
    Ok(())
}
