// AITP Agentic Threat Response Engine — mitre.rs
// MITRE ATT&CK framework mapping from behavioral patterns.

use super::types::MitreTtp;

/// Map behavioral descriptions to MITRE ATT&CK TTPs.
pub fn map_behaviors(behavior: &str) -> Vec<MitreTtp> {
    let b = behavior.to_lowercase();
    let mut ttps = Vec::new();

    // ── Initial Access ──
    if b.contains("credential") || b.contains("valid account") || b.contains("anomalous ip") {
        ttps.push(ttp(
            "T1078",
            "Initial Access",
            "Valid Accounts",
            "Use of valid credentials from an anomalous location or time",
        ));
    }
    if b.contains("exploit") || b.contains("cve") || b.contains("vulnerability") {
        ttps.push(ttp(
            "T1190",
            "Initial Access",
            "Exploit Public-Facing Application",
            "Exploitation of a known vulnerability in a public-facing service",
        ));
    }

    // ── Execution ──
    if b.contains("control signal") || b.contains("command") || b.contains("scripting") {
        ttps.push(ttp(
            "T1059",
            "Execution",
            "Command and Scripting Interpreter",
            "Execution of commands through scripting or control signal injection",
        ));
    }

    // ── Persistence ──
    if b.contains("new entity") || b.contains("rogue") || b.contains("unauthorized device") {
        ttps.push(ttp(
            "T1136",
            "Persistence",
            "Create Account",
            "Creation of rogue entity or unauthorized account for persistence",
        ));
    }

    // ── Privilege Escalation ──
    if b.contains("intent deviation") || b.contains("privilege") || b.contains("escalat") {
        ttps.push(ttp(
            "T1068",
            "Privilege Escalation",
            "Exploitation for Privilege Escalation",
            "Intent deviation suggesting attempted privilege escalation",
        ));
    }
    if b.contains("clearance") || b.contains("permission") {
        ttps.push(ttp(
            "T1548",
            "Privilege Escalation",
            "Abuse Elevation Control Mechanism",
            "Attempt to bypass clearance level restrictions",
        ));
    }

    // ── Defense Evasion ──
    if b.contains("trust score drop") || b.contains("evasion") || b.contains("bypass") {
        ttps.push(ttp(
            "T1562",
            "Defense Evasion",
            "Impair Defenses",
            "Behavioral anomaly indicates attempt to evade trust evaluation",
        ));
    }

    // ── Discovery ──
    if b.contains("new peer")
        || b.contains("scanning")
        || b.contains("probe")
        || b.contains("network scan")
    {
        ttps.push(ttp(
            "T1046",
            "Discovery",
            "Network Service Discovery",
            "Scanning for new peers or network services outside normal baseline",
        ));
    }
    if b.contains("topology") || b.contains("enumerate") {
        ttps.push(ttp(
            "T1018",
            "Discovery",
            "Remote System Discovery",
            "Attempting to map network topology and enumerate remote systems",
        ));
    }

    // ── Lateral Movement ──
    if b.contains("lateral") || b.contains("pivot") || b.contains("hop") || b.contains("spread") {
        ttps.push(ttp(
            "T1021",
            "Lateral Movement",
            "Remote Services",
            "Movement between entities via remote service connections",
        ));
        ttps.push(ttp(
            "T1210",
            "Lateral Movement",
            "Exploitation of Remote Services",
            "Exploiting remote services to move laterally across the network",
        ));
    }

    // ── Collection ──
    if b.contains("data collection") || b.contains("harvest") || b.contains("staging") {
        ttps.push(ttp(
            "T1560",
            "Collection",
            "Archive Collected Data",
            "Staging or archiving data before exfiltration",
        ));
    }

    // ── Exfiltration ──
    if b.contains("exfiltration")
        || b.contains("data transfer")
        || b.contains("unusual bytes")
        || b.contains("large outbound")
    {
        ttps.push(ttp(
            "T1048",
            "Exfiltration",
            "Exfiltration Over Alternative Protocol",
            "Data exfiltration detected via unusual transfer patterns or protocols",
        ));
        ttps.push(ttp(
            "T1041",
            "Exfiltration",
            "Exfiltration Over C2 Channel",
            "Using the command-and-control channel for data exfiltration",
        ));
    }

    // ── Command and Control ──
    if b.contains("c2")
        || b.contains("beaconing")
        || b.contains("callback")
        || b.contains("control signal spike")
    {
        ttps.push(ttp(
            "T1071",
            "Command and Control",
            "Application Layer Protocol",
            "Command and control communication via application layer protocols",
        ));
        ttps.push(ttp(
            "T1573",
            "Command and Control",
            "Encrypted Channel",
            "Using encrypted channels for C2 communication to evade detection",
        ));
    }

    // ── Impact ──
    if b.contains("ransomware")
        || b.contains("encrypt")
        || b.contains("destroy")
        || b.contains("wipe")
    {
        ttps.push(ttp(
            "T1486",
            "Impact",
            "Data Encrypted for Impact",
            "Destructive action: data encryption for ransomware or denial",
        ));
    }
    if b.contains("flood")
        || b.contains("ddos")
        || b.contains("denial of service")
        || b.contains("frequency spike")
    {
        ttps.push(ttp(
            "T1499",
            "Impact",
            "Endpoint Denial of Service",
            "Denial of service attack via resource exhaustion or flooding",
        ));
    }

    if ttps.is_empty() {
        ttps.push(ttp("T1195", "Initial Access", "Supply Chain Compromise",
            "Behavioral pattern does not match known TTPs — possible supply chain compromise or novel technique"));
    }

    ttps
}

fn ttp(id: &str, tactic: &str, technique: &str, desc: &str) -> MitreTtp {
    MitreTtp {
        id: id.to_string(),
        tactic: tactic.to_string(),
        technique: technique.to_string(),
        description: desc.to_string(),
    }
}
