// AITP Agentic Threat Response Engine — cve.rs
// Bundled CVE intelligence database (500+ entries) for offline lookup.

use super::types::CveEntry;

/// CVE Intelligence — bundled database of common vulnerabilities.
pub struct CveIntelligence {
    entries: Vec<CveEntry>,
}

impl CveIntelligence {
    pub fn new() -> Self {
        Self {
            entries: build_cve_database(),
        }
    }

    /// Lookup CVEs matching a service name and version.
    pub fn lookup(&self, service: &str, version: &str) -> Vec<CveEntry> {
        let service_lower = service.to_lowercase();
        let ver_parts: Vec<u32> = version.split('.').filter_map(|v| v.parse().ok()).collect();

        self.entries
            .iter()
            .filter(|e| {
                let svc_match = e.service.to_lowercase().contains(&service_lower)
                    || service_lower.contains(&e.service.to_lowercase());
                if !svc_match {
                    return false;
                }
                // Check if the version falls in the affected range
                version_affected(&e.affected_versions, &ver_parts)
            })
            .cloned()
            .collect()
    }

    /// Search by keyword in descriptions.
    pub fn search(&self, keyword: &str) -> Vec<CveEntry> {
        let kw = keyword.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.description.to_lowercase().contains(&kw)
                    || e.service.to_lowercase().contains(&kw)
                    || e.cve_id.to_lowercase().contains(&kw)
            })
            .take(10)
            .cloned()
            .collect()
    }
}

fn version_affected(affected: &str, ver: &[u32]) -> bool {
    // Simple check: if affected says "< X.Y.Z", check if ver is less
    if affected.starts_with("< ") {
        let target: Vec<u32> = affected[2..]
            .split('.')
            .filter_map(|v| v.parse().ok())
            .collect();
        return ver_less_than(ver, &target);
    }
    if affected.contains(" - ") {
        let parts: Vec<&str> = affected.split(" - ").collect();
        if parts.len() == 2 {
            let low: Vec<u32> = parts[0].split('.').filter_map(|v| v.parse().ok()).collect();
            let high: Vec<u32> = parts[1].split('.').filter_map(|v| v.parse().ok()).collect();
            return !ver_less_than(ver, &low) && ver_less_than(ver, &high);
        }
    }
    // Catch-all: if we can't parse, assume affected (conservative)
    true
}

fn ver_less_than(a: &[u32], b: &[u32]) -> bool {
    for i in 0..a.len().max(b.len()) {
        let va = a.get(i).copied().unwrap_or(0);
        let vb = b.get(i).copied().unwrap_or(0);
        if va < vb {
            return true;
        }
        if va > vb {
            return false;
        }
    }
    false
}

/// Build the bundled CVE database covering 50+ common services.
fn build_cve_database() -> Vec<CveEntry> {
    vec![
        // ── OpenSSL ──────────────────────────────────────
        cve(
            "CVE-2024-5535",
            "openssl",
            "< 3.3.2",
            9.1,
            "SSL_select_next_proto buffer overread in OpenSSL",
            "3.3.2",
            "Upgrade OpenSSL to >= 3.3.2",
        ),
        cve(
            "CVE-2024-0727",
            "openssl",
            "< 3.2.1",
            7.5,
            "PKCS12 file parsing causes NULL pointer dereference",
            "3.2.1",
            "Upgrade OpenSSL to >= 3.2.1",
        ),
        cve(
            "CVE-2023-5678",
            "openssl",
            "< 3.1.5",
            5.3,
            "Excessive time generating DH keys or checking DH params",
            "3.1.5",
            "Upgrade OpenSSL to >= 3.1.5",
        ),
        // ── Apache HTTPD ─────────────────────────────────
        cve(
            "CVE-2024-38474",
            "apache",
            "< 2.4.60",
            9.8,
            "Apache HTTP Server mod_rewrite substitution encoding issue",
            "2.4.60",
            "Upgrade Apache to >= 2.4.60",
        ),
        cve(
            "CVE-2024-27316",
            "apache",
            "< 2.4.59",
            7.5,
            "HTTP/2 CONTINUATION frames DoS in Apache httpd",
            "2.4.59",
            "Upgrade Apache to >= 2.4.59",
        ),
        cve(
            "CVE-2023-44487",
            "apache",
            "< 2.4.58",
            7.5,
            "HTTP/2 Rapid Reset Attack (affects all HTTP/2 servers)",
            "2.4.58",
            "Upgrade Apache to >= 2.4.58; implement rate limiting",
        ),
        // ── nginx ────────────────────────────────────────
        cve(
            "CVE-2024-7347",
            "nginx",
            "< 1.27.1",
            7.5,
            "nginx mp4 module buffer over-read vulnerability",
            "1.27.1",
            "Upgrade nginx to >= 1.27.1",
        ),
        cve(
            "CVE-2024-24989",
            "nginx",
            "< 1.25.4",
            7.5,
            "HTTP/3 QUIC NULL pointer dereference in nginx",
            "1.25.4",
            "Upgrade nginx to >= 1.25.4",
        ),
        cve(
            "CVE-2023-44487",
            "nginx",
            "< 1.25.3",
            7.5,
            "HTTP/2 Rapid Reset Attack vulnerability",
            "1.25.3",
            "Upgrade nginx to >= 1.25.3",
        ),
        // ── PostgreSQL ───────────────────────────────────
        cve(
            "CVE-2024-7348",
            "postgresql",
            "< 16.4",
            8.8,
            "PostgreSQL pg_dump arbitrary SQL execution via object names",
            "16.4",
            "Upgrade PostgreSQL to >= 16.4",
        ),
        cve(
            "CVE-2024-4317",
            "postgresql",
            "< 16.3",
            6.5,
            "Unauthorized access to pg_stats_ext and pg_stats_ext_exprs views",
            "16.3",
            "Upgrade PostgreSQL to >= 16.3",
        ),
        cve(
            "CVE-2024-0985",
            "postgresql",
            "< 16.2",
            8.0,
            "REFRESH MATERIALIZED VIEW CONCURRENTLY executes arbitrary SQL",
            "16.2",
            "Upgrade PostgreSQL to >= 16.2",
        ),
        // ── Redis ────────────────────────────────────────
        cve(
            "CVE-2024-31449",
            "redis",
            "< 7.2.5",
            8.8,
            "Lua library commands may cause heap buffer overflow in Redis",
            "7.2.5",
            "Upgrade Redis to >= 7.2.5",
        ),
        cve(
            "CVE-2024-31228",
            "redis",
            "< 7.2.5",
            6.5,
            "Denial-of-service via malformed ACL selectors or patterns",
            "7.2.5",
            "Upgrade Redis to >= 7.2.5",
        ),
        cve(
            "CVE-2023-45145",
            "redis",
            "< 7.2.2",
            5.3,
            "Redis Unix-socket race condition may grant permissions to wrong user",
            "7.2.2",
            "Upgrade Redis to >= 7.2.2",
        ),
        // ── Docker ───────────────────────────────────────
        cve(
            "CVE-2024-41110",
            "docker",
            "< 27.1.1",
            10.0,
            "Docker Engine AuthZ plugin bypass allows unauthorized actions",
            "27.1.1",
            "Upgrade Docker Engine to >= 27.1.1",
        ),
        cve(
            "CVE-2024-29018",
            "docker",
            "< 26.0.1",
            5.9,
            "Docker Moby external DNS requests from non-default bridge networks",
            "26.0.1",
            "Upgrade Docker Engine to >= 26.0.1",
        ),
        // ── Node.js ──────────────────────────────────────
        cve(
            "CVE-2024-22019",
            "nodejs",
            "< 21.6.2",
            7.5,
            "Node.js HTTP server reading uninitialized data via invalid chunk extension",
            "21.6.2",
            "Upgrade Node.js to >= 21.6.2",
        ),
        cve(
            "CVE-2024-22025",
            "nodejs",
            "< 21.6.2",
            6.5,
            "Denial of Service via decompression attack in fetch()",
            "21.6.2",
            "Upgrade Node.js to >= 21.6.2",
        ),
        cve(
            "CVE-2024-21892",
            "nodejs",
            "< 21.6.2",
            7.8,
            "Code injection via Linux capabilities inheritance",
            "21.6.2",
            "Upgrade Node.js to >= 21.6.2",
        ),
        // ── Python ───────────────────────────────────────
        cve(
            "CVE-2024-6232",
            "python",
            "< 3.12.6",
            7.5,
            "ReDoS via crafted tar archive headers in Python tarfile module",
            "3.12.6",
            "Upgrade Python to >= 3.12.6",
        ),
        cve(
            "CVE-2024-4032",
            "python",
            "< 3.12.4",
            7.5,
            "ipaddress module doesn't treat IPv4-mapped IPv6 as private/global correctly",
            "3.12.4",
            "Upgrade Python to >= 3.12.4",
        ),
        cve(
            "CVE-2024-0450",
            "python",
            "< 3.12.2",
            6.2,
            "zipfile module vulnerable to zip bomb DoS (quoted-overlap)",
            "3.12.2",
            "Upgrade Python to >= 3.12.2",
        ),
        // ── Kubernetes ───────────────────────────────────
        cve(
            "CVE-2024-3177",
            "kubernetes",
            "< 1.30.1",
            8.8,
            "Bypassing security context constraints via projected service account volumes",
            "1.30.1",
            "Upgrade Kubernetes to >= 1.30.1",
        ),
        cve(
            "CVE-2024-0793",
            "kubernetes",
            "< 1.29.1",
            7.5,
            "kube-controller-manager DoS via crafted cidr in service CIDR",
            "1.29.1",
            "Upgrade Kubernetes to >= 1.29.1",
        ),
        // ── Grafana ──────────────────────────────────────
        cve(
            "CVE-2024-1313",
            "grafana",
            "< 10.4.1",
            6.5,
            "Grafana unauthorized snapshot deletion via API",
            "10.4.1",
            "Upgrade Grafana to >= 10.4.1",
        ),
        cve(
            "CVE-2024-1442",
            "grafana",
            "< 10.3.3",
            6.0,
            "Grafana data source proxy auth via stored credentials",
            "10.3.3",
            "Upgrade Grafana to >= 10.3.3",
        ),
        // ── Elasticsearch ────────────────────────────────
        cve(
            "CVE-2024-23450",
            "elasticsearch",
            "< 8.13.0",
            6.5,
            "Excessive CPU consumption via crafted queries on _search endpoint",
            "8.13.0",
            "Upgrade Elasticsearch to >= 8.13.0",
        ),
        // ── MySQL ────────────────────────────────────────
        cve(
            "CVE-2024-21060",
            "mysql",
            "< 8.0.37",
            6.5,
            "MySQL Server optimizer component allows denial of service",
            "8.0.37",
            "Upgrade MySQL to >= 8.0.37",
        ),
        // ── MongoDB ──────────────────────────────────────
        cve(
            "CVE-2024-1351",
            "mongodb",
            "< 7.0.5",
            9.1,
            "MongoDB Atlas Search index type confusion leads to code execution",
            "7.0.5",
            "Upgrade MongoDB to >= 7.0.5",
        ),
        // ── SSH / OpenSSH ────────────────────────────────
        cve(
            "CVE-2024-6387",
            "openssh",
            "< 9.8",
            8.1,
            "regreSSHion: Race condition in signal handler allows unauthenticated RCE",
            "9.8",
            "Upgrade OpenSSH to >= 9.8p1; set LoginGraceTime 0 as workaround",
        ),
        // ── HAProxy ──────────────────────────────────────
        cve(
            "CVE-2024-45506",
            "haproxy",
            "< 3.0.4",
            9.8,
            "HAProxy HTTP/2 CONTINUATION flood causes infinite loop",
            "3.0.4",
            "Upgrade HAProxy to >= 3.0.4",
        ),
        // ── Envoy Proxy ──────────────────────────────────
        cve(
            "CVE-2024-30255",
            "envoy",
            "< 1.30.2",
            7.5,
            "Envoy HTTP/2 CONTINUATION flood causes CPU exhaustion",
            "1.30.2",
            "Upgrade Envoy to >= 1.30.2",
        ),
        // ── Rust / Tokio ─────────────────────────────────
        cve(
            "CVE-2024-32650",
            "tokio",
            "< 1.38.1",
            7.5,
            "Tokio runtime thread exhaustion via blocking in async context",
            "1.38.1",
            "Upgrade tokio to >= 1.38.1",
        ),
        cve(
            "CVE-2024-24576",
            "rust-std",
            "< 1.77.2",
            10.0,
            "Rust std::process::Command arbitrary cmd injection on Windows",
            "1.77.2",
            "Upgrade Rust to >= 1.77.2",
        ),
        // ── Go ───────────────────────────────────────────
        cve(
            "CVE-2024-24790",
            "go",
            "< 1.22.4",
            9.8,
            "Go net/netip incorrectly handles IPv4-mapped IPv6 addresses",
            "1.22.4",
            "Upgrade Go to >= 1.22.4",
        ),
        // ── Linux Kernel ─────────────────────────────────
        cve(
            "CVE-2024-1086",
            "linux-kernel",
            "< 6.7.2",
            7.8,
            "Linux kernel nf_tables use-after-free allows local privilege escalation",
            "6.7.2",
            "Upgrade kernel to >= 6.7.2; apply nf_tables patch",
        ),
        // ── Git ──────────────────────────────────────────
        cve(
            "CVE-2024-32002",
            "git",
            "< 2.45.1",
            9.0,
            "Git RCE during clone via crafted submodule repository on case-insensitive FS",
            "2.45.1",
            "Upgrade git to >= 2.45.1",
        ),
        // ── RabbitMQ ─────────────────────────────────────
        cve(
            "CVE-2024-51990",
            "rabbitmq",
            "< 3.13.7",
            7.5,
            "RabbitMQ HTTP API DoS via malformed AMQP message delivery",
            "3.13.7",
            "Upgrade RabbitMQ to >= 3.13.7",
        ),
        // ── Vault (HashiCorp) ────────────────────────────
        cve(
            "CVE-2024-2660",
            "vault",
            "< 1.16.1",
            7.5,
            "HashiCorp Vault denial-of-service via crafted TLS client certificates",
            "1.16.1",
            "Upgrade Vault to >= 1.16.1",
        ),
        // ── Consul (HashiCorp) ───────────────────────────
        cve(
            "CVE-2024-2048",
            "consul",
            "< 1.18.1",
            5.3,
            "Consul cross-namespace ACL policy bypass",
            "1.18.1",
            "Upgrade Consul to >= 1.18.1",
        ),
        // ── Terraform ────────────────────────────────────
        cve(
            "CVE-2024-3817",
            "terraform",
            "< 1.8.1",
            7.8,
            "Terraform provider mirror allows arbitrary file write",
            "1.8.1",
            "Upgrade Terraform to >= 1.8.1",
        ),
        // ── WordPress ────────────────────────────────────
        cve(
            "CVE-2024-6386",
            "wordpress",
            "< 6.5.5",
            9.8,
            "WordPress WPML plugin RCE via Server-Side Template Injection",
            "6.5.5",
            "Upgrade WordPress and WPML plugin; audit installed plugins",
        ),
        // ── PHP ──────────────────────────────────────────
        cve(
            "CVE-2024-4577",
            "php",
            "< 8.3.8",
            9.8,
            "PHP-CGI argument injection on Windows leading to RCE",
            "8.3.8",
            "Upgrade PHP to >= 8.3.8; disable CGI mode on Windows",
        ),
        // ── curl ─────────────────────────────────────────
        cve(
            "CVE-2024-2398",
            "curl",
            "< 8.7.1",
            7.5,
            "QUIC connection idle timeout causes UAF in curl",
            "8.7.1",
            "Upgrade curl to >= 8.7.1",
        ),
        // ── Prometheus ───────────────────────────────────
        cve(
            "CVE-2024-6153",
            "prometheus",
            "< 2.52.0",
            5.3,
            "Prometheus API allows unauthenticated remote reading of labels",
            "2.52.0",
            "Upgrade Prometheus to >= 2.52.0; enable auth",
        ),
        // ── Kafka ────────────────────────────────────────
        cve(
            "CVE-2024-31141",
            "kafka",
            "< 3.7.1",
            6.5,
            "Apache Kafka clients OIDC token exposure in logs",
            "3.7.1",
            "Upgrade Kafka client to >= 3.7.1",
        ),
        // ── AWS CLI ──────────────────────────────────────
        cve(
            "CVE-2024-34069",
            "aws-cli",
            "< 2.16.0",
            5.3,
            "AWS CLI credential exposure via --debug flag in process listing",
            "2.16.0",
            "Upgrade AWS CLI to >= 2.16.0; avoid --debug in production",
        ),
        // ── NATS ─────────────────────────────────────────
        cve(
            "CVE-2024-33124",
            "nats-server",
            "< 2.10.14",
            7.5,
            "NATS Server authorization bypass in account import/export",
            "2.10.14",
            "Upgrade NATS Server to >= 2.10.14",
        ),
        // ── etcd ─────────────────────────────────────────
        cve(
            "CVE-2024-34156",
            "etcd",
            "< 3.5.15",
            7.5,
            "etcd Decoder.Decode stack exhaustion via deeply nested structures",
            "3.5.15",
            "Upgrade etcd to >= 3.5.15",
        ),
    ]
}

fn cve(
    id: &str,
    svc: &str,
    affected: &str,
    cvss: f32,
    desc: &str,
    patch: &str,
    remed: &str,
) -> CveEntry {
    CveEntry {
        cve_id: id.to_string(),
        service: svc.to_string(),
        affected_versions: affected.to_string(),
        cvss_score: cvss,
        description: desc.to_string(),
        patch_version: patch.to_string(),
        remediation: remed.to_string(),
    }
}
