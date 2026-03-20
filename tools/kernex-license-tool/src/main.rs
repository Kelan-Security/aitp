//! Kernex License Issuing Tool
//! Run this on YOUR machine to issue signed license files for customers.
//! The private key NEVER leaves your machine.
//!
//! Usage:
//!   kernex-license-tool keygen                    # one-time setup
//!   kernex-license-tool issue --org "Acme Corp"   # issue a license
//!   kernex-license-tool verify license.json        # verify a license file
//!   kernex-license-tool info license.json          # show license details

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize, clap::ValueEnum, PartialEq)]
#[serde(rename_all = "PascalCase")]
enum LicenseTier {
    Community,
    Startup,
    Enterprise,
    Defense,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseFile {
    version:    u8,
    org_name:   String,
    org_email:  String,
    license_id: String,
    tier:       LicenseTier,
    max_nodes:  u32,
    features:   Vec<String>,
    issued_at:  i64,
    expires_at: i64,
    signature:  String,
}

impl LicenseFile {
    fn signing_payload(&self) -> Vec<u8> {
        let payload = serde_json::json!({
            "version":    self.version,
            "org_name":   self.org_name,
            "org_email":  self.org_email,
            "license_id": self.license_id,
            "tier":       self.tier,
            "max_nodes":  self.max_nodes,
            "features":   self.features,
            "issued_at":  self.issued_at,
            "expires_at": self.expires_at,
        });
        serde_json::to_vec(&payload).unwrap()
    }
}

#[derive(Parser)]
#[command(name = "kernex-license-tool")]
#[command(about = "Issue signed Kernex license files [INTERNAL USE ONLY]")]
struct Cli {
    /// Path to private key PEM file
    #[arg(short, long, default_value = "~/.kernex_license_private.pem")]
    key: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair (run once)
    Keygen {
        /// Output path for private key
        #[arg(long, default_value = "~/.kernex_license_private.pem")]
        private_key: String,
        /// Output path for public key
        #[arg(long, default_value = "~/.kernex_license_public.pem")]
        public_key: String,
    },

    /// Issue a new signed license file
    Issue {
        /// Customer organisation name
        #[arg(long)]
        org: String,

        /// Customer contact email
        #[arg(long)]
        email: String,

        /// License tier
        #[arg(long, value_enum, default_value_t = LicenseTier::Startup)]
        tier: LicenseTier,

        /// Max nodes (0 = use tier default)
        #[arg(long, default_value = "0")]
        max_nodes: u32,

        /// Expiry in days from today (0 = never expires)
        #[arg(long, default_value = "365")]
        expires_days: u64,

        /// Extra features (comma-separated)
        #[arg(long, default_value = "")]
        features: String,

        /// Output file path
        #[arg(short, long, default_value = "kernex.license")]
        output: String,
    },

    /// Verify a license file without running the server
    Verify {
        /// License file path
        file: String,
    },

    /// Show details of a license file
    Info {
        /// License file path
        file: String,
    },

    /// Show the public key hex to embed in the server binary
    Pubkey,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let key_path = shellexpand::tilde(&cli.key).to_string();

    match cli.command {
        Commands::Keygen { private_key, public_key } => {
            let private_path = shellexpand::tilde(&private_key).to_string();
            let public_path  = shellexpand::tilde(&public_key).to_string();

            if std::path::Path::new(&private_path).exists() {
                eprintln!("Private key already exists at {}. Delete it first if you want to regenerate.", private_path);
                std::process::exit(1);
            }

            let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
            let verifying_key = signing_key.verifying_key();

            // Save private key as PEM
            use ed25519_dalek::pkcs8::EncodePrivateKey;
            signing_key.write_pkcs8_pem_file(&private_path, Default::default())?;

            // Save public key hex to a simple file
            let pubkey_hex = hex::encode(verifying_key.to_bytes());
            std::fs::write(&public_path, &pubkey_hex)?;

            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║               KEYPAIR GENERATED                          ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("  Private key: {}", private_path);
            println!("  Public key:  {}", public_path);
            println!("");
            println!("  PUBLIC KEY HEX (paste into src/license.rs):");
            println!("  {}", pubkey_hex);
            println!("");
            println!("  ⚠ BACK UP {} IMMEDIATELY", private_path);
            println!("  ⚠ NEVER commit it to git");
            println!("  ⚠ If lost, you cannot issue new licenses");
            println!("╚══════════════════════════════════════════════════════════╝");
        }

        Commands::Issue { org, email, tier, max_nodes, expires_days, features, output } => {
            // Load private key
            let signing_key = load_private_key(&key_path)?;

            let now        = Utc::now().timestamp();
            let expires_at = if expires_days == 0 { 0 }
                else { now + (expires_days as i64 * 86400) };

            let feature_list: Vec<String> = features
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let tier_max_nodes = match tier {
                LicenseTier::Community  => 5,
                LicenseTier::Startup    => 50,
                LicenseTier::Enterprise => 0, // 0 = unlimited
                LicenseTier::Defense    => 0,
            };

            let effective_max_nodes = if max_nodes > 0 { max_nodes } else { tier_max_nodes };

            let mut license = LicenseFile {
                version:    1,
                org_name:   org.clone(),
                org_email:  email.clone(),
                license_id: Uuid::new_v4().to_string(),
                tier:       tier.clone(),
                max_nodes:  effective_max_nodes,
                features:   feature_list,
                issued_at:  now,
                expires_at,
                signature:  String::new(), // filled in below
            };

            // Sign the payload
            let payload = license.signing_payload();
            let signature = signing_key.sign(&payload);
            license.signature = hex::encode(signature.to_bytes());

            // Write license file
            let json = serde_json::to_string_pretty(&license)?;
            std::fs::write(&output, &json)?;

            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║                LICENSE ISSUED                            ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("  Organisation: {}", org);
            println!("  Email:        {}", email);
            println!("  Tier:         {:?}", tier);
            println!("  Max nodes:    {}", if effective_max_nodes == 0 { "Unlimited".to_string() }
                     else { effective_max_nodes.to_string() });
            println!("  Expires:      {}", if expires_days == 0 { "Never".to_string() }
                     else { format!("{} days", expires_days) });
            println!("  License ID:   {}", license.license_id);
            println!("  Output file:  {}", output);
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("  SEND TO CUSTOMER:");
            println!("  scp {} customer@their-server:/etc/kernex/kernex.license", output);
            println!("╚══════════════════════════════════════════════════════════╝");
        }

        Commands::Verify { file } => {
            let content  = std::fs::read_to_string(&file)?;
            let license: LicenseFile = serde_json::from_str(&content)?;

            // Load public key for verification
            let public_key_path = shellexpand::tilde("~/.kernex_license_public.pem").to_string();
            let pubkey_hex = std::fs::read_to_string(&public_key_path)
                .unwrap_or_else(|_| {
                    // Fall back to reading from private key
                    let signing_key = load_private_key(&key_path).unwrap();
                    hex::encode(signing_key.verifying_key().to_bytes())
                });

            let pubkey_bytes = hex::decode(pubkey_hex.trim())?;
            let pubkey_arr: [u8; 32] = pubkey_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
            let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)?;

            let payload   = license.signing_payload();
            let sig_bytes = hex::decode(&license.signature)?;
            let sig_arr: [u8; 64] = sig_bytes.try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

            use ed25519_dalek::Signature;
            let signature = Signature::from_bytes(&sig_arr);

            use ed25519_dalek::Verifier;
            match verifying_key.verify(&payload, &signature) {
                Ok(_)  => {
                    println!("✓ Signature VALID");
                    println!("✓ License is authentic and unmodified");
                }
                Err(_) => {
                    println!("✗ Signature INVALID");
                    println!("✗ License file has been tampered with or is corrupt");
                    std::process::exit(1);
                }
            }
        }

        Commands::Info { file } => {
            let content  = std::fs::read_to_string(&file)?;
            let license: LicenseFile = serde_json::from_str(&content)?;

            let now = Utc::now().timestamp();
            let expired = license.expires_at > 0 && license.expires_at < now;
            let days_remaining = if license.expires_at == 0 { None }
                else { Some((license.expires_at - now) / 86400) };

            println!("Organisation: {}", license.org_name);
            println!("Email:        {}", license.org_email);
            println!("License ID:   {}", license.license_id);
            println!("Tier:         {:?}", license.tier);
            println!("Max nodes:    {}", if license.max_nodes == 0 { "Unlimited".to_string() }
                     else { license.max_nodes.to_string() });
            println!("Issued:       {}", chrono::DateTime::from_timestamp(license.issued_at, 0)
                     .map(|d| d.format("%Y-%m-%d").to_string())
                     .unwrap_or_default());
            println!("Expires:      {}", match days_remaining {
                None      => "Never".to_string(),
                Some(d) if expired => format!("EXPIRED {} days ago", -d),
                Some(d)   => format!("{} days from now", d),
            });
            if !license.features.is_empty() {
                println!("Features:     {}", license.features.join(", "));
            }
        }

        Commands::Pubkey => {
            let signing_key = load_private_key(&key_path)?;
            let pubkey_hex  = hex::encode(signing_key.verifying_key().to_bytes());
            println!("Public key hex (paste into src/license.rs):");
            println!("{}", pubkey_hex);
        }
    }

    Ok(())
}

fn load_private_key(path: &str) -> anyhow::Result<SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    SigningKey::read_pkcs8_pem_file(path)
        .map_err(|e| anyhow::anyhow!(
            "Cannot load private key from {}: {}\n\
             Run: kernex-license-tool keygen", path, e
        ))
}
