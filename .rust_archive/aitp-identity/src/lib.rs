//! AITP Identity — Identity and addressing system
//!
//! This crate provides:
//! - Ed25519 keypair generation and entity ID derivation
//! - Permit token generation and validation
//! - Identity-to-IP resolution

pub mod identity;
pub mod resolver;
pub mod token;
pub mod verification;
