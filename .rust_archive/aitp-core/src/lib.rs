//! AITP Core — Transport protocol engine
//!
//! This crate implements the core AITP transport protocol:
//! - Packet header definition and serialization
//! - Handshake state machine
//! - Session lifecycle management
//! - UDP transport loop
//! - Packet framing

pub mod config;
pub mod events;
pub mod framing;
pub mod handshake;
pub mod header;
pub mod intent_fingerprint;
pub mod server;
pub mod session;
pub mod session_dna;
pub mod transport;

