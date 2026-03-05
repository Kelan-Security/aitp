//! AITP Observability — Metrics and structured tracing
//!
//! This crate provides:
//! - Prometheus metrics exporter for AITP protocol events
//! - Structured JSON logging via the `tracing` ecosystem

pub mod metrics;
pub mod tracing_setup;
