//! AITP AI Engine — Trust scoring engine
//!
//! This crate implements the AI-driven trust evaluation system:
//! - Three-mode pipeline: rules-only, Gemini-only, or hybrid (default)
//! - Weighted rule-based scoring (sub-0.5ms)
//! - Gemini 2.0 Flash API integration for AI-driven trust decisions
//! - Hybrid mode: rules + Gemini in parallel, merged by weighted average
//! - Response caching, rate limiting, and fallback on timeout
//! - Session outcome feedback loop for adaptive learning

pub mod engine;
pub mod gemini_client;
pub mod policy;
pub mod scorer;
pub mod telemetry;
