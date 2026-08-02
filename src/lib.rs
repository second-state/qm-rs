//! qm-rs — a multiplayer agent harness for work.
//!
//! A Rust port of [QM](https://github.com/yc-software/qm)'s headless core onto
//! local SQLite: axum + Tera server-rendered UI, rusqlite behind an r2d2 pool,
//! and compile-time embedded versioned migrations.
//!
//! # Shape
//!
//! Every turn runs through [`orchestrator`], which resolves the scope
//! ([`resolution`]) into workspace layers, a system prompt, and the security
//! and command policies ([`policy`]), then drives a [`harness`] over a fixed
//! [`tools`] surface. One of those tools is `execute`, which runs commands in
//! the scope's own [`sandbox`] — its durable computer.
//!
//! Persistence lives in [`store`]. The substrates that a deployment might
//! reasonably swap — the harness, the sandbox, the plugin host — sit behind
//! traits, so a different implementation wires in without touching call sites.
//!
//! Surfaces ([`web`], [`connectors`]) never reach past the orchestrator, which
//! is what keeps one identity and one policy across all of them.

pub mod auth;
pub mod config;
pub mod connectors;
pub mod cron;
pub mod db;
pub mod error;
pub mod harness;
pub mod memory;
pub mod onboarding;
pub mod orchestrator;
pub mod plugin;
pub mod policy;
pub mod resolution;
pub mod sandbox;
pub mod skills;
pub mod store;
pub mod tools;
pub mod types;
pub mod web;
