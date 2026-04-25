//! Bedrock Echo witness library — Linux profile.
//!
//! The binary in `main.rs` is a thin UDP loop on top of these modules.
//! This `lib.rs` exposes them so integration tests and other crates can
//! drive the state machine without sockets.

pub mod handler;
pub mod state;

pub use handler::{handle, Reply};
pub use state::State;
