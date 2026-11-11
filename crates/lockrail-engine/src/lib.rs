//! Lockrail detection engine (PLAN.md section 3.2, Phase 3).
//!
//! Extracted from `lockrail-protocol::seal` with no behaviour change (Phase 3A);
//! `lockrail_protocol::seal` re-exports [`seal`] so existing callers are unchanged.
//! - [`seal`]: secret detectors, sealing, the allowlist.
//! - [`phi`]: PHI detectors and span withholding.
//! - [`handle`]: keyed handles and handle parsing.

pub mod handle;
pub mod phi;
pub mod seal;
