//! CS2 offset / schema / SDK dumper library.
//!
//! The CLI in `main.rs` is a thin attach + I/O wrapper around these modules.
//! Benches and tests drive the same analysis and pattern code the exe uses.

pub mod analysis;
pub mod dump;
pub mod loadlib;
pub mod memory;
pub mod output;
pub mod patterns;
pub(crate) mod source2;
pub mod ui;
