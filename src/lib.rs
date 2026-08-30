//! CS2 offset / schema / SDK dumper library.
//!
//! The CLI in `main.rs` is a thin attach + I/O wrapper around these modules.
//! Benches and tests drive the same analysis and pattern code the exe uses.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(windows))]
compile_error!("cs2-dumper supports Windows only");
#[cfg(all(windows, not(target_arch = "x86_64")))]
compile_error!("cs2-dumper requires the x86_64 Windows target");

pub mod analysis;
pub mod dump;
pub mod loadlib;
pub mod memory;
pub mod output;
pub mod patterns;
pub(crate) mod source2;
pub mod ui;
