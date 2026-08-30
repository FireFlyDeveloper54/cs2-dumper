pub(crate) mod address;
pub mod local;
pub mod shade;
pub(crate) mod snapshot;
pub mod syscall;

#[cfg(windows)]
pub(crate) mod win;

#[cfg(any(test, feature = "bench"))]
#[allow(dead_code)]
pub(crate) mod fake;
