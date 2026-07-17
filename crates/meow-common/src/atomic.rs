//! Platform-adaptive atomic type aliases.
//!
//! On 64-bit targets these are the native `AtomicU64`/`AtomicI64`.
//! On 32-bit targets (e.g. MIPS32, armv7) they fall back to the
//! widest atomics the platform supports (`AtomicU32`/`AtomicI32`).

#[cfg(target_pointer_width = "64")]
pub type AtomicU = std::sync::atomic::AtomicU64;
#[cfg(target_pointer_width = "32")]
pub type AtomicU = std::sync::atomic::AtomicU32;

#[cfg(target_pointer_width = "64")]
pub type AtomicI = std::sync::atomic::AtomicI64;
#[cfg(target_pointer_width = "32")]
pub type AtomicI = std::sync::atomic::AtomicI32;

#[cfg(target_pointer_width = "64")]
pub type Uint = u64;
#[cfg(target_pointer_width = "32")]
pub type Uint = u32;

#[cfg(target_pointer_width = "64")]
pub type Int = i64;
#[cfg(target_pointer_width = "32")]
pub type Int = i32;
