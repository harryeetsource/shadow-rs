//! # shadowx: Kernel-Level Utilities Library
//!
//! **shadowx** is a `#![no_std]` library designed for low-level kernel operations,
//! including process management, thread handling, injection mechanisms, driver interactions,
//! registry manipulation, and more.

#![no_std]
#![allow(unused_must_use)]
#![allow(unused_variables)]
#![allow(static_mut_refs)]
#![allow(non_snake_case)]

extern crate alloc;

/// Process management and utilities.
mod process;
pub use process::*;

/// Thread management and utilities.
mod thread;
pub use thread::*;

/// Code/DLL injection mechanisms.
mod injection;
pub use injection::*;

/// Kernel module handling and driver utilities.
mod module;
pub use module::*;

/// Driver-related functionality.
mod driver;
pub use driver::*;

/// Miscellaneous kernel utilities.
mod misc;
pub use misc::*;

/// General-purpose utilities.
mod utils;
pub use utils::*;

/// Data structures used throughout the library.
mod data;
pub use data::*;

/// Port communication utilities.
pub mod network;
pub use network::*;

/// Error handling utilities.
pub mod error;

/// Registry manipulation utilities.
pub mod registry;
pub use registry::*;

/// Kernel callback management.
pub mod callback;
pub use callback::*;

mod offsets;

pub(crate) type Result<T> = core::result::Result<T, error::ShadowError>;
