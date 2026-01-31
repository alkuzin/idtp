// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Inertial Measurement Unit Data Transfer Protocol (IDTP) - binary protocol
//! used for transferring IMU data. This protocol is suitable for usage in areas
//! of robotics, unmanned vehicles, wearable devices etc.
//!
//! This crate was designed for use on `embedded systems`.

#![no_std]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::todo,
    clippy::unreachable,
    missing_docs
)]

#[cfg(feature = "software_impl")]
pub mod crypto;
pub mod payload;

#[macro_use]
pub mod macros;

mod frame;
mod header;

pub use frame::*;
pub use header::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Protocol errors enumeration.
#[derive(Debug)]
pub enum IdtpError {
    /// Buffer too short.
    BufferUnderflow,
    /// Buffer too large.
    BufferOverflow,
    /// Incorrect CRC value.
    InvalidCrc,
    /// Incorrect HMAC value.
    InvalidHMac,
    /// Incorrect HMAC key.
    InvalidHMacKey,
    /// Error to convert from/to bytes.
    ParseError,
}

/// Result alias for IDTP.
pub type IdtpResult<T> = Result<T, IdtpError>;

/// Trait for serializable & deserializable data.
pub trait IdtpData: IntoBytes + FromBytes + Immutable + KnownLayout {}

/// Every type that has these traits also has `IdtpData`.
impl<T: IntoBytes + FromBytes + Immutable + KnownLayout> IdtpData for T {}
