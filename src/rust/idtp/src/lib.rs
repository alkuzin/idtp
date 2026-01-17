// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Inertial Measurement Unit Data Transfer Protocol (IDTP) - network protocol
//! used for transferring IMU data. This protocol is suitable for usage in areas
//! of robotics, unmanned vehicles, wearable devices etc.
//!
//! This crate was designed for use on `embedded systems`.

#![no_std]
// Ignore #[must_use] suggestions from clippy.
#![allow(clippy::must_use_candidate)]

#[cfg(feature = "software_impl")]
pub mod crypto;
mod header;
mod frame;

pub use header::*;
pub use frame::*;

/// Protocol errors enumeration.
#[derive(Debug)]
pub enum IdtpError {
    /// Buffer too short.
    BufferUnderflow,
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
