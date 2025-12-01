// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Inertial Measurement Unit Data Transfer Protocol (IDTP) - network protocol
//! used for transferring IMU data. This protocol is suitable for usage in areas
//! of robotics, unmanned vehicles, wearable devices and etc.
//!
//! This crate was designed for use on `embedded systems`.

#![no_std]
// Ignore #[must_use] suggestions from clippy.
#![allow(clippy::must_use_candidate)]

mod header;
mod idtp;
pub use header::*;
pub use idtp::*;
