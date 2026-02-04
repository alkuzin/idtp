// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP header related declarations.

use crate::{FromBytes, Immutable, IntoBytes, KnownLayout, idtp_data};

/// Value to signal the start of a new IDTP frame.
pub const IDTP_PREAMBLE: u32 = 0x5054_4449;

/// Current IDTP version.
/// For v2.0, the value is 0x21 (where 0x2 is Major and 0x1 is Minor).
pub const IDTP_VERSION: u8 = 0x21;

/// IDTP operating mode.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum IdtpMode {
    /// `IDTP-L (Lite mode)` - operating mode for minimum latency & overhead
    /// with general protection. SHOULD be used for trusted channels only.
    Lite = 0x00,
    /// `IDTP-S (Safety mode)` - operating mode with balance between speed and
    /// integrity with more complex protection. SHOULD be used for
    /// most applications.
    #[default]
    Safety = 0x01,
    /// `IDTP-SEC (Secure mode)` - operating mode with protection against
    /// data spoofing. MUST be used for data transmission over unsecured
    /// channels.
    Secure = 0x02,
    /// Unknown mode. No special handling required (used as placeholder).
    Unknown = 0xff,
}

impl From<IdtpMode> for u8 {
    /// Convert IDTP mode to u8.
    ///
    /// # Parameters
    /// - `mode` - given IDTP mode to convert.
    ///
    /// # Returns
    /// -  IDTP mode in u8 representation.
    fn from(mode: IdtpMode) -> Self {
        mode as Self
    }
}

impl From<u8> for IdtpMode {
    /// Convert byte to IDTP operating mode.
    ///
    /// # Parameters
    /// - `bytes` - given byte slice to convert.
    ///
    /// # Returns
    /// - IDTP operating mode from byte slice.
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Self::Lite,
            0x01 => Self::Safety,
            0x02 => Self::Secure,
            _ => Self::Unknown,
        }
    }
}

idtp_data! {
    #[derive(Default)]
    /// IDTP header struct.
    pub struct IdtpHeader {
        /// Value to signal the start of a new IDTP frame.
        pub preamble: u32,
        /// Timestamp represents the sensor-local time.
        pub timestamp: u32,
        /// Sequence number of IDTP frame sent.
        pub sequence: u32,
        /// Vendor-specific unique IMU device identifier.
        pub device_id: u16,
        /// Size of packet payload in bytes.
        pub payload_size: u16,
        /// Protocol version in format MAJOR.MINOR.
        pub version: u8,
        /// Protocol operating mode.
        pub mode: u8,
        /// Both standard & vendor-specific payload type.
        pub payload_type: u8,
        /// Cyclic Redundancy Check - value to used for complex error detection.
        pub crc: u8,
    }
}

/// Size of IDTP header in bytes.
pub const IDTP_HEADER_SIZE: usize = size_of::<IdtpHeader>();

impl IdtpHeader {
    /// Construct new `IdtpHeader` object.
    ///
    /// # Returns
    /// - New `IdtpHeader` object.
    #[must_use]
    pub fn new() -> Self {
        Self {
            preamble: IDTP_PREAMBLE,
            version: IDTP_VERSION,
            ..Default::default()
        }
    }

    /// Get header size.
    ///
    /// # Returns
    /// - Header size in bytes.
    #[inline]
    #[must_use]
    pub const fn size() -> usize {
        IDTP_HEADER_SIZE
    }
}
