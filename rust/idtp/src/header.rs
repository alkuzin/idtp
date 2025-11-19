// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP header related declarations.

/// Value to signal the start of a new IDTP packet.
pub const IDTP_PREAMBLE: &[u8] = b"IDTP";

/// Size of IDTP preamble in bytes.
pub const IDTP_PREAMBLE_SIZE: usize = IDTP_PREAMBLE.len();

/// Value to signal the end of a new IDTP packet.
pub const IDTP_TRAILER: &[u8] = b"PTDI";

/// Size of IDTP trailer in bytes.
pub const IDTP_TRAILER_SIZE: usize = IDTP_TRAILER.len();

/// IDTP version information struct.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct Version {
    /// Increments after incompatible API changes were made.
    pub major: u8,
    /// Increments after adding functionality in a backwards-compatible manner.
    pub minor: u8,
    /// Increments after backwards-compatible bug fixes were made.
    pub patch: u8,
}

/// Size of IDTP version size in bytes.
pub const IDTP_VERSION_SIZE: usize = size_of::<Version>();

/// Current IDTP version.
pub const IDTP_VERSION: Version = Version {
    major: 1,
    minor: 0,
    patch: 0,
};

impl Version {
    /// Convert IDTP version to byte slice.
    ///
    /// # Returns
    /// - Byte representation of IDTP version.
    pub fn as_bytes(&self) -> [u8; IDTP_VERSION_SIZE] {
        [self.major, self.minor, self.patch]
    }
}

impl From<&[u8]> for Version {
    /// Convert byte slice to IDTP version.
    ///
    /// # Parameters
    /// - `bytes` - given byte slice to convert.
    ///
    /// # Returns
    /// - IDTP version from byte slice.
    fn from(bytes: &[u8]) -> Self {
        Self {
            major: bytes[0],
            minor: bytes[1],
            patch: bytes[2],
        }
    }
}

/// IDTP operating mode.
#[derive(Debug, Default, Clone, Copy)]
#[repr(u8)]
pub enum Mode {
    /// IDTP-N (Normal mode) - operating mode with general protection.
    /// Error detection provided by checksum only.
    ///
    /// Detects simple errors like single-bit errors and some small
    /// burst errors. However, it's less effective against more complex or
    /// patterned errors.
    ///
    /// Only `checksum` field of IDTP header is used. The `crc` field is unused
    /// and filled with zeros.
    #[default]
    Normal = 0x00,
    /// IDTP-S (Safety mode) - operating mode with more complex protection.
    /// Error detection provided by checksum and CRC (Cyclic Redundancy Check).
    ///
    /// CRC is effective at detecting common error patterns,
    /// including single-bit errors, burst errors, and many random errors.
    /// The effectiveness depends on the choice of generator polynomial.
    ///
    /// Both `checksum` and `crc` fields of IDTP header are used.
    Safety = 0x01,
}

impl From<u8> for Mode {
    /// Convert byte to IDTP operating mode.
    ///
    /// # Parameters
    /// - `bytes` - given byte slice to convert.
    ///
    /// # Returns
    /// - IDTP operating mode from byte slice.
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Mode::Normal,
            0x01 => Mode::Safety,
            _ => Mode::Normal,
        }
    }
}

/// IDTP header struct.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C, packed)]
pub struct IdtpHeader {
    /// Value to signal the start of a new IDTP packet.
    pub preamble: [u8; IDTP_PREAMBLE_SIZE],
    /// Protocol version in format MAJOR.MINOR.PATCH.
    pub version: Version,
    /// Protocol operating mode.
    pub mode: Mode,
    /// IMU device identifier.
    pub device_id: u16,
    /// Value to used for simple error detection.
    pub checksum: u16,
    /// Sensors flags that IMU contain.
    pub sensors: u32,
    /// Timestamp from the IMU's MCU internal clock.
    pub timestamp: u32,
    /// Sequence number of IDTP packet sent.
    pub packet_num: u32,
    /// Size of packet payload in bytes (header and trailer size excluded).
    pub size: u32,
    /// Cyclic Redundancy Check - value to used for complex error detection.
    pub crc: u32,
}

/// Size of IDTP header in bytes.
pub const IDTP_HEADER_SIZE: usize = size_of::<IdtpHeader>();

impl IdtpHeader {
    /// Construct new `IdtpHeader` object.
    ///
    /// # Returns
    /// - New `IdtpHeader` object.
    pub fn new() -> Self {
        let mut header = IdtpHeader::default();
        header.preamble.clone_from_slice(IDTP_PREAMBLE);
        header.version = IDTP_VERSION;
        header
    }

    /// Convert IDTP header to byte slice with big-endian network byte order.
    ///
    /// # Returns
    /// - Big-endian byte representation of IDTP header.
    pub fn as_bytes_be(&self) -> [u8; IDTP_HEADER_SIZE] {
        let mut buffer = [0u8; IDTP_HEADER_SIZE];

        buffer[0..4].copy_from_slice(&self.preamble);
        buffer[4..7].copy_from_slice(&self.version.as_bytes());
        buffer[7] = self.mode as u8;
        buffer[8..10].copy_from_slice(&self.device_id.to_be_bytes());
        buffer[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buffer[12..16].copy_from_slice(&self.sensors.to_be_bytes());
        buffer[16..20].copy_from_slice(&self.timestamp.to_be_bytes());
        buffer[20..24].copy_from_slice(&self.packet_num.to_be_bytes());
        buffer[24..28].copy_from_slice(&self.size.to_be_bytes());
        buffer[28..32].copy_from_slice(&self.crc.to_be_bytes());
        buffer
    }
}

impl From<&[u8]> for IdtpHeader {
    /// Convert byte slice to IDTP header.
    ///
    /// # Parameters
    /// - `bytes` - given byte slice to convert (big-endian byte order).
    ///
    /// # Returns
    /// - IDTP header from byte slice.
    fn from(bytes: &[u8]) -> Self {
        let mut header = IdtpHeader::default();

        header.preamble.copy_from_slice(&bytes[0..4]);
        header.version = Version::from(&bytes[4..7]);
        header.mode = Mode::from(bytes[7]);
        header.device_id = u16::from_be_bytes([bytes[8], bytes[9]]);
        header.checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        header.sensors = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        header.timestamp =
            u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        header.packet_num =
            u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        header.size = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        header.crc = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
        header
    }
}
