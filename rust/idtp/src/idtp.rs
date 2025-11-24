// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Inertial Measurement Unit Data Transfer Protocol (IDTP) implementation.

use crate::{IDTP_HEADER_SIZE, IDTP_TRAILER, IDTP_TRAILER_SIZE, IdtpHeader};

/// IDTP network packet max size in bytes. It includes size of IDTP header,
/// payload and packet trailer.
pub const IDTP_PACKET_MAX_SIZE: usize = 1024;

/// IDTP network packet min size in bytes.
pub const IDTP_PACKET_MIN_SIZE: usize = IDTP_HEADER_SIZE + IDTP_TRAILER_SIZE;

/// IDTP network packet payload max size in bytes.
pub const IDTP_PAYLOAD_MAX_SIZE: usize =
    IDTP_PACKET_MAX_SIZE - IDTP_HEADER_SIZE - IDTP_TRAILER_SIZE;

/// Inertial Measurement Unit Data Transfer Protocol management struct.
#[derive(Debug, Clone, Copy)]
pub struct Idtp {
    /// IDTP network packet header.
    header: IdtpHeader,
    /// Value that containing IMU data.
    payload: [u8; IDTP_PAYLOAD_MAX_SIZE],
    /// IDTP payload size in bytes.
    payload_size: usize,
}

impl Idtp {
    /// Construct new `Idtp` struct.
    ///
    /// # Returns
    /// - New `Idtp` struct.
    pub fn new() -> Self {
        Self {
            header: IdtpHeader::new(),
            payload: [0u8; IDTP_PAYLOAD_MAX_SIZE],
            payload_size: 0usize,
        }
    }

    /// Set IDTP header.
    ///
    /// # Parameters
    /// - `header` - given IDTP header to set.
    pub fn set_header(&mut self, header: &IdtpHeader) {
        self.header = *header;
    }

    /// Set IDTP payload.
    ///
    /// # Parameters
    /// - `payload` - given IDTP payload bytes to set.
    pub fn set_payload(&mut self, payload: &[u8]) {
        let payload_size = payload.len();

        if payload_size <= IDTP_PAYLOAD_MAX_SIZE {
            self.payload[0..payload_size].copy_from_slice(payload);
            self.payload_size = payload_size;
        }
    }

    /// Get IDTP header.
    ///
    /// # Returns
    /// - IDTP header struct.
    pub fn header(&self) -> IdtpHeader {
        self.header
    }

    /// Get IDTP payload.
    ///
    /// # Returns
    /// - IDTP payload in bytes representation.
    pub fn payload(&self) -> &[u8] {
        &self.payload[0..self.payload_size]
    }

    /// Get IDTP payload size in bytes.
    ///
    /// # Returns
    /// - IDTP payload in bytes representation.
    pub fn payload_size(&self) -> usize {
        self.payload_size
    }

    /// Pack into raw IDTP network packet.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to store raw IDTP packet.
    ///
    /// # Returns
    /// - `Ok`  - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Will return `Err` if network packet buffer size is too small.
    pub fn pack(&self, buffer: &mut [u8]) -> Result<(), &'static str> {
        if buffer.len() < IDTP_PACKET_MIN_SIZE + self.payload_size {
            return Err("Network packet buffer size too small");
        }

        let mut lower_range = 0;
        let mut upper_range = IDTP_HEADER_SIZE;

        buffer[lower_range..upper_range]
            .copy_from_slice(&self.header.as_bytes_be());
        lower_range = upper_range;
        upper_range += self.payload_size;

        buffer[lower_range..upper_range]
            .copy_from_slice(&self.payload[0..self.payload_size]);
        lower_range = upper_range;
        upper_range += IDTP_TRAILER_SIZE;

        buffer[lower_range..upper_range].copy_from_slice(IDTP_TRAILER);

        Ok(())
    }
}

impl Default for Idtp {
    /// Construct new default `Idtp` struct.
    ///
    /// # Returns
    /// - New default `Idtp` struct.
    fn default() -> Self {
        Self::new()
    }
}

impl From<&[u8]> for Idtp {
    /// Convert byte slice to IDTP managing struct.
    ///
    /// # Parameters
    /// - `bytes` - given byte slice to convert (big-endian byte order).
    ///
    /// # Returns
    /// - IDTP managins struct from byte slice.
    fn from(bytes: &[u8]) -> Self {
        let mut idtp = Idtp::new();
        idtp.header = IdtpHeader::from(&bytes[0..IDTP_HEADER_SIZE]);
        idtp.payload_size = bytes.len() - IDTP_HEADER_SIZE - IDTP_TRAILER_SIZE;
        idtp.payload
            .copy_from_slice(&bytes[IDTP_HEADER_SIZE..idtp.payload_size]);
        idtp
    }
}
