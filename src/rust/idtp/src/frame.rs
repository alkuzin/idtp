// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Inertial Measurement Unit Data Transfer Protocol frame implementation.

#[cfg(feature = "software_impl")]
use crate::crypto;
use crate::{IDTP_HEADER_SIZE, IdtpError, IdtpHeader, IdtpResult, Mode};
use zerocopy::{FromBytes, IntoBytes};

/// IDTP frame max size in bytes. It includes size of IDTP header,
/// payload and packet trailer.
pub const IDTP_FRAME_MAX_SIZE: usize = 1024;

/// IDTP frame min size in bytes.
pub const IDTP_FRAME_MIN_SIZE: usize = IDTP_HEADER_SIZE;

/// IDTP network packet payload max size in bytes.
pub const IDTP_PAYLOAD_MAX_SIZE: usize = 972;

/// Inertial Measurement Unit Data Transfer Protocol frame struct.
#[derive(Debug, Clone, Copy)]
pub struct IdtpFrame {
    /// IDTP frame header.
    header: IdtpHeader,
    /// Value that containing IMU data.
    payload: [u8; IDTP_PAYLOAD_MAX_SIZE],
    /// IDTP payload size in bytes.
    payload_size: usize,
}

impl IdtpFrame {
    /// Construct new `IdtpFrame` struct.
    ///
    /// # Returns
    /// - New `IdtpFrame` struct.
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
            self.header.payload_size = payload_size as u16;
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

    /// Get frame trailer size.
    ///
    /// # Returns
    /// - Trailer size in bytes.
    pub fn trailer_size(&self) -> usize {
        let mode = Mode::from(self.header.mode);

        match mode {
            Mode::Lite => 0,
            Mode::Safety => 4,
            Mode::Secure => 32,
            Mode::Unknown => 0,
        }
    }

    /// Pack into raw IDTP frame. `CRC` & `HMAC` calculation is software-based.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to store IDTP frame bytes.
    /// - `key` - given `HMAC` key.
    ///
    /// # Returns
    /// - Frame size in bytes - in case of success.
    /// - `Err` - otherwise.
    #[cfg(feature = "software_impl")]
    pub fn pack(
        &self,
        buffer: &mut [u8],
        key: Option<&[u8]>,
    ) -> IdtpResult<usize> {
        self.pack_with(
            buffer,
            crypto::sw_crc8,
            crypto::sw_crc32,
            crypto::sw_hmac_closure(key),
        )
    }

    /// Pack into raw IDTP frame with custom `CRC` and `HMAC` calculation.
    /// Recommended to use if hardware acceleration for `CRC`/`HMAC` available.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to store IDTP frame bytes.
    /// - `calc_crc8` - given closure with custom `CRC-8` calculation logic.
    /// - `calc_crc32` - given closure with custom `CRC-32` calculation logic.
    /// - `calc_hmac` - given closure with custom `HMAC-SHA256` calculation logic.
    ///
    /// # Returns
    /// - Frame size in bytes - in case of success.
    /// - `Err` - otherwise.
    pub fn pack_with<C8, C32, H>(
        &self,
        buffer: &mut [u8],
        calc_crc8: C8,
        calc_crc32: C32,
        calc_hmac: H,
    ) -> IdtpResult<usize>
    where
        C8: FnOnce(&[u8]) -> IdtpResult<u8>,
        C32: FnOnce(&[u8]) -> IdtpResult<u32>,
        H: FnOnce(&[u8]) -> IdtpResult<[u8; 32]>,
    {
        let trailer_size = self.trailer_size();
        let expected_size =
            IDTP_FRAME_MIN_SIZE + self.payload_size + trailer_size;

        if buffer.len() < expected_size {
            return Err(IdtpError::BufferUnderflow);
        }

        // Packing IDTP header & calculating the CRC-8.
        let header_size = IDTP_HEADER_SIZE;
        buffer[..header_size].copy_from_slice(self.header.as_bytes());

        let crc8 = calc_crc8(&buffer[..19])?;
        buffer[19] = crc8;

        // Packing payload.
        let payload_size = self.payload_size;
        let payload_range = header_size..header_size + payload_size;
        buffer[payload_range].copy_from_slice(&self.payload[..payload_size]);

        // Packing frame trailer.
        let data_size = header_size + payload_size;
        let mode = Mode::from(self.header.mode);
        let frame_size = data_size + trailer_size;

        match mode {
            Mode::Lite => {}
            Mode::Safety => {
                let crc32 = calc_crc32(&buffer[..data_size])?;
                buffer[data_size..frame_size]
                    .copy_from_slice(&crc32.to_le_bytes());
            }
            Mode::Secure => {
                let hmac = calc_hmac(&buffer[..data_size])?;
                buffer[data_size..frame_size].copy_from_slice(&hmac);
            }
            Mode::Unknown => {}
        };

        Ok(frame_size)
    }

    /// Validate IDTP frame integrity. `CRC` & `HMAC` calculation is software-based.
    ///
    /// # Parameters
    /// - `buffer` - given IDTP frame bytes.
    /// - `key` - given `HMAC` key.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    #[cfg(feature = "software_impl")]
    pub fn validate(
        &self,
        buffer: &[u8],
        key: Option<&[u8]>,
    ) -> IdtpResult<()> {
        self.validate_with(
            buffer,
            crypto::sw_crc8,
            crypto::sw_crc32,
            crypto::sw_hmac_closure(key),
        )
    }

    /// Validate IDTP frame integrity with custom `CRC` and `HMAC` calculation.
    /// Recommended to use if hardware acceleration for `CRC`/`HMAC` available.
    ///
    /// # Parameters
    /// - `buffer` - given IDTP frame bytes.
    /// - `calc_crc8` - given closure with custom `CRC-8` calculation logic.
    /// - `calc_crc32` - given closure with custom `CRC-32` calculation logic.
    /// - `calc_hmac` - given closure with custom `HMAC-SHA256` calculation logic.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    pub fn validate_with<C8, C32, H>(
        &self,
        buffer: &[u8],
        calc_crc8: C8,
        calc_crc32: C32,
        calc_hmac: H,
    ) -> IdtpResult<()>
    where
        C8: FnOnce(&[u8]) -> IdtpResult<u8>,
        C32: FnOnce(&[u8]) -> IdtpResult<u32>,
        H: FnOnce(&[u8]) -> IdtpResult<[u8; 32]>,
    {
        let header_size = IDTP_HEADER_SIZE;

        if buffer.len() < header_size {
            return Err(IdtpError::BufferUnderflow);
        }

        // Checking CRC-8 of IDTP header.
        let received_crc8 = buffer[19];
        let computed_crc8 = calc_crc8(&buffer[..19])?;

        if received_crc8 != computed_crc8 {
            return Err(IdtpError::InvalidCrc);
        }

        // Checking size.
        let header = IdtpHeader::read_from_prefix(buffer)
            .map_err(|_| IdtpError::ParseError)?
            .0;

        let payload_size = header.payload_size as usize;
        let mode = Mode::from(header.mode);

        let trailer_size = self.trailer_size();

        let data_size = header_size + payload_size;
        let expected_size = data_size + trailer_size;

        if buffer.len() < expected_size {
            return Err(IdtpError::BufferUnderflow);
        }

        let frame_size = data_size + trailer_size;

        // Checking frame trailer.
        match mode {
            Mode::Lite => {}
            Mode::Safety => {
                let computed_crc32 = calc_crc32(&buffer[..data_size])?;
                let received_crc32 = u32::from_le_bytes(
                    buffer[data_size..frame_size]
                        .try_into()
                        .map_err(|_| IdtpError::ParseError)?,
                );

                if received_crc32 != computed_crc32 {
                    return Err(IdtpError::InvalidCrc);
                }
            }
            Mode::Secure => {
                let computed_hmac = calc_hmac(&buffer[..data_size])?;
                let received_hmac = &buffer[data_size..data_size + 32];

                if computed_hmac != received_hmac {
                    return Err(IdtpError::InvalidHMac);
                }
            }
            Mode::Unknown => return Err(IdtpError::InvalidCrc),
        };

        Ok(())
    }
}

impl TryFrom<&[u8]> for IdtpFrame {
    type Error = IdtpError;

    /// Convert byte slice into IDTP frame.
    ///
    /// # Parameters
    /// - `buffer` - given byte slice to convert (Little-Endian byte order).
    ///
    /// # Returns
    /// - IDTP frame struct from byte slice - in case of success.
    /// - `Err` - otherwise.
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let header_size = IDTP_HEADER_SIZE;

        if buffer.len() < header_size {
            return Err(IdtpError::BufferUnderflow);
        }

        let header = IdtpHeader::read_from_prefix(buffer)
            .map_err(|_| IdtpError::ParseError)?
            .0;

        let mut idtp = IdtpFrame::new();
        idtp.header = header;
        idtp.payload_size = header.payload_size as usize;

        let trailer_size = idtp.trailer_size();
        let expected_size = header_size + idtp.payload_size + trailer_size;

        if buffer.len() < expected_size {
            return Err(IdtpError::BufferUnderflow);
        }

        let payload_start = header_size;
        let payload_end = header_size + idtp.payload_size;

        idtp.payload[..idtp.payload_size]
            .copy_from_slice(&buffer[payload_start..payload_end]);
        Ok(idtp)
    }
}

impl Default for IdtpFrame {
    /// Construct new default `IdtpFrame` struct.
    ///
    /// # Returns
    /// - New default `IdtpFrame` struct.
    fn default() -> Self {
        Self::new()
    }
}
