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
    #[must_use]
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
    pub const fn set_header(&mut self, header: &IdtpHeader) {
        self.header = *header;
    }

    /// Set IDTP payload.
    ///
    /// # Parameters
    /// - `payload` - given IDTP payload bytes to set.
    ///   TODO:
    ///
    /// # Errors
    /// - Buffer underflow.
    pub fn set_payload(&mut self, payload: &[u8]) -> IdtpResult<()> {
        let payload_size = payload.len();

        if payload_size <= IDTP_PAYLOAD_MAX_SIZE {
            self.payload
                .get_mut(..payload_size)
                .ok_or(IdtpError::BufferUnderflow)?
                .copy_from_slice(payload);
            self.payload_size = payload_size;
            self.header.payload_size = u16::try_from(payload_size)
                .map_err(|_| IdtpError::ParseError)?;
        }

        Ok(())
    }

    /// Get IDTP header.
    ///
    /// # Returns
    /// - IDTP header struct.
    #[must_use]
    pub const fn header(&self) -> IdtpHeader {
        self.header
    }

    /// Get IDTP payload.
    ///
    /// # Returns
    /// - IDTP payload in bytes representation.
    ///
    /// # Errors
    /// - Buffer underflow.
    pub fn payload(&self) -> IdtpResult<&[u8]> {
        let payload = &self
            .payload
            .get(0..self.payload_size)
            .ok_or(IdtpError::BufferUnderflow)?;
        Ok(payload)
    }

    /// Get IDTP payload size in bytes.
    ///
    /// # Returns
    /// - IDTP payload in bytes representation.
    #[must_use]
    pub const fn payload_size(&self) -> usize {
        self.payload_size
    }

    /// Get frame trailer size.
    ///
    /// # Returns
    /// - Trailer size in bytes.
    #[must_use]
    pub fn trailer_size(&self) -> usize {
        let mode = Mode::from(self.header.mode);

        match mode {
            Mode::Safety => 4,
            Mode::Secure => 32,
            Mode::Lite | Mode::Unknown => 0,
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
    ///
    /// # Errors
    /// - Buffer underflow.
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
    ///
    /// # Errors
    /// - Buffer underflow.
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
        buffer
            .get_mut(..header_size)
            .ok_or(IdtpError::BufferUnderflow)?
            .copy_from_slice(self.header.as_bytes());

        let data = &buffer.get(..19).ok_or(IdtpError::BufferUnderflow)?;
        let crc8 = calc_crc8(data)?;
        *buffer.get_mut(19).ok_or(IdtpError::BufferUnderflow)? = crc8;

        // Packing payload.
        let payload_size = self.payload_size;
        let payload_range = header_size..header_size + payload_size;
        let payload = &self
            .payload
            .get(..payload_size)
            .ok_or(IdtpError::BufferUnderflow)?;

        buffer
            .get_mut(payload_range)
            .ok_or(IdtpError::BufferUnderflow)?
            .copy_from_slice(payload);

        // Packing frame trailer.
        let data_size = header_size + payload_size;
        let mode = Mode::from(self.header.mode);
        let frame_size = data_size + trailer_size;
        let data =
            &buffer.get(..data_size).ok_or(IdtpError::BufferUnderflow)?;

        match mode {
            Mode::Safety => {
                let crc32 = calc_crc32(data)?;
                buffer
                    .get_mut(data_size..frame_size)
                    .ok_or(IdtpError::BufferUnderflow)?
                    .copy_from_slice(&crc32.to_le_bytes());
            }
            Mode::Secure => {
                let hmac = calc_hmac(data)?;
                buffer
                    .get_mut(data_size..frame_size)
                    .ok_or(IdtpError::BufferUnderflow)?
                    .copy_from_slice(&hmac);
            }
            Mode::Lite | Mode::Unknown => {}
        }

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
    ///
    /// # Errors
    /// - Buffer underflow.
    #[cfg(feature = "software_impl")]
    pub fn validate(
        buffer: &[u8],
        key: Option<&[u8]>,
    ) -> IdtpResult<()> {
        Self::validate_with(
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
    ///
    /// # Errors
    /// - Buffer underflow.
    pub fn validate_with<C8, C32, H>(
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
        let received_crc8 = buffer.get(19).ok_or(IdtpError::BufferUnderflow)?;
        let data = &buffer.get(..19).ok_or(IdtpError::BufferUnderflow)?;
        let computed_crc8 = calc_crc8(data)?;

        if *received_crc8 != computed_crc8 {
            return Err(IdtpError::InvalidCrc);
        }

        // Checking size.
        let header = IdtpHeader::read_from_prefix(buffer)
            .map_err(|_| IdtpError::ParseError)?
            .0;

        let payload_size = header.payload_size as usize;
        let mode = Mode::from(header.mode);

        let trailer_size = match mode {
            Mode::Lite => 0,
            Mode::Safety => 4,
            Mode::Secure => 32,
            _ => 0,
        };

        let data_size = header_size + payload_size;
        let expected_size = data_size + trailer_size;

        if buffer.len() < expected_size {
            return Err(IdtpError::BufferUnderflow);
        }

        let frame_size = data_size + trailer_size;
        let data =
            &buffer.get(..data_size).ok_or(IdtpError::BufferUnderflow)?;

        // Checking frame trailer.
        match mode {
            Mode::Lite => {}
            Mode::Safety => {
                let computed_crc32 = calc_crc32(data)?;
                let received_crc32 = u32::from_le_bytes(
                    buffer
                        .get(data_size..frame_size)
                        .ok_or(IdtpError::BufferUnderflow)?
                        .try_into()
                        .map_err(|_| IdtpError::ParseError)?,
                );

                if computed_crc32 != received_crc32 {
                    return Err(IdtpError::InvalidCrc);
                }
            }
            Mode::Secure => {
                let computed_hmac = calc_hmac(data)?;
                let received_hmac = buffer
                    .get(data_size..frame_size)
                    .ok_or(IdtpError::BufferUnderflow)?;

                if computed_hmac != received_hmac {
                    return Err(IdtpError::InvalidHMac);
                }
            }
            Mode::Unknown => return Err(IdtpError::InvalidCrc),
        }

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

        let mut idtp = Self::new();
        idtp.header = header;
        idtp.payload_size = header.payload_size as usize;

        let trailer_size = idtp.trailer_size();
        let expected_size = header_size + idtp.payload_size + trailer_size;

        if buffer.len() < expected_size {
            return Err(IdtpError::BufferUnderflow);
        }

        let payload_start = header_size;
        let payload_end = header_size + idtp.payload_size;

        let payload = &buffer
            .get(payload_start..payload_end)
            .ok_or(IdtpError::BufferUnderflow)?;

        idtp.payload
            .get_mut(..idtp.payload_size)
            .ok_or(IdtpError::BufferUnderflow)?
            .copy_from_slice(payload);

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
