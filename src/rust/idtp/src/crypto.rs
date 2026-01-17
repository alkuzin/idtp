// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Cryptographic and checksum calculating algorithms wrappers.

use crate::{IdtpError, IdtpResult};

#[cfg(feature = "software_impl")]
use crc::{CRC_8_AUTOSAR, CRC_32_AUTOSAR, Crc};
#[cfg(feature = "software_impl")]
use hmac::{Hmac, Mac};
#[cfg(feature = "software_impl")]
use sha2::Sha256;

/// Closure for calculating software-based `CRC-8`.
///
/// # Parameters
/// - `data` - given data to handle.
///
/// # Returns
/// - `CRC-8` - in case of success.
/// - `Err` - otherwise.
///
/// # Errors
/// - None.
#[cfg(feature = "software_impl")]
pub const fn sw_crc8(data: &[u8]) -> IdtpResult<u8> {
    Ok(Crc::<u8>::new(&CRC_8_AUTOSAR).checksum(data))
}

/// Closure for calculating software-based `CRC-32`.
///
/// # Parameters
/// - `data` - given data to handle.
///
/// # Returns
/// - `CRC-32` - in case of success.
/// - `Err` - otherwise.
///
/// # Errors
/// - None.
#[cfg(feature = "software_impl")]
pub const fn sw_crc32(data: &[u8]) -> IdtpResult<u32> {
    Ok(Crc::<u32>::new(&CRC_32_AUTOSAR).checksum(data))
}

/// Get closure for calculating software-based `HMAC-SHA256`.
///
/// # Parameters
/// - `data` - given data to handle.
/// - `key` - given `HMAC` key.
///
/// # Returns
/// - Closure for calculating software-based `HMAC-SHA256` - in case of success.
/// - `Err` - otherwise.
///
/// # Errors
/// - Invalid HMAC key.
#[cfg(feature = "software_impl")]
pub fn sw_hmac_closure(
    key: Option<&[u8]>,
) -> impl FnOnce(&[u8]) -> IdtpResult<[u8; 32]> + '_ {
    move |data: &[u8]| {
        let k = key.ok_or(IdtpError::InvalidHMacKey)?;

        let mut mac = Hmac::<Sha256>::new_from_slice(k)
            .map_err(|_| IdtpError::InvalidHMac)?;

        mac.update(data);

        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);

        Ok(out)
    }
}
