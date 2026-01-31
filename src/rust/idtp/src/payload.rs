// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Standard payload types.

use crate::{IdtpData, IdtpError, idtp_data};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Trait that **RECOMMENDED** to be used for IDTP payload.
pub trait IdtpPayload: Sized + IdtpData {
    /// Payload type identifier according to IDTP specification.
    const TYPE_ID: u8;

    /// Get payload size.
    ///
    /// # Returns
    /// - Payload size in bytes.
    #[inline]
    fn size(&self) -> usize {
        size_of::<Self>()
    }

    /// Get payload type.
    ///
    /// # Returns
    /// - Payload type according to IDTP specification.
    #[inline]
    #[must_use]
    fn payload_type() -> u8 {
        Self::TYPE_ID
    }

    /// Construct payload from raw bytes.
    ///
    /// # Parameters
    /// - `data` - given raw bytes to handle.
    ///
    /// # Returns
    /// - New payload object in case of success.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Parse error.
    fn from_bytes(data: &[u8]) -> Result<Self, IdtpError> {
        if data.len() < size_of::<Self>() {
            return Err(IdtpError::BufferUnderflow);
        }

        if let Ok(payload) = Self::read_from_prefix(data) {
            Ok(payload.0)
        } else {
            Err(IdtpError::ParseError)
        }
    }

    /// Convert payload to bytes.
    ///
    /// # Returns
    /// - Bytes representation of payload.
    #[inline]
    fn to_bytes(&self) -> &[u8] {
        Self::as_bytes(self)
    }
}

#[cfg(feature = "std_payloads")]
pub use std_payloads::*;

#[cfg(feature = "std_payloads")]
mod std_payloads {
    use super::{
        FromBytes, IdtpPayload, Immutable, IntoBytes, KnownLayout, idtp_data,
    };

    idtp_data! {
        /// Accelerometer only (for 3-axis sensor).
        #[derive(Default)]
        pub struct Imu3Acc {
            /// Acceleration along the X-axis in
            /// meters per second squared (`m/s²`).
            pub acc_x: f32,
            /// Acceleration along the Y-axis in
            /// meters per second squared (`m/s²`).
            pub acc_y: f32,
            /// Acceleration along the Z-axis in
            /// meters per second squared (`m/s²`).
            pub acc_z: f32,
        }

        /// Gyroscope only (for 3-axis sensor).
        #[derive(Default)]
        pub struct Imu3Gyr {
            /// Angular velocity along the X-axis in
            /// radians per second (`rad/s`).
            pub gyr_x: f32,
            /// Angular velocity along the Y-axis in
            /// radians per second (`rad/s`).
            pub gyr_y: f32,
            /// Angular velocity along the Z-axis in
            /// radians per second (`rad/s`).
            pub gyr_z: f32,
        }

        /// Magnetometer only (for 3-axis sensor).
        #[derive(Default)]
        pub struct Imu3Mag {
            /// Magnetic field induction along the X-axis in
            /// microteslas (`μT`).
            pub mag_x: f32,
            /// Magnetic field induction along the Y-axis in
            /// microteslas (`μT`).
            pub mag_y: f32,
            /// Magnetic field induction along the Z-axis in
            /// microteslas (`μT`).
            pub mag_z: f32,
        }

        /// Accelerometer + Gyroscope readings (for 6-axis sensor).
        #[derive(Default)]
        pub struct Imu6 {
            /// Accelerometer readings along 3 axes.
            pub acc: Imu3Acc,
            /// Gyroscope readings along 3 axes.
            pub gyr: Imu3Gyr,
        }

        /// Accelerometer + Gyroscope + Magnetometer readings
        /// (for 9-axis sensor).
        #[derive(Default)]
        pub struct Imu9 {
            /// Accelerometer readings along 3 axes.
            pub acc: Imu3Acc,
            /// Gyroscope readings along 3 axes.
            pub gyr: Imu3Gyr,
            /// Magnetometer readings along 3 axes.
            pub mag: Imu3Mag,
        }

        /// Accelerometer + Gyroscope + Magnetometer + Barometer readings
        /// (for 10-axis sensor).
        #[derive(Default)]
        pub struct Imu10 {
            /// Accelerometer readings along 3 axes.
            pub acc: Imu3Acc,
            /// Gyroscope readings along 3 axes.
            pub gyr: Imu3Gyr,
            /// Magnetometer readings along 3 axes.
            pub mag: Imu3Mag,
            /// Atmospheric pressure in Pascals (`Pa`).
            pub baro: f32,
        }

        /// Attitude. Hamiltonian Quaternion (w, x, y, z).
        /// **MUST** be normalized.
        #[derive(Default)]
        pub struct ImuQuat {
            /// Scalar component.
            pub w: f32,
            /// Vector X component.
            pub x: f32,
            /// Vector Y component.
            pub y: f32,
            /// Vector Z component.
            pub z: f32,
        }
    }

    impl IdtpPayload for Imu3Acc {
        const TYPE_ID: u8 = 0x00;
    }

    impl IdtpPayload for Imu3Gyr {
        const TYPE_ID: u8 = 0x01;
    }

    impl IdtpPayload for Imu3Mag {
        const TYPE_ID: u8 = 0x02;
    }

    impl IdtpPayload for Imu6 {
        const TYPE_ID: u8 = 0x03;
    }

    impl IdtpPayload for Imu9 {
        const TYPE_ID: u8 = 0x04;
    }

    impl IdtpPayload for Imu10 {
        const TYPE_ID: u8 = 0x05;
    }

    impl IdtpPayload for ImuQuat {
        const TYPE_ID: u8 = 0x06;
    }
}
