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

/// Trait for converting payload to metrics array and vice versa.
pub trait AsMetricsArray<const N: usize> {
    /// Convert metrics to a fixed-size array for.
    ///
    /// # Returns
    /// - Fixed-size array of payload members.
    fn to_array(&self) -> [f32; N];
}

#[cfg(feature = "std_payloads")]
pub use std_payloads::*;

#[cfg(feature = "std_payloads")]
mod std_payloads {
    use super::{
        AsMetricsArray, FromBytes, IdtpPayload, Immutable, IntoBytes,
        KnownLayout, idtp_data,
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

    /// Enumeration of standard payload types.
    #[derive(Debug)]
    #[repr(u8)]
    pub enum PayloadType {
        /// Accelerometer only (for 3-axis sensor).
        Imu3Acc = 0x00,
        /// Gyroscope only (for 3-axis sensor).
        Imu3Gyr = 0x01,
        /// Magnetometer only (for 3-axis sensor).
        Imu3Mag = 0x02,
        /// Accelerometer + Gyroscope readings (for 6-axis sensor).
        Imu6 = 0x03,
        /// Accelerometer + Gyroscope + Magnetometer readings
        /// (for 9-axis sensor).
        Imu9 = 0x04,
        /// Accelerometer + Gyroscope + Magnetometer + Barometer readings
        /// (for 10-axis sensor).
        Imu10 = 0x05,
        /// Attitude. Hamiltonian Quaternion (w, x, y, z).
        /// **MUST** be normalized.
        ImuQuat = 0x06,
    }

    impl IdtpPayload for Imu3Acc {
        const TYPE_ID: u8 = PayloadType::Imu3Acc as u8;
    }

    impl AsMetricsArray<3> for Imu3Acc {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 3] {
            [self.acc_x, self.acc_y, self.acc_z]
        }
    }

    impl IdtpPayload for Imu3Gyr {
        const TYPE_ID: u8 = PayloadType::Imu3Gyr as u8;
    }

    impl AsMetricsArray<3> for Imu3Gyr {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 3] {
            [self.gyr_x, self.gyr_y, self.gyr_z]
        }
    }

    impl IdtpPayload for Imu3Mag {
        const TYPE_ID: u8 = PayloadType::Imu3Mag as u8;
    }

    impl AsMetricsArray<3> for Imu3Mag {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 3] {
            [self.mag_x, self.mag_y, self.mag_z]
        }
    }

    impl IdtpPayload for Imu6 {
        const TYPE_ID: u8 = PayloadType::Imu6 as u8;
    }

    impl AsMetricsArray<6> for Imu6 {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 6] {
            [
                self.acc.acc_x,
                self.acc.acc_y,
                self.acc.acc_z,
                self.gyr.gyr_x,
                self.gyr.gyr_y,
                self.gyr.gyr_z,
            ]
        }
    }

    impl IdtpPayload for Imu9 {
        const TYPE_ID: u8 = PayloadType::Imu9 as u8;
    }

    impl AsMetricsArray<9> for Imu9 {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 9] {
            [
                self.acc.acc_x,
                self.acc.acc_y,
                self.acc.acc_z,
                self.gyr.gyr_x,
                self.gyr.gyr_y,
                self.gyr.gyr_z,
                self.mag.mag_x,
                self.mag.mag_y,
                self.mag.mag_z,
            ]
        }
    }

    impl IdtpPayload for Imu10 {
        const TYPE_ID: u8 = PayloadType::Imu10 as u8;
    }

    impl AsMetricsArray<10> for Imu10 {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 10] {
            [
                self.acc.acc_x,
                self.acc.acc_y,
                self.acc.acc_z,
                self.gyr.gyr_x,
                self.gyr.gyr_y,
                self.gyr.gyr_z,
                self.mag.mag_x,
                self.mag.mag_y,
                self.mag.mag_z,
                self.baro,
            ]
        }
    }

    impl IdtpPayload for ImuQuat {
        const TYPE_ID: u8 = PayloadType::ImuQuat as u8;
    }

    impl AsMetricsArray<4> for ImuQuat {
        /// Convert metrics to a fixed-size array for.
        ///
        /// # Returns
        /// - Fixed-size array of payload members.
        fn to_array(&self) -> [f32; 4] {
            [self.w, self.x, self.y, self.z]
        }
    }
}
