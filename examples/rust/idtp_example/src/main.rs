// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP v2.0.0 usage example.

use idtp::{IdtpFrame, IdtpHeader, Mode};
use std::{mem, process};

/// Example IDTP payload struct.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C, packed)]
pub struct ImuPayload {
    pub acc_x: f32,
    pub acc_y: f32,
    pub acc_z: f32,
    pub gyr_x: f32,
    pub gyr_y: f32,
    pub gyr_z: f32,
}

/// Example payload size in bytes.
pub const PAYLOAD_SIZE: usize = size_of::<ImuPayload>();

impl ImuPayload {
    /// Convert payload to bytes.
    ///
    /// # Returns
    /// - Payload byte array.
    pub fn as_bytes(&self) -> [u8; PAYLOAD_SIZE] {
        unsafe { mem::transmute::<Self, [u8; PAYLOAD_SIZE]>(*self) }
    }

    /// Convert a byte slice to a `Payload` struct.
    ///
    /// # Parameters
    /// - `bytes` - given bytes to convert.
    ///
    /// # Returns
    /// - Payload from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut payload = Self::default();

        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut payload as *mut Self as *mut u8,
                size_of::<Self>(),
            );
        }
        payload
    }
}

fn main() {
    // -----------------------------------------------------------------------
    // 1) SENDER SIDE: Creating and packing an IDTP v2 frame.
    // -----------------------------------------------------------------------

    let imu_data = ImuPayload {
        acc_x: 0.001,
        acc_y: 0.002,
        acc_z: 0.003,
        gyr_x: 0.004,
        gyr_y: 0.005,
        gyr_z: 0.006,
    };

    let mut frame = IdtpFrame::new();
    let mut header = IdtpHeader::new();

    header.mode = Mode::Safety as u8;
    header.device_id = 0xABCD;
    header.timestamp = 12345678;
    header.sequence = 1;

    // Important: In v2, set_header should be called before set_payload
    // or payload size must be synchronized.
    frame.set_header(&header);
    let _ = frame.set_payload(&imu_data.as_bytes());

    // Prepare buffer for data transmission.
    let mut buffer = [0u8; 64];

    // Packing with software-based CRC/HMAC (requires "software_impl" feature)
    // In production (MCU), use pack_with() to utilize
    // hardware CRC/HMAC accelerators.
    let packet_size = match frame.pack(&mut buffer, None) {
        Ok(size) => {
            println!("Successfully packed {} bytes", size);
            size
        }
        Err(e) => {
            eprintln!("Packing error: {:?}", e);
            process::exit(1);
        }
    };

    println!("Hex frame: {:02X?}", &buffer[..packet_size]);

    // -----------------------------------------------------------------------
    // 2) RECEIVER SIDE: Validating and parsing IDTP v2 frame.
    // -----------------------------------------------------------------------

    let incoming_data = &buffer[..packet_size];

    // Validate integrity. This checks Header CRC-8 and Frame CRC-32 without
    // creating an object.
    if let Err(e) = IdtpFrame::validate(incoming_data, None) {
        eprintln!("Invalid frame received: {:?}", e);
        return;
    }

    // Parse bytes into frame structure.
    let decoded_frame = match IdtpFrame::try_from(incoming_data) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Parse error: {:?}", e);
            return;
        }
    };

    // Extract and use data.
    let header = decoded_frame.header();
    let payload_bytes = decoded_frame.payload().unwrap();
    let payload = ImuPayload::from_bytes(payload_bytes);

    println!("Received header: {:#?}", header);
    println!("Received payload: {:#?}", payload);
}
