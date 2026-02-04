// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP v2.1.0 usage example.

use idtp::{
    IdtpFrame, IdtpHeader, IdtpMode,
    payload::{Imu3Acc, Imu3Gyr, Imu6},
};
use std::process;

fn main() {
    // -----------------------------------------------------------------------
    // 1) SENDER SIDE: Creating and packing an IDTP v2 frame.
    // -----------------------------------------------------------------------

    let imu_data = Imu6 {
        acc: Imu3Acc {
            acc_x: 0.001,
            acc_y: 0.002,
            acc_z: 0.003,
        },
        gyr: Imu3Gyr {
            gyr_x: 0.004,
            gyr_y: 0.005,
            gyr_z: 0.006,
        },
    };

    let mut frame = IdtpFrame::new();
    let mut header = IdtpHeader::new();

    header.mode = IdtpMode::Safety.into();
    header.device_id = 0xABCD;
    header.timestamp = 12345678;
    header.sequence = 1;

    // Important: In v2, set_header should be called before set_payload
    // or payload size must be synchronized.
    frame.set_header(&header);
    let _ = frame.set_payload(&imu_data);

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

    if let Ok(payload) = decoded_frame.payload::<Imu6>() {
        println!("Received header: {:#?}", header);
        println!("Received payload: {:#?}", payload);
    }
}
