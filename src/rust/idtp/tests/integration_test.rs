// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP integration tests.

#[cfg(test)]
mod tests {
    use idtp::payload::{IdtpPayload, Imu6};
    use idtp::*;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

    #[test]
    fn test_constants() {
        assert_eq!(IDTP_HEADER_SIZE, 20);
        assert_eq!(IDTP_FRAME_MAX_SIZE, 1024);
        assert_eq!(IDTP_PAYLOAD_MAX_SIZE, 972);
        assert_eq!(u32::from_le_bytes(*b"IDTP"), 0x50544449);
    }

    #[test]
    fn test_header_alignment() {
        let mut header = IdtpHeader::new();
        header.timestamp = 0x12345678;
        header.sequence = 0x11223344;
        header.device_id = 0x01;
        header.payload_size = 10;
        header.version = 0x20;
        header.mode = 0x01;

        let bytes = header.as_bytes();
        assert_eq!(bytes.len(), 20);

        assert_eq!(bytes[4], 0x78);
        assert_eq!(bytes[5], 0x56);
        assert_eq!(bytes[6], 0x34);
        assert_eq!(bytes[7], 0x12);
    }

    #[test]
    fn test_mode_trailer_sizes() {
        let mut frame = IdtpFrame::new();

        frame.set_header(&IdtpHeader {
            mode: 0,
            ..IdtpHeader::new()
        });
        assert_eq!(frame.trailer_size(), 0);

        frame.set_header(&IdtpHeader {
            mode: 1,
            ..IdtpHeader::new()
        });
        assert_eq!(frame.trailer_size(), 4);

        frame.set_header(&IdtpHeader {
            mode: 2,
            ..IdtpHeader::new()
        });
        assert_eq!(frame.trailer_size(), 32);
    }

    #[test]
    fn test_pack_with_custom_closures() {
        let mut frame = IdtpFrame::new();
        let payload = [0xAA, 0xBB, 0xCC];

        frame.set_header(&IdtpHeader {
            mode: 1,
            ..IdtpHeader::new()
        });
        let _ = frame.set_payload_raw(&payload, 0x80);

        let mut buffer = [0u8; 128];

        let result = frame.pack_with(
            &mut buffer,
            |_| Ok(0xDE),
            |_| Ok(0xDEADBEEF),
            |_| Ok([0u8; 32]),
        );

        assert!(result.is_ok());
        let total_size = result.unwrap();

        // 20 (header) + 3 (payload) + 4 (crc32) = 27.
        assert_eq!(total_size, 27);
        assert_eq!(buffer[19], 0xDE);
        assert_eq!(&buffer[23..27], &[0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn test_buffer_underflow_protection() {
        let mut frame = IdtpFrame::new();
        frame.set_header(&IdtpHeader {
            mode: 1,
            ..IdtpHeader::new()
        });
        let _ = frame.set_payload_raw(&[0u8; 100], 0x80);

        let mut small_buffer = [0u8; 20 + 100 + 3];
        let result = frame.pack_with(
            &mut small_buffer,
            |_| Ok(0),
            |_| Ok(0),
            |_| Ok([0u8; 32]),
        );

        assert!(matches!(result, Err(IdtpError::BufferUnderflow)));
    }

    #[test]
    fn test_full_cycle_try_from() {
        let mut buffer = [0u8; 30];
        let mut frame = IdtpFrame::new();
        let payload = b"Hello";

        frame.set_header(&IdtpHeader {
            device_id: 0x42,
            mode: 0,
            ..IdtpHeader::new()
        });
        frame.set_payload_raw(payload, 0x80).unwrap();
        frame
            .pack_with(&mut buffer, |_| Ok(0), |_| Ok(0), |_| Ok([0u8; 32]))
            .unwrap();

        let decoded = IdtpFrame::try_from(&buffer[..]).expect("Should decode");
        let header = decoded.header();

        let device_id = header.device_id;
        let decoded_payload = decoded.payload_raw().unwrap();

        assert_eq!(device_id, 0x42);
        assert_eq!(decoded_payload, payload);
        assert_eq!(decoded.payload_size(), 5);
    }

    #[cfg(feature = "software_impl")]
    #[test]
    fn test_software_validation_safety_mode() {
        let mut frame = IdtpFrame::new();
        frame.set_header(&IdtpHeader {
            mode: 1,
            ..IdtpHeader::new()
        });
        let _ = frame.set_payload_raw(b"IntegrityCheck", 0x80);

        let mut buffer = [0u8; 256];
        let size = frame.pack(&mut buffer, None).unwrap();

        let validation = IdtpFrame::validate(&buffer[..size], None);
        assert!(
            validation.is_ok(),
            "Validation failed: {:?}",
            validation.err()
        );

        buffer[25] ^= 0xFF;
        let validation_corrupted = IdtpFrame::validate(&buffer[..size], None);
        assert!(matches!(validation_corrupted, Err(IdtpError::InvalidCrc)));
    }

    #[cfg(feature = "software_impl")]
    #[test]
    fn test_secure_mode_hmac() {
        let mut frame = IdtpFrame::new();
        frame.set_header(&IdtpHeader {
            mode: 2,
            ..IdtpHeader::new()
        });
        let _ = frame.set_payload_raw(b"SecretData", 0x80);

        let key = b"very_secure_key_32_bytes_length_";
        let mut buffer = [0u8; 256];
        let size = frame.pack(&mut buffer, Some(key)).unwrap();

        assert!(IdtpFrame::validate(&buffer[..size], Some(key)).is_ok());

        let bad_key = b"wrong_secure_key_32_bytes_length";
        assert!(matches!(
            IdtpFrame::validate(&buffer[..size], Some(bad_key)),
            Err(IdtpError::InvalidHMac)
        ));
    }

    // Mock payload for testing
    idtp_data! {
        pub struct TestPayload {
            pub value: f32,
        }
    }

    impl IdtpPayload for TestPayload {
        const TYPE_ID: u8 = 0x7F; // Use a distinct standard-range ID
    }

    #[test]
    fn test_set_payload_success() {
        let mut frame = IdtpFrame::new();
        let data = TestPayload { value: 42.42 };

        let result = frame.set_payload(&data);

        assert!(result.is_ok());

        // Verifying header sync.
        let header = frame.header();
        let payload_type = header.payload_type;
        let payload_size = header.payload_size;

        assert_eq!(payload_type, 0x7F);
        assert_eq!(payload_size, 4);

        // Verifying data integrity.
        let extracted: &TestPayload =
            &frame.payload::<TestPayload>().expect("Failed to extract");

        let value = extracted.value;
        assert_eq!(value, 42.42);
    }

    #[test]
    fn test_set_payload_updates_size_correctly() {
        let mut frame = IdtpFrame::new();

        // Testing with Imu6 (24 bytes).
        let imu_data = Imu6::default();
        frame.set_payload(&imu_data).unwrap();

        let header = frame.header();
        let payload_type = header.payload_type;
        let payload_size = header.payload_size;

        assert_eq!(payload_size, 24);
        assert_eq!(payload_type, 0x03);
    }

    // Creating a payload that is too large.
    idtp_data! {
        struct HugePayload([u8; 1000]); // 1000 > 972 bytes.
    }

    impl IdtpPayload for HugePayload {
        const TYPE_ID: u8 = 0x80;
    }

    #[test]
    fn test_payload_buffer_overflow() {
        let mut frame = IdtpFrame::new();

        let huge = HugePayload([0u8; 1000]);
        let result = frame.set_payload(&huge);

        assert!(matches!(result, Err(IdtpError::BufferOverflow)));
    }
}
