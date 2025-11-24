// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP implementation integration tests.

extern crate idtp;

#[cfg(test)]
mod tests {
    use super::*;
    use core::{mem, ptr};
    use idtp::*;

    #[test]
    fn test_idtp_version_as_bytes() {
        let version = Version::new(0x0A, 0x0B, 0x0C);
        let bytes = version.as_bytes();

        assert_eq!(bytes, [0x0A, 0x0B, 0x0C]);

        let version = Version::new(0x01, 0x02, 0x03);
        let bytes = version.as_bytes();

        assert_eq!(bytes, [0x01, 0x02, 0x03]);

        let version = Version::new(0xff, 0xff, 0xff);
        let bytes = version.as_bytes();

        assert_eq!(bytes, [0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_sizes() {
        assert_eq!(IDTP_PREAMBLE_SIZE, 4);
        assert_eq!(IDTP_TRAILER_SIZE, 4);
        assert_eq!(IDTP_HEADER_SIZE, 32);
        assert_eq!(IDTP_VERSION_SIZE, 3);
    }

    #[test]
    fn test_idtp_header_creation() {
        let header = IdtpHeader::new();
        println!("{header:#X?}");
        println!("Header size: {} bytes", size_of_val(&header));
        assert!(header.preamble.eq(IDTP_PREAMBLE));
    }

    #[test]
    fn test_idtp_header_as_bytes_be_method() {
        let bytes: [u8; IDTP_HEADER_SIZE] = [
            0x49, 0x44, 0x54, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
            0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut header = IdtpHeader::new();
        header.version = Version::new(0, 0, 0);
        header.checksum = 0x1234;

        let header_bytes = header.as_bytes_be();

        println!("bytes:        {:?}", bytes);
        println!("header_bytes: {:?}", header_bytes);

        assert_eq!(bytes, header_bytes);
    }

    #[test]
    fn test_idtp_header_from_bytes_method() {
        let bytes: [u8; _] = [
            0x49, 0x44, 0x54, 0x50, 0x01, 0x02, 0x03, 0x01, 0x05, 0x06, 0x12,
            0x34, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x01, 0x02, 0x03, 0x04,
        ];

        let header = IdtpHeader::from(&bytes[..]);
        let header_bytes = header.as_bytes_be();

        assert_eq!(bytes, header_bytes);
    }

    #[test]
    fn test_idtp_creation() {
        let idtp = Idtp::new();
        println!("IDTP packet size: {} bytes", size_of_val(&idtp));
    }

    // -----------------------------------------------------------------------

    #[derive(Debug, Default, Clone, Copy, PartialEq)]
    #[repr(C, packed)]
    pub struct TestPayload {
        acc_x: f32,
        acc_y: f32,
        acc_z: f32,
        gyr_x: f32,
        gyr_y: f32,
        gyr_z: f32,
    }

    impl TestPayload {
        fn as_bytes(&self) -> [u8; std::mem::size_of::<Self>()] {
            unsafe { mem::transmute::<Self, [u8; size_of::<Self>()]>(*self) }
        }

        fn from_bytes(bytes: &[u8]) -> Self {
            assert_eq!(bytes.len(), mem::size_of::<Self>());
            unsafe { ptr::read(bytes.as_ptr() as *const Self) }
        }
    }

    #[test]
    fn test_payload_serialization_and_idtp() {
        let payload = TestPayload {
            acc_x: 1.1,
            acc_y: 2.2,
            acc_z: 3.3,
            gyr_x: 4.4,
            gyr_y: 5.5,
            gyr_z: 6.6,
        };

        let payload_bytes = payload.as_bytes();

        let mut idtp = Idtp::new();
        idtp.set_payload(&payload_bytes);

        let idtp_payload = idtp.payload();

        println!("IDTP payload:  {idtp_payload:?}");
        println!("payload_bytes: {payload_bytes:?}");
        assert_eq!(idtp_payload, payload_bytes);

        let reconstructed_payload = TestPayload::from_bytes(idtp_payload);
        println!("Reconstructed payload: {reconstructed_payload:#?}");
        assert_eq!(payload, reconstructed_payload);
    }

    #[test]
    fn test_pack_with_payload() {
        let payload_struct = TestPayload {
            acc_x: 1.1,
            acc_y: 2.2,
            acc_z: 3.3,
            gyr_x: 4.4,
            gyr_y: 5.5,
            gyr_z: 6.6,
        };

        let payload_bytes = payload_struct.as_bytes();
        println!("Payload bytes: {payload_bytes:?}");

        let mut idtp = Idtp::new();
        idtp.set_payload(&payload_bytes);

        println!("Idtp: {idtp:?}");

        let mut buffer = [0u8; 64];

        let result = idtp.pack(&mut buffer);

        println!("Result: {result:?}");
        assert!(result.is_ok());

        let payload_start = IDTP_HEADER_SIZE;
        let payload_end = payload_start + payload_bytes.len();
        assert_eq!(&buffer[payload_start..payload_end], &payload_bytes);

        let trailer_start = payload_end;
        let trailer_end = trailer_start + IDTP_TRAILER_SIZE;
        assert_eq!(&buffer[trailer_start..trailer_end], IDTP_TRAILER);
    }

    #[test]
    fn test_pack_with_small_buffer() {
        let payload_struct = TestPayload {
            acc_x: 1.1,
            acc_y: 2.2,
            acc_z: 3.3,
            gyr_x: 4.4,
            gyr_y: 5.5,
            gyr_z: 6.6,
        };

        let payload_bytes = payload_struct.as_bytes();

        let mut idtp = Idtp::new();
        idtp.set_payload(&payload_bytes);

        let mut small_buffer = vec![0u8; IDTP_PACKET_MIN_SIZE - 1];

        let result = idtp.pack(&mut small_buffer);
        assert!(result.is_err());
    }
}
