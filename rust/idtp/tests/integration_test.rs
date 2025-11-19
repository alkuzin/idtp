// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP implementation integration tests.

extern crate idtp;

#[cfg(test)]
mod tests {
    use idtp::*;

    #[test]
    fn test_idtp_version_as_bytes() {
        let version = Version {
            major: 0x00,
            minor: 0x00,
            patch: 0x00,
        };
        let bytes = version.as_bytes();

        assert_eq!(bytes, [0x00, 0x00, 0x00]);

        let version = Version {
            major: 0x01,
            minor: 0x02,
            patch: 0x03,
        };
        let bytes = version.as_bytes();

        assert_eq!(bytes, [0x01, 0x02, 0x03]);

        let version = Version {
            major: 0xff,
            minor: 0xff,
            patch: 0xff,
        };
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
        header.version = Version {
            major: 0,
            minor: 0,
            patch: 0,
        };
        header.checksum = 0x1234;

        let header_bytes = header.as_bytes_be();

        println!("bytes: {:?}", bytes);
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
}
