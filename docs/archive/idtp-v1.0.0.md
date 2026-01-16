# Inertial Measurement Unit Data Transfer Protocol (IDTP) Specification v1.0.0

## 1. Abstract

Inertial Measurement Unit Data Transfer Protocol (IDTP) —
it is a binary application-layer (L7) protocol that can be used by different transport layers, such as SPI, I2C, UART, UDP or TCP.
This protocol designed for transfering navigation data in systems with strict real-time requirements (unmanned vehicles, robotics).

IDTP solves the problem of unifying data exchange between different types of inertial measurement units (IMU) and host systems, providing a multi-level data integrity checking.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 3. Frame architecture

## 3.1. Format

Frame - is a data exchange unit of IDTP.
It consists of three sections:

| Section | Size (Bytes) | Description          |
|---------|--------------|----------------------|
| Header  | 32           | Protocol metadata    |
| Payload | 0 - 988      | Vendor-specific data |
| Trailer | 32           | Frame end-marker     |
|         |              |                      |

![IDTP Frame Structure](../../res/archive/idtp_v1.0.0_frame.png)

## 3.2. Maximum Transmission Unit (MTU)

IDTP frame size MUST NOT exceed 1024 bytes.
This max size was chosen in order to fit well within the common Ethernet MTU (1500 bytes) avoiding link‑level fragmentation that can lead to increased latency.

## 4. IDTP header

## 4.1. Header structure

| Offset | Field        | Type  |
|--------|--------------|-------|
| 0      | preamble     | u8[4] |
| 4      | version      | u8[3] |
| 7      | mode         | u8    |
| 8      | device_id    | u16   |
| 10     | checksum     | u16   |
| 12     | timestamp    | u32   |
| 16     | sequence     | u32   |
| 20     | crc          | u32   |
| 24     | payload_size | u32   |
| 28     | payload_type | u8    |
| 29     | reserved     | u8[3] |
|        |              |       |

![IDTP Header Structure](../../res/archive/idtp_v1.0.0_header.png)

## 4.2. Byte order

All multibyte fields MUST be transmitted in Big-Endian format.

## 4.3. Sections description

- `preamble` - Value to signal the start of a new IDTP packet.
MUST be [`'I'`, `'D'`, `'T'`, `'P'`] ([`0x49`, `0x44`, `0x54`, `0x50`] in raw bytes)
- `version` - Protocol version in format MAJOR.MINOR.PATCH (see [Semantic Versioning](https://semver.org/)).
- `mode` - Protocol operating mode.
  - `IDTP-N (Normal mode)` [`0x00`] - operating mode with general protection. Error detection MUST be provided by checksum only. Detects simple errors like single-bit errors and some small burst errors. However, it's less effective against more complex or patterned errors.
    Only `checksum` field of IDTP header MUST be used. The `crc` field MUST be unused and filled with zeros.
  - `IDTP-S (Safety mode)` [`0x01`] - operating mode with more complex protection. Error detection provided by checksum and CRC (Cyclic Redundancy Check). CRC is effective at detecting common error patterns, including single-bit errors, burst errors, and many random errors. The effectiveness depends on the choice of generator polynomial.
  Both `checksum` and `crc` fields of IDTP header MUST be used. RECOMMENDED to use `CRC-32` with `0x04C11DB7` polynomial that used for Ethernet.
  - `Unknown mode` [`0xff`] - SHOULD be used as placeholder. No special handling required.
- `device_id` - Vendor-specific unique IMU device identifier.
- `checksum` - Value used for simple error detection. SHOULD be calculated as sum of bytes (excluding checksum and crc fields themselves).
- `timestamp` - Timestamp from the IMU's MCU internal clock. RECOMMENDED to be in milliseconds.
- `sequence` - Sequence number of IDTP packet sent.
- `crc` - Cyclic Redundancy Check - value to used for complex error detection.
- `payload_size` - Size of packet payload in bytes. MUST NOT exceed the limit in 988 bytes.
- `payload_type` - Vendor-specific packet payload type. This is the way to distinguish different types of payload within one organization.
- `reserved` - Reserved field. MUST be filled with zeros.

## 5. Security

IDTP designed to transfer critical data.

## 5.1. General threats and protection methods:

- `Data spoofing`: In order to protect against unauthorized modification of data in the payload section of IDTP frame, it is RECOMMENDED to use asymmetric RSA encryption for session key exchange and symmetric AES-128 encryption for streaming data.
- `Integrity`: When used in environments with strong noise, `Safety mode` is REQUIRED.
- `Replay attack`: The sequence field MUST be verified by the receiver. Packets with a sequence number less than or equal to the last successfully received SHOULD be discarded.
