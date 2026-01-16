# Inertial Measurement Unit Data Transfer Protocol (IDTP) Specification v2.0.0

## Table of Contents

- [1. Abstract](#1-abstract)
- [2. Terminology](#2-terminology)
- [3. Frame Architecture](#3-frame-architecture)
- [3.1. Format](#31-format)
- [3.2. Maximum Transmission Unit (MTU)](#32-maximum-transmission-unit-mtu)
- [4. IDTP Header](#4-idtp-header)
- [4.1. Header Structure](#41-header-structure)
- [4.2. Byte Order](#42-byte-order)
- [4.3. Sections Description](#43-sections-description)
- [4.4. Protocol Operating Mode](#44-protocol-operating-mode)
- [5. Error Handling](#5-error-handling)
- [6. Security](#6-security)
- [6.1. General Threats and Protection Methods](#61-general-threats-and-protection-methods)

---

## 1. Abstract

**Inertial Measurement Unit Data Transfer Protocol (IDTP)** — it is a binary application-layer (L7) protocol that can be used by different transport layers, such as SPI, I2C, UART, UDP or TCP.
This protocol designed for transferring navigation data in systems with strict real-time requirements (unmanned vehicles, robotics).

IDTP solves the problem of unifying data exchange between different types of **Inertial Measurement Units (IMU)** and host systems, providing a multi-level data integrity checking.

## 2. Terminology

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",  "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 3. Frame Architecture

## 3.1. Format

Frame - is a data exchange unit of IDTP.
It consists of three sections:

| Section | Size (Bytes) | Description          |
|---------|--------------|----------------------|
| Header  | 20           | Protocol metadata    |
| Payload | 0 - 972      | Vendor-specific data |
| Trailer | 0 - 32       | Frame end-marker     |
|         |              |                      |

![IDTP Frame Structure](../res/idtp_v2.0.0_frame.png)

## 3.2. Maximum Transmission Unit (MTU)

IDTP frame size **MUST NOT** exceed 1024 bytes.
This max size was chosen in order to fit well within the common Ethernet MTU (1500 bytes) avoiding link‑level fragmentation that can lead to increased latency.

## 4. IDTP header

## 4.1. Header Structure

| Offset | Field        | Type  |
|--------|--------------|-------|
| 0      | preamble     | u32   |
| 4      | timestamp    | u32   |
| 8      | sequence     | u32   |
| 12     | device_id    | u16   |
| 14     | payload_size | u16   |
| 16     | version      | u8    |
| 17     | mode         | u8    |
| 18     | payload_type | u8    |
| 19     | crc          | u8    |

![IDTP Header Structure](../res/idtp_v2.0.0_header.png)

## 4.2. Byte Order

All multibyte fields **MUST** be transmitted in `Little-Endian` format.

## 4.3. Sections Description

- `preamble` - Value to signal the start of a new IDTP frame. **MUST** be `0x50544449` - `IDTP` in ASCII.
- `timestamp` - Timestamp represents the sensor-local time. **RECOMMENDED** to be in microseconds.
- `sequence` - Sequence number of IDTP frame sent.
- `device_id` - Vendor-specific unique IMU device identifier.
- `payload_size` - Size of payload in bytes. **MUST NOT** exceed the limit in 972 bytes.
- `version` - Protocol version. For v2.0, the value **MUST** be `0x20` (where `0x2` is Major and `0x0` is Minor).
- `mode` - Protocol operating mode.
- `payload_type` - Vendor-specific payload type. This is the way to distinguish different types of payload within one organization.
- `crc` - Cyclic Redundancy Check - value to used for complex error detection. **RECOMMENDED** to use `CRC-8-AUTOSAR` with `0x2F` polynomial. **MUST** be calculated over the first 19 bytes of the header (offsets 0 to 18).

## 4.4. Protocol Operating Mode

- `IDTP-L (Lite mode)` [`0x00`] - operating mode for minimum latency & overhead with general protection. **SHOULD** be used for trusted channels only. Error detection **MUST** be provided by `CRC-8` only.
Frame trailer size **MUST** be 0 bytes.

- `IDTP-S (Safety mode)` [`0x01`] - operating mode with balance between speed and integrity with more complex protection. **SHOULD** be used for most applications. Error detection provided by `CRC-8` for header and `CRC-32` for the whole frame. CRC is effective at detecting common error patterns, including single-bit errors, burst errors, and many random errors. The effectiveness depends on the choice of generator polynomial.
Frame trailer size **MUST** be 4 bytes and **MUST** hold `CRC-32` value. **RECOMMENDED** to use `CRC-32-AUTOSAR` with `0xF4ACFB13` polynomial.
`CRC-32` is calculated for the entire frame, including header and payload, but excluding the trailer section itself.

- `IDTP-SEC (Secure mode)` [`0x02`] - operating mode with protection against data spoofing. **MUST** be used for data transmission over unsecured channels. Error detection provided by `CRC-8` for header and `HMAC-SHA256` for the whole frame. In order to operate, a shared secret key (pre-shared key) **MUST** be present on the sender and the host.
Frame trailer size **MUST** be 32 bytes and **MUST** hold `HMAC` value.
`HMAC` is calculated for the entire frame, including header and payload, but excluding the trailer section itself.

## 5. Error Handling

If header `crc` fails, the receiver **MUST** discard the frame immediately and **SHOULD NOT** attempt to parse `payload_size` to find the next frame, but rather scan for the next `preamble`.

## 6. Security

IDTP designed to transfer critical data.

## 6.1. General Threats And Protection Methods

- `Data spoofing`: When used for data transmission over unsecured channels, `Secure mode` is **REQUIRED**.
- `Integrity`: When used in environments with strong noise, `Safety mode` is **REQUIRED**.
- `Replay attack`: The sequence field **MUST** be verified by the receiver. Packets with a sequence number less than or equal to the last successfully received **SHOULD** be discarded.
