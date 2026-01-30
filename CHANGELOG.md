# Changelog

All notable changes to this project will be documented in this file.

---

## IDTP v2.1.0

### Added

- **Standard Payload Types**: Defined types `0x00` through `0x06` for common IMU configurations (`Imu3Acc`, `Imu3Gyr`, `Imu3Mag`, `Imu6`, `Imu9`, `Imu10`, `ImuQuat`).
- **Standard Units**: Mandated measurement units for all standard payloads: *m/s^2* for acceleration, *rad/s* for angular velocity, *μT* for magnetic field, and *Pa* for pressure.
- **Coordinate System**: Specified the `Right-Hand Rule (RHR)` and `ENU (East-North-Up)` convention for all standard payloads.

### Changed

- **Payload Type Range**: Formalized the split between Standard (`0x00-0x7F`) and Vendor-Specific (`0x80-0xFF`) ranges.

## IDTP v2.0.0

### Added

- **New Modes**: Introduced `IDTP-L` (Lite), `IDTP-S` (Safety), and `IDTP-SEC` (Secure).
- **Security**: Added `HMAC-SHA256` support for the Secure mode.
- **Integrity**: Added `CRC-8-AUTOSAR` for mandatory header protection.
- **Alignment**: Header is now 20-byte fixed and 4-byte aligned for zero-copy parsing.

### Changed

- **Breaking Change**: Changed Endianness from Big-Endian to **Little-Endian** for native ARM/RISC-V support.
- **Breaking Change**: Redesigned header structure (size reduced from 32 bytes to 20 bytes).
- **Trailer**: Removed fixed 4-byte trailer; now size depends on the operating mode (0, 4, or 32 bytes).

### Removed

- Removed fixed `PTDI` end-marker to reduce overhead.

## IDTP v1.0.0

- Initial release of IDTP (legacy Big-Endian version).
