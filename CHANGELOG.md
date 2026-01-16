# Changelog

All notable changes to this project will be documented in this file.

---

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
