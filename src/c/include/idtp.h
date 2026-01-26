// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Inertial Measurement Unit Data Transfer Protocol (IDTP) - binary protocol
//! used for transferring IMU data. This protocol is suitable for usage in areas
//! of robotics, unmanned vehicles, wearable devices etc.

#ifndef IDTP_H
#define IDTP_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>
#include <string.h>

// Utils section.

/// Protocol errors enumeration.
enum IdtpResult {
    /// Success.
    IDTP_RESULT_OK,
    /// Buffer too short.
    IDTP_RESULT_BUFFER_UNDERFLOW,
    /// Incorrect CRC value.
    IDTP_RESULT_INVALID_CRC,
    /// Incorrect HMAC value.
    IDTP_RESULT_INVALID_HMAC,
    /// Incorrect HMAC key.
    IDTP_RESULT_INVALID_HMAC_KEY,
    /// Error to convert from/to bytes.
    IDTP_RESULT_PARSE_ERROR,
};

// Cryptographic functions section.

#ifdef SOFTWARE_IMPL

/// @brief Calculate software-based `CRC-8`.
///
/// @param [in] data given data to handle.
/// @param [in] size given size of the data in bytes.
/// @param [out] out given buffer to hold the result.
///
/// @return CRC-8 - in case of success.
/// @return Error - otherwise.
IdtpResult sw_crc8(const uint8_t *data, size_t size, uint8_t *out) {
    // TODO:
    return IDTP_RESULT_OK;
}

/// @brief Calculate software-based `CRC-32`.
///
/// @param [in] data given data to handle.
/// @param [in] size given size of the data in bytes.
/// @param [out] out given buffer to hold the result.
///
/// @return CRC-32 - in case of success.
/// @return Error - otherwise.
IdtpResult sw_crc32(const uint8_t *data, size_t size, uint8_t *out) {
    // TODO:
    return IDTP_RESULT_OK;
}

/// @brief Calculate software-based `HMAC-SHA256`.
///
/// @param [in] data given data to handle.
/// @param [in] size given size of the data in bytes.
/// @param [in] key - given `HMAC` key.
/// @param [in] key_size - given `HMAC` key size in bytes.
/// @param [out] out given buffer to hold the result.
///
/// @return HMAC-SHA256 calculation result - in case of success.
/// @return Error - otherwise.
IdtpResult sw_hmac(
    const uint8_t *data,
    size_t size,
    const uint8_t *key,
    size_t key_size,
    uint8_t *out
) {
    // TODO:
    return IDTP_RESULT_OK;
}

#endif // SOFTWARE_IMPL

// Header section.

/// Value to signal the start of a new IDTP frame.
const uint32_t IDTP_PREAMBLE = 0x50544449;

/// Current IDTP version.
/// For v2.0, the value is 0x20 (where 0x2 is Major and 0x0 is Minor).
const uint8_t IDTP_VERSION = 0x20;

/// IDTP operating mode.
enum IdtpMode {
    /// `IDTP-L (Lite mode)` - operating mode for minimum latency & overhead
    /// with general protection. SHOULD be used for trusted channels only.
    IDTP_MODE_LITE = 0x00,
    /// `IDTP-S (Safety mode)` - operating mode with balance between speed and
    /// integrity with more complex protection. SHOULD be used for
    /// most applications.
    IDTP_MODE_SAFETY = 0x01,
    /// `IDTP-SEC (Secure mode)` - operating mode with protection against
    /// data spoofing. MUST be used for data transmission over unsecured
    /// channels.
    IDTP_MODE_SECURE = 0x02,
};

/// IDTP header struct.
typedef struct {
    /// Value to signal the start of a new IDTP frame.
    uint32_t preamble;
    /// Timestamp represents the sensor-local time.
    uint32_t timestamp;
    /// Sequence number of IDTP frame sent.
    uint32_t sequence;
    /// Vendor-specific unique IMU device identifier.
    uint16_t device_id;
    /// Size of packet payload in bytes.
    uint16_t payload_size;
    /// Protocol version in format MAJOR.MINOR.
    uint8_t version;
    /// Protocol operating mode.
    uint8_t mode;
    /// Vendor-specific payload type. This is the way to distinguish different
    /// types of payload within one organization.
    uint8_t payload_type;
    /// Cyclic Redundancy Check - value to used for complex error detection.
    uint8_t crc;
} IdtpHeader;

/// Size of IDTP header in bytes.
const size_t IDTP_HEADER_SIZE = sizeof(IdtpHeader);

// Frame section.

/// IDTP frame max size in bytes. It includes size of IDTP header,
/// payload and packet trailer.
const size_t IDTP_FRAME_MAX_SIZE = 1024;

/// IDTP frame min size in bytes.
const size_t IDTP_FRAME_MIN_SIZE = IDTP_HEADER_SIZE;

/// IDTP network packet payload max size in bytes.
const size_t IDTP_PAYLOAD_MAX_SIZE = 972;

/// Inertial Measurement Unit Data Transfer Protocol frame struct.
typedef struct {
    /// IDTP frame header.
    IdtpHeader header;
    /// Value that containing IMU data.
    uint8_t payload[IDTP_PAYLOAD_MAX_SIZE];
    /// IDTP payload size in bytes.
    size_t payload_size;
} IdtpFrame;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IDTP_H

// Implementation section.
#ifdef IDTP_IMPLEMENTATION

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// @brief Construct new IDTP header.
///
/// @param [out] header given IDTP header object to fill.
void idtp_create_header(IdtpHeader *header) {
    memset(header, 0, IDTP_HEADER_SIZE);
    header->preamble = IDTP_PREAMBLE;
    header->version = IDTP_VERSION;
}

/// @brief Get frame trailer size.
///
/// @param [in] header given IDTP header to handle.
/// @return Trailer size in bytes.
inline size_t idtp_header_trailer_size(const IdtpHeader* header) {
    switch (header->mode) {
        case IDTP_MODE_LITE:
            return 0;
        case IDTP_MODE_SAFETY:
            return 4;
        case IDTP_MODE_SECURE:
            return 32;
        default:
            return 0;
    }
}

/// @brief Construct new IDTP frame.
///
/// @param [out] frame given IDTP frame object to fill.
void idtp_create_frame(IdtpFrame *frame) {
    memset(frame, 0, sizeof(IdtpFrame));
}

/// @brief Set IDTP header.
///
/// @param [out] frame given IDTP frame object to handle.
/// @param [in] header given IDTP header to set.
void idtp_frame_set_header(IdtpFrame *frame, const IdtpHeader *header) {
    frame->header = *header;
}

/// @brief Set IDTP payload.
///
/// @param [out] frame given IDTP frame object to handle.
/// @param [in] payload - given IDTP payload bytes to set.
/// @param payload_size
IdtpResult idtp_frame_set_payload(
    IdtpFrame *frame,
    const uint8_t *payload,
    const size_t payload_size
) {
    if (payload_size > IDTP_PAYLOAD_MAX_SIZE)
        return IDTP_RESULT_PARSE_ERROR;

    memcpy(frame->payload, payload, payload_size);
    frame->payload_size = payload_size;
    frame->header.payload_size = (uint16_t)payload_size;

    return IDTP_RESULT_OK;
}

/// @brief Alias for function for calculating software-based `CRC-8`.
///
/// @param [in] data given data to handle.
/// @param [in] size given size of the data in bytes.
/// @param [out] out given buffer to hold the result.
///
/// @return CRC-8 - in case of success.
/// @return Error - otherwise.
typedef IdtpResult (calc_crc8_fn)(
    const uint8_t *data,
    size_t size,
    uint8_t *out
);

/// @brief Alias for function for calculating software-based `CRC-32`.
///
/// @param [in] data given data to handle.
/// @param [in] size given size of the data in bytes.
/// @param [out] out given buffer to hold the result.
///
/// @return CRC-32 - in case of success.
/// @return Error - otherwise.
typedef IdtpResult (calc_crc32_fn)(
    const uint8_t *data,
    size_t size,
    uint8_t *out
);

/// @brief Alias for function for calculating software-based `HMAC-SHA256`.
///
/// @param [in] data given data to handle.
/// @param [in] size given size of the data in bytes.
/// @param [in] key - given `HMAC` key.
/// @param [in] key_size - given `HMAC` key size in bytes.
/// @param [out] out given buffer to hold the result.
///
/// @return HMAC-SHA256 calculation result - in case of success.
/// @return Error - otherwise.
typedef IdtpResult (calc_hmac_fn)(
    const uint8_t *data,
    size_t size,
    const uint8_t *key,
    size_t key_size,
    uint8_t *out
);

/// @brief Pack into raw IDTP frame with custom `CRC` and `HMAC` calculation.
/// Recommended to use if hardware acceleration for `CRC`/`HMAC` available.
///
/// @param [in] frame given IDTP frame object to handle.
/// @param [out] buffer given buffer to store IDTP frame bytes.
/// @param [in] buffer_size given buffer size in bytes.
/// @param [in] calc_crc8 given function with custom `CRC-8` calculation logic.
/// @param [in] calc_crc32 given function with custom `CRC-32` calculation logic.
/// @param [in] calc_hmac given function with custom `HMAC-SHA256` calculation logic.
/// @param [in] key given `HMAC` key.
/// @param [in] key_size given `HMAC` key size in bytes.
/// @param [out] frame_size given frame size in bytes.
///
/// @return Frame size in bytes - in case of success
/// @return Error otherwise.
IdtpResult idtp_frame_pack_with(
    const IdtpFrame *frame,
    uint8_t *buffer,
    const size_t buffer_size,
    calc_crc8_fn calc_crc8,
    calc_crc32_fn calc_crc32,
    calc_hmac_fn calc_hmac,
    const uint8_t *key,
    size_t key_size,
    size_t *frame_size
) {
    const size_t payload_size = frame->payload_size;
    const size_t trailer_size = idtp_header_trailer_size(&frame->header);
    const size_t expected_size = IDTP_FRAME_MIN_SIZE + payload_size + trailer_size;
    *frame_size = 0;

    if (buffer_size < expected_size) {
        return IDTP_RESULT_BUFFER_UNDERFLOW;
    }

    // Packing IDTP header & calculating the CRC-8.
    const size_t header_size = IDTP_HEADER_SIZE;
    memcpy(buffer, &frame->header, IDTP_HEADER_SIZE);
    calc_crc8(buffer, 18, &buffer[19]);

    // Packing payload.
    memcpy(buffer + IDTP_HEADER_SIZE, frame->payload, payload_size);

    // Packing frame trailer.
    const size_t data_size = header_size + payload_size;

    switch (frame->header.mode) {
        case IDTP_MODE_LITE:
            break;
        case IDTP_MODE_SAFETY:
            calc_crc32(buffer, data_size, buffer + data_size);
            break;
        case IDTP_MODE_SECURE:
            calc_hmac(buffer, data_size, key, key_size, buffer + data_size);
            break;
        default:
            break;
    }

    *frame_size = data_size + trailer_size;
    return IDTP_RESULT_OK;
}

/// @brief Validate IDTP frame integrity with custom `CRC` and `HMAC` calculation.
/// Recommended to use if hardware acceleration for `CRC`/`HMAC` available.
///
/// @param [in] frame given IDTP frame object to handle.
/// @param [out] buffer given buffer to store IDTP frame bytes.
/// @param [in] buffer_size given buffer size in bytes.
/// @param [in] calc_crc8 given function with custom `CRC-8` calculation logic.
/// @param [in] calc_crc32 given function with custom `CRC-32` calculation logic.
/// @param [in] calc_hmac given function with custom `HMAC-SHA256` calculation logic.
/// @param [in] key given `HMAC` key.
/// @param [in] key_size given `HMAC` key size in bytes.
///
/// @return IDTP_RESULT_OK - in case of success
/// @return Error otherwise.
IdtpResult idtp_frame_validate_with(
    const IdtpFrame *frame,
    uint8_t *buffer,
    const size_t buffer_size,
    calc_crc8_fn calc_crc8,
    calc_crc32_fn calc_crc32,
    calc_hmac_fn calc_hmac,
    const uint8_t *key,
    size_t key_size
) {
    const size_t header_size = IDTP_HEADER_SIZE;

    if (buffer_size < header_size)
        return IDTP_RESULT_BUFFER_UNDERFLOW;

    // Checking CRC-8 of IDTP header.
    const uint8_t received_crc8 = buffer[19];
    uint8_t computed_crc8 = 0;
    calc_crc8(buffer, 18, &computed_crc8);

    if (received_crc8 != computed_crc8)
        return IDTP_RESULT_INVALID_CRC;

    // Checking size.
    const IdtpHeader *header = (const IdtpHeader*)buffer;

    const size_t payload_size = header->payload_size;
    const size_t trailer_size = idtp_header_trailer_size(header);
    const size_t data_size = header_size + payload_size;
    const size_t expected_size = data_size + trailer_size;

    if (buffer_size < expected_size)
        return IDTP_RESULT_BUFFER_UNDERFLOW;

    // Checking frame trailer.
    switch (frame->header.mode) {
        case IDTP_MODE_LITE:
            break;

        case IDTP_MODE_SAFETY: {
            uint32_t computed_crc32 = 0;
            calc_crc32(buffer, data_size, (uint8_t*)&computed_crc32);

            uint32_t received_crc32 = *(buffer + data_size);

            if (computed_crc32 != received_crc32)
                return IDTP_RESULT_INVALID_CRC;
            break;
        }

        case IDTP_MODE_SECURE: {
            uint8_t computed_hmac[32] = {};
            calc_hmac(buffer, data_size, key, key_size, (uint8_t*)&computed_hmac);

            const uint8_t *received_hmac = buffer + data_size;

            if (memcmp(received_hmac, computed_hmac, 32) != 0)
                return IDTP_RESULT_INVALID_HMAC;

            break;
        }
        default:
            return IDTP_RESULT_INVALID_CRC;
    }

    return IDTP_RESULT_OK;
}

/// @brief Convert byte slice into IDTP frame.
///
/// @param [in] buffer given buffer to handle.
/// @param [in] size given size of the buffer in bytes.
/// @param [out] out given frame to hold the result.
///
/// @return IDTP frame struct from byte slice - in case of success.
/// @return Error otherwise.
IdtpResult idtp_frame_from_bytes(const uint8_t *buffer, size_t size, IdtpFrame *out) {
    const size_t header_size = IDTP_HEADER_SIZE;

    if (size < header_size)
        return IDTP_RESULT_BUFFER_UNDERFLOW;

    IdtpHeader *header = (IdtpHeader*)(buffer + header_size);

    IdtpFrame frame = {};
    idtp_create_frame(&frame);

    frame.header = *header;
    frame.payload_size = header->payload_size;

    const size_t trailer_size = idtp_header_trailer_size(header);
    const size_t expected_size = header_size + frame.payload_size + trailer_size;

    if (size < expected_size)
        return IDTP_RESULT_BUFFER_UNDERFLOW;

    memcpy(frame.payload, buffer + header_size, frame.payload_size);
    *out = frame;

    return IDTP_RESULT_OK;
}

#ifdef SOFTWARE_IMPL
/// @brief Pack into raw IDTP frame.
/// `CRC` & `HMAC` calculation is software-based.
///
/// @param [in] frame given IDTP frame object to handle.
/// @param [out] buffer given buffer to store IDTP frame bytes.
/// @param [in] buffer_size given buffer size in bytes.
/// @param [in] key given `HMAC` key.
/// @param [in] key_size given `HMAC` key size in bytes.
/// @param [out] frame_size given frame size in bytes.
///
/// @return Frame size in bytes - in case of success.
/// @return Error otherwise.
IdtpResult idtp_frame_pack(
    const IdtpFrame *frame,
    uint8_t *buffer,
    const size_t buffer_size,
    const uint8_t *key,
    size_t key_size,
    size_t *frame_size
) {
    idtp_frame_pack_with(
        frame,
        buffer,
        buffer_size,
        sw_crc8,
        sw_crc32,
        sw_hmac,
        key,
        key_size,
        frame_size
    );

    return IDTP_RESULT_OK;
}

/// @brief Validate IDTP frame integrity. `CRC` & `HMAC` calculation
/// is software-based.
///
/// @param [in] frame given IDTP frame object to handle.
/// @param [out] buffer given buffer to store IDTP frame bytes.
/// @param [in] buffer_size given buffer size in bytes.
/// @param [in] key given `HMAC` key.
/// @param [in] key_size given `HMAC` key size in bytes.
///
/// @return Frame size in bytes - in case of success.
/// @return Error otherwise.
IdtpResult idtp_frame_validate(
    const IdtpFrame *frame,
    uint8_t *buffer,
    const size_t buffer_size,
    const uint8_t *key,
    size_t key_size
) {
    idtp_frame_validate_with(
        frame,
        buffer,
        buffer_size,
        sw_crc8,
        sw_crc32,
        sw_hmac,
        key,
        key_size
    );

    return IDTP_RESULT_OK;
}

#endif // SOFTWARE_IMPL

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IDTP_IMPLEMENTATION
