// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP usage example.

#include <idtp/idtp.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/// Example IDTP payload struct.
typedef struct PACKED {
    /// The value of the projection of the acceleration vector
    /// along the X axis (m/s^2).
    float acc_x;
    /// The value of the projection of the acceleration vector
    /// along the Y axis (m/s^2).
    float acc_y;
    /// The value of the projection of the acceleration vector
    /// along the Z axis (m/s^2).
    float acc_z;
    /// Angular velocity along the X axis (rad/s).
    float gyr_x;
    /// Angular velocity along the Y axis (rad/s).
    float gyr_y;
    /// Angular velocity along the Z axis (rad/s).
    float gyr_z;
} Payload;

/// Example payload size in bytes.
#define PAYLOAD_SIZE (sizeof(Payload))

/// @brief Calculate checksum for network packet.
///
/// @return Checksum for network packet.
uint16_t calculate_checksum(void) {
    // Implement this function suitable for your needs.
    return 0x1234;
}

int32_t main(void) {
    // 1) IDTP usage example - creation of raw IDTP network packet.
    // Fill custom payload with IMU sensors data.
    const Payload payload = (Payload) {
        .acc_x = 0.001f,
        .acc_y = 0.002f,
        .acc_z = 0.003f,
        .gyr_x = 0.004f,
        .gyr_y = 0.005f,
        .gyr_z = 0.006f,
    };

    const uint8_t *payload_bytes = (const uint8_t *)&payload;

    // Fill IDTP header.
    // Prefer creating IdtpHeader instance using new() method because there
    // will be no need for you to set preamble and version manually.
    IdtpHeader header = idtp_header_create();

    // Handling IDTP_MODE_SAFETY is almost the same,
    // but header.crc field should be calculated.
    header.mode = IDTP_MODE_NORMAL;
    header.device_id = 0xABCD;
    header.checksum = calculate_checksum();
    header.timestamp = 0;
    header.sequence = 0;
    header.crc = 0;
    header.payload_size = sizeof(Payload);
    header.payload_type = 0;


    // Create IDTP packet manager instance.
    IdtpFrame frame = idtp_frame_create();

    idtp_frame_set_header(&frame, &header);
    idtp_frame_set_payload(&frame, payload_bytes, PAYLOAD_SIZE);

    // Get raw network packet bytes.
    const size_t PACKET_SIZE = IDTP_PACKET_MIN_SIZE + sizeof(Payload);
    uint8_t raw_packet[PACKET_SIZE];
    memset(raw_packet, 0, PACKET_SIZE);

    idtp_frame_pack(&frame, raw_packet);
    // Handle this raw packet...

    // 2) IDTP usage example - parsing IDTP from raw network packet.

    const IdtpFrame frame2 = idtp_frame_from_bytes(raw_packet, PACKET_SIZE);
    const IdtpHeader header2 = frame2.header;

    uint8_t preamble[IDTP_PREAMBLE_SIZE + 1];
    memcpy(preamble, header2.preamble, IDTP_PREAMBLE_SIZE);
    preamble[IDTP_PREAMBLE_SIZE] = '\0';

    printf("Header preamble: %s\n", (const char *)preamble);

    uint8_t payload_bytes2[PAYLOAD_SIZE];
    memset(payload_bytes2, 0, PAYLOAD_SIZE);
    memcpy(payload_bytes2, frame.payload, PAYLOAD_SIZE);

    const Payload payload2 = *(Payload *)payload_bytes2;

    printf("Payload size: %llu\n", sizeof(payload));
    puts("Payload:");
    printf("acc_x: %lf\n", payload2.acc_x);
    printf("acc_y: %lf\n", payload2.acc_y);
    printf("acc_z: %lf\n", payload2.acc_z);
    printf("gyr_x: %lf\n", payload2.gyr_x);
    printf("gyr_y: %lf\n", payload2.gyr_y);
    printf("gyr_z: %lf\n", payload2.gyr_z);

    return 0;
}
