// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! IDTP implementation tests.

#include <gtest/gtest.h>
#include <idtp/idtp.h>

/// @brief Convert to printable character.
///
/// @param [in] ch given character to convert.
/// @return Character to print.
inline int32_t to_print(const int32_t ch) {
    return ch > 31 && ch < 127 ? ch : '.';
}

/// @brief Print IDTP header.
///
/// @param [in] header given IDTP header to print.
void print_idtp_header(const IdtpHeader *header) {
    const auto *bytes = reinterpret_cast<const uint8_t*>(header);

    putchar('|');
    for (size_t i = 0; i < IDTP_HEADER_SIZE; i++)
        printf("%02x ", bytes[i]);
    puts("\b|");

    putchar('|');
    for (size_t i = 0; i < IDTP_HEADER_SIZE; i++) {
        const char ch = static_cast<char>(to_print(bytes[i]));
        printf("%c", ch);
    }
    puts("|");
}

TEST(IdtpTest, Sizes) {
    EXPECT_EQ(IDTP_PREAMBLE_SIZE, 4);
    EXPECT_EQ(IDTP_TRAILER_SIZE, 4);
    EXPECT_EQ(IDTP_HEADER_SIZE, sizeof(IdtpHeader));
}

TEST(IdtpTest, IdtpHeaderCreation) {
    const IdtpHeader header = idtp_header_create();
    EXPECT_TRUE(memcmp(header.preamble, IDTP_PREAMBLE, IDTP_PREAMBLE_SIZE) == 0);
}

TEST(IdtpTest, IdtpHeaderConvertEndian) {
    const uint8_t BYTES[IDTP_HEADER_SIZE] = {
        0x49, 0x44, 0x54, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
        0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    IdtpHeader header = idtp_header_from_bytes(BYTES);
    EXPECT_EQ(header.checksum, 0x1234);

    idtp_header_convert_endian(&header);
    EXPECT_EQ(header.checksum, 0x3412);
}

TEST(IdtpHeaderTest, ConvertEndianSwapsCorrectly) {
    IdtpHeader header;
    header.checksum = 0x1234;
    idtp_header_convert_endian(&header);

    EXPECT_EQ(header.checksum, 0x3412);
}

TEST(IdtpHeaderTest, IdtpHeaderFromBytes) {
    const uint8_t BYTES[IDTP_HEADER_SIZE] = {
        0x49, 0x44, 0x54, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
        0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    const IdtpHeader header = idtp_header_from_bytes(BYTES);
    EXPECT_EQ(header.checksum, 0x1234);
}
