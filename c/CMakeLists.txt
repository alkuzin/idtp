# SPDX-License-Identifier: Apache-2.0.
# Copyright (C) 2025-present idtp project and contributors.

cmake_minimum_required(VERSION 3.10.0)

# Project name.
project(idtp)

set(CMAKE_C_STANDARD 17)          # Using C standard.
set(CMAKE_C_STANDARD_REQUIRED ON) # Enforce the standard.
set(CMAKE_C_EXTENSIONS OFF)       # Disable compiler-specific extensions.

# Main paths.
set(INCLUDE_DIR   ${CMAKE_SOURCE_DIR}/include)
set(SRC_DIR       ${CMAKE_SOURCE_DIR}/src)
set(TESTS_DIR     ${CMAKE_SOURCE_DIR}/tests)
set(EXAMPLES_DIR  ${CMAKE_SOURCE_DIR}/../examples/c)

# Project source files.
set(SRCS "${SRC_DIR}/idtp_header.c" "${SRC_DIR}/idtp.c" "${SRC_DIR}/utils.c")

# Static library from C sources.
add_library(${PROJECT_NAME} STATIC ${SRCS})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})

# Compiler flags.
set(CFLAGS -Wall -Werror -Wextra -Wpedantic -g -O2)
target_compile_options(${PROJECT_NAME} PRIVATE ${CFLAGS})

# Include directories.
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR})

# -----------------------------------------------------------------------------

enable_testing()

# C++ standard for tests.
set(CMAKE_CXX_STANDARD 17)          # Using C++ standard.
set(CMAKE_CXX_STANDARD_REQUIRED ON) # Enforce the standard.
set(CMAKE_CXX_EXTENSIONS OFF)       # Disable compiler-specific extensions.

# Find GTest package.
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

set(TESTS_EXE_NAME idtp_tests)
add_executable(${TESTS_EXE_NAME})

# Project test source files.
target_sources(${TESTS_EXE_NAME} PRIVATE
        "${TESTS_DIR}/test_idtp_header.cc"
        "${TESTS_DIR}/test_idtp_frame.cc"
)

# Link libraries to tests.
target_link_libraries(${TESTS_EXE_NAME} PRIVATE
        GTest::GTest GTest::Main pthread
        ${PROJECT_NAME}
)

# Include project directories for tests.
target_include_directories(${TESTS_EXE_NAME} PRIVATE ${INCLUDE_DIR})
add_test(NAME ${TESTS_EXE_NAME} COMMAND ${TESTS_EXE_NAME})

# -----------------------------------------------------------------------------

set(EXAMPLE_EXE_NAME idtp_example)
add_executable(${EXAMPLE_EXE_NAME})

# Project test source files.
target_sources(${EXAMPLE_EXE_NAME} PRIVATE "${EXAMPLES_DIR}/idtp_example.c")
target_compile_options(${EXAMPLE_EXE_NAME} PRIVATE ${CFLAGS})

# Include project directories for examples.
target_include_directories(${EXAMPLE_EXE_NAME} PRIVATE ${INCLUDE_DIR})

# Link libraries to examples.
target_link_libraries(${EXAMPLE_EXE_NAME} PRIVATE ${PROJECT_NAME})
