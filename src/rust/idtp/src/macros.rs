// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2025-present idtp project and contributors.

//! Macros utilities.

/// Apply some traits for IDTP struct declarations.
#[macro_export]
macro_rules! idtp_data {
    ($($item:item)*) => {
        $(
            #[derive(
                Debug, Default, Clone, Copy,
                IntoBytes, FromBytes, Immutable, KnownLayout,
            )]
            #[repr(C, packed)]
            $item
        )*
    };
}
