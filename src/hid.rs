// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(dead_code)]

fn short_item(typ: u8, tag: u8, data: u32) -> Vec<u8> {
    let b0 = |size: u8| {
        assert!(size <= 0b11);
        assert!(typ <= 0b10);
        assert!(tag <= 0b1111);
        size | (typ << 2) | (tag << 4)
    };
    let bytes = data.to_le_bytes();
    #[allow(ellipsis_inclusive_range_patterns)]
    match data {
        0 => vec![b0(0b00)],
        1...0xff => vec![b0(0b01), bytes[0]],
        0x0100...0xffff => vec![b0(0b10), bytes[0], bytes[1]],
        _ => vec![b0(0b11), bytes[0], bytes[1], bytes[2], bytes[3]],
    }
}

const MAIN: u8 = 0b00;
const GLOBAL: u8 = 0b01;
const LOCAL: u8 = 0b10;

// Usage pages
pub const GENERIC_DESKTOP: u16 = 0x01;
pub const KEY_CODES: u16 = 0x07;
pub const LEDS: u16 = 0x08;
pub const FIDO: u16 = 0xF1D0;

macro_rules! define_item {
    ($name:ident, $kind:ident, $tag:expr, $typ:ty) => {
        pub fn $name(data: $typ) -> Vec<u8> {
            short_item($kind, $tag, data as u32)
        }
    };
}

define_item!(usage_page, GLOBAL, 0b0000, u16);
define_item!(logical_minimum, GLOBAL, 0b0001, u32);
define_item!(logical_maximum, GLOBAL, 0b0010, u32);
define_item!(report_size, GLOBAL, 0b0111, u32);
define_item!(report_count, GLOBAL, 0b1001, u32);

#[allow(dead_code)]
pub const KEYBOARD: u16 = 0x06;

pub const CTAPHID: u16 = 0x1;
pub const FIDO_USAGE_DATA_IN: u16 = 0x20;
pub const FIDO_USAGE_DATA_OUT: u16 = 0x21;

define_item!(usage, LOCAL, 0b0000, u16);
//define_item!(usage_minimum, LOCAL, 0b0001, u32);
//define_item!(usage_maximum, LOCAL, 0b0010, u32);

pub const APPLICATION: u8 = 0x01;

define_item!(collection, MAIN, 0b1010, u8);

pub fn end_collection() -> Vec<u8> {
    short_item(MAIN, 0b1100, 0)
}

// Data field flags
pub const DATA: u8 = 0b0;
pub const CONSTANT: u8 = 0b1;

pub const ARRAY: u8 = 0b00;
pub const VARIABLE: u8 = 0b10;

pub const ABSOLUTE: u8 = 0b000;
pub const RELATIVE: u8 = 0b100;

define_item!(input, MAIN, 0b1000, u8);
define_item!(output, MAIN, 0b1001, u8);
