// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LogLevel {
    USBIP = 0,
    USB,
    CTAPHID,
    CTAP,
    CRYPTO,
}

static LOG_LEVEL: AtomicUsize = AtomicUsize::new(0);

#[allow(dead_code)]
pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.fetch_or(1 << (level as usize), Ordering::Relaxed);
}

pub fn log(level: LogLevel, s: &str) {
    if (LOG_LEVEL.load(Ordering::Relaxed) & 1 << (level as usize)) != 0 {
        eprintln!("{}", s);
    }
}

macro_rules! log {
    ($level:ident, $($x:expr),*) => {
        crate::log::log(
	    crate::log::LogLevel::$level,
	    &format!("{}: {}", module_path!(), format_args!($($x),*)))
    }
}
