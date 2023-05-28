// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::{AtomicUsize, Ordering};

pub enum LogLevel {
    USBIP = 0,
    USB,
    CTAPHID,
    CTAP,
    CRYPTO,
}

static LOG_LEVEL: AtomicUsize = AtomicUsize::new(LogLevel::CTAP as usize);

#[allow(dead_code)]
pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.store(level as usize, Ordering::Relaxed);
}

pub fn log(level: LogLevel, s: &str) {
    if LOG_LEVEL.load(Ordering::Relaxed) <= level as usize {
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
