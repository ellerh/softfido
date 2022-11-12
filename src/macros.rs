// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

macro_rules! log {
    ($($x:expr),*) => {
        eprintln!("{}: {}", module_path!(), format_args!($($x),*))
    }
}
