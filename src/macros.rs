
macro_rules! log {
    ($($x:expr),*) => {
        eprintln!("{}: {}", module_path!(), format_args!($($x),*))
    }
}
