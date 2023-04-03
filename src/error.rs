// Commonly used Error/Result types.

pub type R<T> = Result<T, Box<dyn std::error::Error>>;
pub type IOR<T> = Result<T, std::io::Error>;
