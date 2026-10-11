#[cfg(feature = "aot")]
mod aot;
mod check;
mod compile;
#[cfg(feature = "debug-cmd")]
mod debug;
mod deps;
mod fix;
mod fmt;
mod man;
mod scan;
