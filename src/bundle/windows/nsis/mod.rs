pub mod pe;
pub mod script;

#[allow(clippy::module_inception)]
pub mod nsis;

pub use nsis::nsis_package;
