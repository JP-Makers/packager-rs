pub mod msi;
pub mod nsis;

pub use msi::{msi_package, msi_package as build_msi};
pub use nsis::{nsis_package, nsis_package as build_nsis};

