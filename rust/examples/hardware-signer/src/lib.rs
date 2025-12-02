use bip375_core::Bip375PsbtExt;

// BIP-375 Hardware Signer - Shared Library
// Exports all modules for use by binaries

#[cfg(feature = "gui")]
pub mod gui;

pub mod hw_device;
pub mod shared_utils;
pub mod wallet_coordinator;

pub use wallet_coordinator::WalletCoordinator;
pub use hw_device::HardwareDevice;
