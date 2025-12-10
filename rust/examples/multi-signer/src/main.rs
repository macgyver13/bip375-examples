//! Multi-Signer Example - GUI Entry Point
//!
//! Demonstrates 3-party signing workflow with progressive ECDH coverage.
//! Provides a graphical interface to visualize the Alice → Bob → Charlie workflow.

use common::set_use_memory_storage;
use multi_signer::gui;

fn main() -> Result<(), slint::PlatformError> {
    set_use_memory_storage(true);
    gui::run_gui()
}
