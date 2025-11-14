// BIP-375 Hardware Signer - GUI Binary
// Slint-based graphical interface

use hardware_signer::gui;
use common::set_use_memory_storage;

fn main() {
    set_use_memory_storage(true);
    gui::run_gui().unwrap();
}
