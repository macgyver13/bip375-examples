// BIP-375 Hardware Signer - GUI Binary
// Slint-based graphical interface

use bip375_helpers::display::psbt_io::set_use_memory_storage;
use hardware_signer::gui;

fn main() {
    set_use_memory_storage(true);
    gui::run_gui().unwrap();
}
