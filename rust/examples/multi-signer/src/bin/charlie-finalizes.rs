//! Charlie Finalizes PSBT - Binary wrapper
//!
//! This is a standalone binary that calls the charlie_finalizes function from the multi-signer library.

use multi_signer::charlie_finalizes::charlie_finalizes;

fn main() {
    match charlie_finalizes() {
        Ok(()) => {
            println!("\n✅ Charlie's step completed successfully!");
            println!("✅ Multi-signer silent payment workflow complete!");
        }
        Err(e) => {
            eprintln!("\n❌ Charlie's step failed: {}", e);
            std::process::exit(1);
        }
    }
}
