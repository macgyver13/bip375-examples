//! Alice Creates PSBT - Binary wrapper
//!
//! This is a standalone binary that calls the alice_creates function from the multi-signer library.

use multi_signer::alice_creates::alice_creates;

fn main() {
    match alice_creates() {
        Ok(()) => {
            println!("\n✅ Alice's step completed successfully!");
        }
        Err(e) => {
            eprintln!("\n❌ Alice's step failed: {}", e);
            std::process::exit(1);
        }
    }
}
