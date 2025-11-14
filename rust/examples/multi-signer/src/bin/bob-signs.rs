//! Bob Signs PSBT - Binary wrapper
//!
//! This is a standalone binary that calls the bob_signs function from the multi-signer library.

use multi_signer::bob_signs::bob_signs;

fn main() {
    match bob_signs() {
        Ok(()) => {
            println!("\n✅ Bob's step completed successfully!");
        }
        Err(e) => {
            eprintln!("\n❌ Bob's step failed: {}", e);
            std::process::exit(1);
        }
    }
}
