// BIP-375 Hardware Signer Demo
// Demonstrates air-gapped signing with DLEQ proof validation and attack detection

#[cfg(feature = "gui")]
mod gui;

mod hw_device;
mod shared_utils;
mod wallet_coordinator;

use hw_device::HardwareDevice;
use std::io::{self, Write};
use wallet_coordinator::WalletCoordinator;

/// Demo state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum DemoState {
    Ready,
    PsbtCreated,
    PsbtSigned,
    TransactionExtracted,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse CLI flags
    let auto_read = args.contains(&"--auto-read".to_string());
    let auto_approve = args.contains(&"--auto-approve".to_string());
    let attack_mode = args.contains(&"--attack".to_string());
    let demo_flow = args.contains(&"--demo-flow".to_string());

    if demo_flow {
        run_automated_demo(auto_read, auto_approve, attack_mode);
    } else {
        run_interactive_menu(auto_read, auto_approve, attack_mode);
    }
}

/// Run automated demo flow
fn run_automated_demo(_auto_read: bool, _auto_approve: bool, attack_mode: bool) {
    println!("\n  Running automated BIP-375 Hardware Signer demo...\n");

    if attack_mode {
        println!("Running ATTACK SIMULATION mode\n");
        if let Err(e) = run_attack_simulation(true, true) {
            eprintln!("❌ Attack simulation failed: {}", e);
        }
    } else {
        println!("Running NORMAL mode\n");
        if let Err(e) = run_normal_flow(true, true) {
            eprintln!("❌ Normal flow failed: {}", e);
        }
    }
}

/// Run normal flow automatically
fn run_normal_flow(auto_read: bool, auto_approve: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== NORMAL FLOW ===\n");

    // Step 1: Create PSBT
    WalletCoordinator::create_psbt(true)?;

    // Step 2: Sign on hardware device
    HardwareDevice::sign_workflow(auto_read, auto_approve, false)?;

    // Step 3: Finalize
    WalletCoordinator::finalize_transaction(auto_read)?;

    println!("\n  Normal flow completed successfully!\n");
    Ok(())
}

/// Run attack simulation
fn run_attack_simulation(
    auto_read: bool,
    auto_approve: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ATTACK SIMULATION ===\n");

    // Step 1: Create PSBT
    WalletCoordinator::create_psbt(true)?;

    // Step 2: Sign with ATTACK MODE
    HardwareDevice::sign_workflow(auto_read, auto_approve, true)?;

    // Step 3: Finalize (should fail with attack detection)
    println!("\n Coordinator will now verify DLEQ proofs...\n");
    match WalletCoordinator::finalize_transaction(auto_read) {
        Ok(_) => {
            println!("\n⚠️  WARNING: Attack was NOT detected!");
            println!("   This should not happen - check validation logic\n");
        }
        Err(e) => {
            println!("\n  SUCCESS: Attack was detected and rejected!");
            println!("   Error: {}\n", e);
            println!("   The DLEQ proof verification correctly identified the");
            println!("   malicious scan key and prevented fund redirection.\n");
        }
    }

    Ok(())
}

/// Run interactive menu system
fn run_interactive_menu(auto_read: bool, auto_approve: bool, attack_mode: bool) {
    let mut state = DemoState::Ready;

    loop {
        display_menu(state);

        print!("Choose option [1-7]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                // Create PSBT
                if state == DemoState::Ready || state == DemoState::TransactionExtracted {
                    match WalletCoordinator::create_psbt(false) {
                        Ok(_) => {
                            state = DemoState::PsbtCreated;
                        }
                        Err(e) => {
                            eprintln!("\n❌ Error creating PSBT: {}\n", e);
                        }
                    }
                } else {
                    println!("\n❌ Invalid state. Reset demo first.\n");
                }
            }
            "2" => {
                // Sign PSBT
                if state == DemoState::PsbtCreated {
                    match HardwareDevice::sign_workflow(auto_read, auto_approve, attack_mode) {
                        Ok(_) => {
                            state = DemoState::PsbtSigned;
                        }
                        Err(e) => {
                            eprintln!("\n❌ Error signing PSBT: {}\n", e);
                        }
                    }
                } else {
                    println!("\n❌ Invalid state. Create PSBT first.\n");
                }
            }
            "3" => {
                // Finalize transaction
                if state == DemoState::PsbtSigned {
                    match WalletCoordinator::finalize_transaction(auto_read) {
                        Ok(_) => {
                            state = DemoState::TransactionExtracted;
                        }
                        Err(e) => {
                            eprintln!("\n❌ Error finalizing transaction: {}\n", e);
                            // Stay in PsbtSigned state - may want to retry
                        }
                    }
                } else {
                    println!("\n❌ Invalid state. Sign PSBT first.\n");
                }
            }
            "4" => {
                // Reset
                println!("\n Resetting demo...\n");
                match WalletCoordinator::reset() {
                    Ok(_) => {
                        println!("  Demo reset complete\n");
                        state = DemoState::Ready;
                    }
                    Err(e) => {
                        eprintln!("❌ Error resetting: {}\n", e);
                    }
                }
            }
            "5" => {
                // Attack simulation
                if state == DemoState::Ready || state == DemoState::TransactionExtracted {
                    if let Err(e) = run_attack_simulation(auto_read, auto_approve) {
                        eprintln!("\n❌ Attack simulation error: {}\n", e);
                    }
                    // Reset state after attack simulation
                    let _ = WalletCoordinator::reset();
                    state = DemoState::Ready;
                } else {
                    println!("\n❌ Reset demo first before running attack simulation.\n");
                }
            }
            "6" => {
                // About
                display_about();
            }
            "7" => {
                // Exit
                println!("\nGoodbye! \n");
                break;
            }
            _ => {
                println!("\n❌ Invalid option. Please choose 1-7.\n");
            }
        }
    }
}

/// Display main menu
fn display_menu(state: DemoState) {
    println!("\n{}", "=".repeat(60));
    println!("  BIP-375 Hardware Signer Demo");
    println!("{}\n", "=".repeat(60));

    println!("Current State: {:?}\n", state);

    println!("Main Menu:");
    match state {
        DemoState::Ready | DemoState::TransactionExtracted => {
            println!("  1.  Create New PSBT (Wallet Coordinator)");
        }
        _ => {
            println!("  1.  Create New PSBT (Wallet Coordinator) [disabled]");
        }
    }

    match state {
        DemoState::PsbtCreated => {
            println!("  2.  Sign PSBT (Hardware Device)");
        }
        _ => {
            println!("  2.  Sign PSBT (Hardware Device) [disabled]");
        }
    }

    match state {
        DemoState::PsbtSigned => {
            println!("  3.  Finalize Transaction (Wallet Coordinator)");
        }
        _ => {
            println!("  3.  Finalize Transaction (Wallet Coordinator) [disabled]");
        }
    }

    println!("  4.  Reset Demo");

    match state {
        DemoState::Ready | DemoState::TransactionExtracted => {
            println!("  5.  Run Attack Simulation");
        }
        _ => {
            println!("  5.  Run Attack Simulation [disabled]");
        }
    }

    println!("  6.  About This Demo");
    println!("  7.  Exit");
    println!();
}

/// Display about information
fn display_about() {
    println!("\n{}", "=".repeat(60));
    println!("  About BIP-375 Hardware Signer Demo");
    println!("{}\n", "=".repeat(60));

    println!("This demo demonstrates:");
    println!("  • Air-gapped hardware wallet signing for silent payments");
    println!("  • DLEQ proof generation and verification (BIP-374)");
    println!("  • Attack detection when hardware uses wrong scan keys");
    println!("  • File-based PSBT exchange (simulates QR/USB transfer)");
    println!("  • Privacy mode: no derivation paths revealed to coordinator");
    println!("\nWorkflow:");
    println!("  1. Coordinator creates PSBT with inputs/outputs");
    println!("  2. PSBT transferred to air-gapped hardware device");
    println!("  3. Hardware computes ECDH shares + DLEQ proofs + signatures");
    println!("  4. Signed PSBT transferred back to coordinator");
    println!("  5. Coordinator verifies DLEQ proofs (detects attacks!)");
    println!("  6. Coordinator finalizes and extracts transaction");
    println!("\nSecurity:");
    println!("  • DLEQ proofs cryptographically prove hardware computed");
    println!("    ECDH shares for the correct scan keys");
    println!("  • Attack mode shows what happens if hardware is malicious");
    println!("  • Coordinator can verify without trusting hardware");
    println!();
}
