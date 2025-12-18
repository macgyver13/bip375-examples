// BIP-375 Hardware Signer Demo
// Demonstrates air-gapped signing with DLEQ proof validation and attack detection

#[cfg(feature = "gui")]
mod gui;

mod hw_device;
mod shared_utils;
mod wallet_coordinator;

use bip375_helpers::wallet::{types::InteractiveConfig, TransactionConfig, VirtualWallet};
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

    // Check for help flag
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        display_help();
        return;
    }

    // Parse mnemonic if provided
    let mnemonic = match parse_mnemonic_arg(&args) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    };

    // Parse CLI flags
    let auto_read = args.contains(&"--auto-read".to_string());
    let auto_approve = args.contains(&"--auto-approve".to_string());
    let attack_mode = args.contains(&"--attack".to_string());
    let demo_flow = args.contains(&"--demo-flow".to_string());
    let interactive_config = args.contains(&"--interactive-config".to_string());

    if demo_flow {
        run_automated_demo(
            auto_read,
            auto_approve,
            attack_mode,
            interactive_config,
            mnemonic,
        );
    } else {
        run_interactive_menu(
            auto_read,
            auto_approve,
            attack_mode,
            interactive_config,
            mnemonic,
        );
    }
}

/// Parse --mnemonic argument from command line
fn parse_mnemonic_arg(args: &[String]) -> Result<Option<String>, String> {
    if let Some(pos) = args.iter().position(|arg| arg == "--mnemonic") {
        if let Some(mnemonic) = args.get(pos + 1) {
            if mnemonic.starts_with("--") {
                return Err("--mnemonic requires a value (12 or 24 word phrase)".to_string());
            }
            // Validate word count (12 or 24 words)
            let word_count = mnemonic.split_whitespace().count();
            if word_count != 12 && word_count != 24 {
                return Err(format!(
                    "Invalid mnemonic: expected 12 or 24 words, got {}",
                    word_count
                ));
            }
            Ok(Some(mnemonic.clone()))
        } else {
            Err("--mnemonic requires a value".to_string())
        }
    } else {
        Ok(None)
    }
}

/// Display help information
fn display_help() {
    println!("\nBIP-375 Hardware Signer Demo");
    println!("{}\n", "=".repeat(60));
    println!("Demonstrates air-gapped signing with DLEQ proof validation");
    println!("and attack detection for Silent Payment transactions.\n");
    println!("USAGE:");
    println!("    hardware-signer [OPTIONS]\n");
    println!("OPTIONS:");
    println!("    --help, -h              Show this help message");
    println!("    --mnemonic <phrase>     BIP39 mnemonic (12 or 24 words, quoted)");
    println!("    --demo-flow             Run automated demo flow");
    println!("    --auto-read             Auto-confirm PSBT transfers");
    println!("    --auto-approve          Auto-approve transactions");
    println!("    --attack                Run attack simulation mode");
    println!("    --interactive-config    Interactively configure UTXOs\n");
    println!("UTXO SELECTION:");
    println!("    --utxos <ids>           Comma-separated UTXO IDs (e.g., 1,2,3)");
    println!("    --recipient <sats>      Recipient amount in satoshis");
    println!("    --change <sats>         Change amount in satoshis");
    println!("    --fee <sats>            Fee amount in satoshis\n");
    println!("EXAMPLES:");
    println!("    # Run interactive menu");
    println!("    hardware-signer\n");
    println!("    # Use BIP39 mnemonic");
    println!("    hardware-signer --mnemonic \"word1 word2 ... word12\"\n");
    println!("    # Run automated demo with default config");
    println!("    hardware-signer --demo-flow --auto-read --auto-approve\n");
    println!("    # Use custom UTXOs");
    println!("    hardware-signer --utxos 1,3 --recipient 200000 --change 40000 --fee 5000\n");
    println!("    # Interactive UTXO selection");
    println!("    hardware-signer --interactive-config\n");
    println!("AVAILABLE UTXOs:");
    let wallet = VirtualWallet::hardware_wallet_default(None).expect("Failed to create wallet");
    for utxo in wallet.list_utxos() {
        let sp_marker = if utxo.has_sp_tweak { " [SP]" } else { "" };
        println!(
            "    [{}] {} sats - {} - {}{}",
            utxo.id,
            utxo.utxo.amount.to_sat(),
            utxo.script_type.as_str(),
            utxo.description,
            sp_marker
        );
    }
    println!();
}

/// Run automated demo flow
fn run_automated_demo(
    _auto_read: bool,
    _auto_approve: bool,
    attack_mode: bool,
    interactive_config: bool,
    mnemonic: Option<String>,
) {
    println!("\n  Running automated BIP-375 Hardware Signer demo...\n");

    // Get configuration
    let config = if interactive_config {
        match get_interactive_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("❌ Configuration error: {}", e);
                return;
            }
        }
    } else {
        let args: Vec<String> = std::env::args().collect();
        TransactionConfig::from_args(&args, TransactionConfig::hardware_wallet_auto())
    };

    if attack_mode {
        println!("Running ATTACK SIMULATION mode\n");
        if let Err(e) = run_attack_simulation_with_config(&config, true, true, mnemonic.as_deref())
        {
            eprintln!("❌ Attack simulation failed: {}", e);
        }
    } else {
        println!("Running NORMAL mode\n");
        if let Err(e) = run_normal_flow_with_config(&config, true, true, mnemonic.as_deref()) {
            eprintln!("❌ Normal flow failed: {}", e);
        }
    }
}

/// Run normal flow with provided config
fn run_normal_flow_with_config(
    config: &TransactionConfig,
    auto_read: bool,
    auto_approve: bool,
    mnemonic: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== NORMAL FLOW ===\n");

    // Step 1: Create PSBT
    WalletCoordinator::create_psbt(config, true, mnemonic)?;

    // Step 2: Sign on hardware device
    HardwareDevice::sign_workflow(config, auto_read, auto_approve, false, mnemonic)?;

    // Step 3: Finalize
    WalletCoordinator::finalize_transaction(config, auto_read, mnemonic)?;

    println!("\n  Normal flow completed successfully!\n");
    Ok(())
}

/// Run attack simulation with provided config
fn run_attack_simulation_with_config(
    config: &TransactionConfig,
    auto_read: bool,
    auto_approve: bool,
    mnemonic: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ATTACK SIMULATION ===\n");

    // Step 1: Create PSBT
    WalletCoordinator::create_psbt(config, true, mnemonic)?;

    // Step 2: Sign with ATTACK MODE
    HardwareDevice::sign_workflow(config, auto_read, auto_approve, true, mnemonic)?;

    // Step 3: Finalize (should fail with attack detection)
    println!("\n Coordinator will now verify DLEQ proofs...\n");
    match WalletCoordinator::finalize_transaction(config, auto_read, mnemonic) {
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
fn run_interactive_menu(
    auto_read: bool,
    auto_approve: bool,
    attack_mode: bool,
    _interactive_config: bool,
    mnemonic: Option<String>,
) {
    let mut state = DemoState::Ready;
    let mut current_config: Option<TransactionConfig> = None;

    loop {
        display_menu(state, current_config.as_ref());

        print!("Choose option [1-8]: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            "1" => {
                // Configure UTXOs
                match get_interactive_config() {
                    Ok(config) => {
                        current_config = Some(config);
                        println!("\n✅ Configuration saved\n");
                    }
                    Err(e) => {
                        eprintln!("\n❌ Configuration error: {}\n", e);
                    }
                }
            }
            "2" => {
                // Create PSBT
                if state == DemoState::Ready || state == DemoState::TransactionExtracted {
                    let config = current_config
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(TransactionConfig::hardware_wallet_auto);
                    match WalletCoordinator::create_psbt(&config, false, mnemonic.as_deref()) {
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
            "3" => {
                // Sign PSBT
                if state == DemoState::PsbtCreated {
                    let config = current_config
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(TransactionConfig::hardware_wallet_auto);
                    match HardwareDevice::sign_workflow(
                        &config,
                        auto_read,
                        auto_approve,
                        attack_mode,
                        mnemonic.as_deref(),
                    ) {
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
            "4" => {
                // Finalize transaction
                if state == DemoState::PsbtSigned {
                    let config = current_config
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(TransactionConfig::hardware_wallet_auto);
                    match WalletCoordinator::finalize_transaction(
                        &config,
                        auto_read,
                        mnemonic.as_deref(),
                    ) {
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
            "5" => {
                // Reset
                println!("\n Resetting demo...\n");
                match WalletCoordinator::reset() {
                    Ok(_) => {
                        println!("  Demo reset complete\n");
                        state = DemoState::Ready;
                        current_config = None;
                    }
                    Err(e) => {
                        eprintln!("❌ Error resetting: {}\n", e);
                    }
                }
            }
            "6" => {
                // Attack simulation
                if state == DemoState::Ready || state == DemoState::TransactionExtracted {
                    let config = current_config
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(TransactionConfig::hardware_wallet_auto);
                    if let Err(e) = run_attack_simulation_with_config(
                        &config,
                        auto_read,
                        auto_approve,
                        mnemonic.as_deref(),
                    ) {
                        eprintln!("\n❌ Attack simulation error: {}\n", e);
                    }
                    // Reset state after attack simulation
                    let _ = WalletCoordinator::reset();
                    state = DemoState::Ready;
                    current_config = None;
                } else {
                    println!("\n❌ Reset demo first before running attack simulation.\n");
                }
            }
            "7" => {
                // About
                display_about();
            }
            "8" => {
                // Exit
                println!("\nGoodbye! \n");
                break;
            }
            _ => {
                println!("\n❌ Invalid option. Please choose 1-8.\n");
            }
        }
    }
}

/// Display main menu
fn display_menu(state: DemoState, config: Option<&TransactionConfig>) {
    println!("\n{}", "=".repeat(60));
    println!("  BIP-375 Hardware Signer Demo");
    println!("{}\n", "=".repeat(60));

    println!("Current State: {:?}", state);
    if let Some(cfg) = config {
        println!(
            "Configuration: UTXOs {:?}, Recipient {}k, Change {}k, Fee {}k",
            cfg.selected_utxo_ids,
            cfg.recipient_amount / 1000,
            cfg.change_amount / 1000,
            cfg.fee / 1000
        );
    } else {
        println!("Configuration: Default");
    }
    println!();

    println!("Main Menu:");
    println!("  1.  Configure UTXO Selection");
    match state {
        DemoState::Ready | DemoState::TransactionExtracted => {
            println!("  2.  Create New PSBT (Wallet Coordinator)");
        }
        _ => {
            println!("  2.  Create New PSBT (Wallet Coordinator) [disabled]");
        }
    }

    match state {
        DemoState::PsbtCreated => {
            println!("  3.  Sign PSBT (Hardware Device)");
        }
        _ => {
            println!("  3.  Sign PSBT (Hardware Device) [disabled]");
        }
    }

    match state {
        DemoState::PsbtSigned => {
            println!("  4.  Finalize Transaction (Wallet Coordinator)");
        }
        _ => {
            println!("  4.  Finalize Transaction (Wallet Coordinator) [disabled]");
        }
    }

    println!("  5.  Reset Demo");

    match state {
        DemoState::Ready | DemoState::TransactionExtracted => {
            println!("  6.  Run Attack Simulation");
        }
        _ => {
            println!("  6.  Run Attack Simulation [disabled]");
        }
    }

    println!("  7.  About This Demo");
    println!("  8.  Exit");
    println!();
}

/// Get interactive configuration from user
fn get_interactive_config() -> Result<TransactionConfig, Box<dyn std::error::Error>> {
    let wallet = VirtualWallet::hardware_wallet_default(None)?;
    let default_config = TransactionConfig::hardware_wallet_auto();
    InteractiveConfig::build(&wallet, default_config)
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
