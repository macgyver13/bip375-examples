//! Interactive CLI menu for multi-signer workflow

use crate::core::{AppState, WorkflowOrchestrator, WorkflowState};
use bip375_helpers::display::psbt_io::export_to_file;
use std::io::{self, Write};

/// Run the interactive CLI menu
pub fn run_cli() -> Result<(), String> {
    let mut state = AppState::default();

    println!("\n{}", "=".repeat(60));
    println!("  BIP-375 Multi-Signer Silent Payment Demo");
    println!("{}\n", "=".repeat(60));

    loop {
        display_status(&state);
        display_menu(&state);

        let choice = read_input("Select action: ")?;

        match choice.trim() {
            "0" => {
                println!("\nExiting...");
                break;
            }
            "1" => configure_parties(&mut state)?,
            "2" => create_psbt(&mut state)?,
            "3" => sign_as_party(&mut state, "Alice")?,
            "4" => sign_as_party(&mut state, "Bob")?,
            "5" => sign_as_party(&mut state, "Charlie")?,
            "6" => finalize_transaction(&mut state)?,
            "7" => view_psbt_details(&state)?,
            "8" => reset_demo(&mut state)?,
            "9" => export_psbt(&state)?,
            _ => println!("\n⚠ Invalid choice. Please try again."),
        }
    }

    Ok(())
}

/// Display current workflow status
fn display_status(state: &AppState) {
    println!("\n{}", "=".repeat(60));
    println!("Current Configuration:");
    println!("  Creator: {}", state.multi_config.get_creator().name);

    for party in &state.multi_config.parties {
        let input_indices: Vec<String> = party
            .controlled_input_indices
            .iter()
            .map(|&i| i.to_string())
            .collect();
        println!(
            "  {}: UTXOs {:?} → Inputs [{}]",
            party.name,
            party.tx_config.selected_utxo_ids,
            input_indices.join(", ")
        );
    }

    println!("\nWorkflow Status: {:?}", state.workflow_state);

    if state.ecdh_progress.total_inputs > 0 {
        println!("\nECDH Phase:");
        for party in &state.multi_config.parties {
            let completed = state
                .ecdh_progress
                .parties_completed
                .contains(&party.name);
            let symbol = if completed { "✓" } else { "⧗" };
            println!(
                "  {} {} ECDH {}",
                symbol,
                party.name,
                if completed { "done" } else { "pending" }
            );
        }

        println!("Signing Phase:");
        for party in &state.multi_config.parties {
            let completed = state
                .signing_progress
                .parties_completed
                .contains(&party.name);
            let symbol = if completed { "✓" } else { "⧗" };
            println!(
                "  {} {} {}",
                symbol,
                party.name,
                if completed { "signed" } else { "pending" }
            );
        }
    }

    if let Some(psbt) = &state.current_psbt {
        println!("\nPSBT Status:");
        println!("  Inputs: {}", psbt.inputs.len());
        println!("  Outputs: {}", psbt.outputs.len());
        println!(
            "  ECDH Coverage: {}/{}",
            state.ecdh_coverage.inputs_with_ecdh, state.ecdh_coverage.total_inputs
        );
        println!(
            "  Signing Progress: {}",
            state.signing_progress.completion_fraction()
        );
    }

    println!("{}", "=".repeat(60));
}

/// Display menu options based on current state
fn display_menu(state: &AppState) {
    println!("\nActions:");
    println!("  1. Configure Parties (UTXOs & Input Assignment)");

    let can_create = matches!(
        state.workflow_state,
        WorkflowState::ConfiguringParties
            | WorkflowState::PsbtCreated
            | WorkflowState::TransactionExtracted
    );
    println!(
        "  2. Create PSBT {}",
        if can_create { "" } else { "[disabled]" }
    );

    let is_ecdh_phase = matches!(
        state.workflow_state,
        WorkflowState::EcdhInProgress(_) | WorkflowState::PsbtCreated
    );

    for (i, name) in ["Alice", "Bob", "Charlie"].iter().enumerate() {
        let num = i + 3;
        if is_ecdh_phase {
            let can_add = WorkflowOrchestrator::can_party_add_ecdh(state, name);
            let completed = state.ecdh_progress.parties_completed.contains(*name);
            println!(
                "  {}. Add ECDH for {} {}",
                num,
                name,
                if completed {
                    "[done]"
                } else if can_add {
                    ""
                } else {
                    "[disabled]"
                }
            );
        } else {
            let can_sign = WorkflowOrchestrator::can_party_sign(state, name);
            let completed = state.signing_progress.parties_completed.contains(*name);
            println!(
                "  {}. Sign as {} {}",
                num,
                name,
                if completed {
                    "[signed]"
                } else if can_sign {
                    ""
                } else {
                    "[disabled]"
                }
            );
        }
    }

    let can_extract = state.workflow_state == WorkflowState::FullySigned;
    println!(
        "  6. Extract Transaction {}",
        if can_extract { "" } else { "[disabled]" }
    );

    let has_psbt = state.current_psbt.is_some();
    println!(
        "  7. View PSBT Details {}",
        if has_psbt { "" } else { "[disabled]" }
    );

    println!("  8. Reset Demo");

    println!(
        "  9. Export PSBT {}",
        if has_psbt { "" } else { "[disabled]" }
    );

    println!("  0. Exit");
}

/// Configure parties (simplified - uses defaults for now)
fn configure_parties(state: &mut AppState) -> Result<(), String> {
    println!("\n{}", "=".repeat(60));
    println!("Configure Parties");
    println!("{}", "=".repeat(60));

    println!("\nSelect transaction creator:");
    println!("  1. Alice");
    println!("  2. Bob");
    println!("  3. Charlie");

    let choice = read_input("Creator [1-3]: ")?;

    let creator_index = match choice.trim() {
        "1" => 0,
        "2" => 1,
        "3" => 2,
        _ => {
            println!("Invalid choice, using Alice as creator");
            0
        }
    };

    // Update the creator in the config
    state.multi_config.creator_index = creator_index;

    println!("\n✓ Configuration updated:");
    println!("  Creator: {}", state.multi_config.get_creator().name);
    println!("\nUsing default UTXO selection for all parties.");
    println!("Each party contributes 1 input (100,000 sats).");

    Ok(())
}

/// Create PSBT
fn create_psbt(state: &mut AppState) -> Result<(), String> {
    println!("\n{}", "=".repeat(60));
    println!("Creating PSBT...");
    println!("{}", "=".repeat(60));

    WorkflowOrchestrator::execute_create_psbt(state)?;

    println!("\n✓ PSBT created successfully!");
    println!(
        "  Inputs: {}",
        state.current_psbt.as_ref().unwrap().inputs.len()
    );
    println!(
        "  Outputs: {}",
        state.current_psbt.as_ref().unwrap().outputs.len()
    );

    Ok(())
}

/// Process party action (ECDH shares or signing depending on phase)
fn sign_as_party(state: &mut AppState, party_name: &str) -> Result<(), String> {
    let is_ecdh_phase = matches!(
        state.workflow_state,
        WorkflowState::EcdhInProgress(_) | WorkflowState::PsbtCreated
    );

    if is_ecdh_phase {
        if !WorkflowOrchestrator::can_party_add_ecdh(state, party_name) {
            println!("\n{} ECDH shares already added", party_name);
            return Ok(());
        }

        println!("\n{}", "=".repeat(60));
        println!("Adding ECDH shares for {}...", party_name);
        println!("{}", "=".repeat(60));

        WorkflowOrchestrator::execute_add_ecdh_for_party(state, party_name)?;

        println!("\n{} ECDH shares added!", party_name);
        println!(
            "  ECDH Coverage: {}/{}",
            state.ecdh_coverage.inputs_with_ecdh, state.ecdh_coverage.total_inputs
        );

        if state.ecdh_coverage.is_complete {
            println!("  Output scripts computed - ready for signing!");
        }
    } else {
        if !WorkflowOrchestrator::can_party_sign(state, party_name) {
            println!("\n{} cannot sign", party_name);
            return Ok(());
        }

        println!("\n{}", "=".repeat(60));
        println!("Signing as {}...", party_name);
        println!("{}", "=".repeat(60));

        WorkflowOrchestrator::execute_sign_for_party(state, party_name)?;

        println!("\n{} signed!", party_name);
        println!(
            "  Signing Progress: {}",
            state.signing_progress.completion_fraction()
        );
    }

    Ok(())
}

/// Finalize transaction
fn finalize_transaction(state: &mut AppState) -> Result<(), String> {
    if state.workflow_state != WorkflowState::FullySigned {
        println!("\n⚠ Cannot finalize: not all inputs are signed");
        return Ok(());
    }

    println!("\n{}", "=".repeat(60));
    println!("Finalizing transaction...");
    println!("{}", "=".repeat(60));

    WorkflowOrchestrator::execute_extract_transaction(state)?;

    println!("\nTransaction extracted!");

    if let Some(summary) = &state.transaction_summary {
        println!("\nTransaction Summary:");
        println!("  Total Input: {} sats", summary.total_input);
        println!("  Total Output: {} sats", summary.total_output);
        println!("  Fee: {} sats", summary.fee);
    }

    Ok(())
}

/// View PSBT details
fn view_psbt_details(state: &AppState) -> Result<(), String> {
    let psbt = match &state.current_psbt {
        Some(p) => p,
        None => {
            println!("\n⚠ No PSBT available");
            return Ok(());
        }
    };

    println!("\n{}", "=".repeat(60));
    println!("PSBT Details");
    println!("{}", "=".repeat(60));

    println!("\nInputs ({}):", psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        println!("\n  Input {}:", i);
        println!("    Has ECDH share: {}", !input.sp_ecdh_shares.is_empty());
        println!("    Has DLEQ proof: {}", !input.sp_dleq_proofs.is_empty());
        println!("    Has signature: {}", !input.partial_sigs.is_empty());
    }

    println!("\nOutputs ({}):", psbt.outputs.len());
    for (i, output) in psbt.outputs.iter().enumerate() {
        println!("\n  Output {}:", i);
        println!("    Has script: {}", !output.script_pubkey.is_empty());
    }

    Ok(())
}

/// Reset demo
fn reset_demo(state: &mut AppState) -> Result<(), String> {
    println!("\n{}", "=".repeat(60));
    print!("Are you sure you want to reset? [y/N]: ");
    io::stdout().flush().ok();

    let mut confirm = String::new();
    io::stdin()
        .read_line(&mut confirm)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    if confirm.trim().to_lowercase() == "y" {
        WorkflowOrchestrator::execute_reset(state)?;
        println!("\n✓ Demo reset successfully!");
    } else {
        println!("\nReset cancelled.");
    }

    Ok(())
}

/// Export PSBT to file
fn export_psbt(state: &AppState) -> Result<(), String> {
    let psbt = match &state.current_psbt {
        Some(p) => p,
        None => {
            println!("\n⚠ No PSBT available to export");
            return Ok(());
        }
    };

    println!("\n{}", "=".repeat(60));
    println!("Enter 'c' to cancel");
    let filename = read_input("Export filename [output/psbt_export.json]: ")?;
    let filename = if filename.trim().is_empty() {
        "output/psbt_export.json"
    } else {
        filename.trim()
    };

    if filename.to_lowercase() == "c" {
        println!("  Export cancelled...");
        return Ok(());
    }

    export_to_file(psbt, filename).map_err(|e| format!("Failed to export PSBT: {}", e))?;

    println!("\n✓ PSBT exported to: {}", filename);

    Ok(())
}

/// Read user input from stdin
fn read_input(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout()
        .flush()
        .map_err(|e| format!("Failed to flush stdout: {}", e))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    Ok(input)
}
