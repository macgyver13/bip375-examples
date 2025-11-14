#!/usr/bin/env python3
"""
Alice Creates PSBT - Step 1 of Multi-Signer Silent Payment

Alice acts as:
- CREATOR: Creates the PSBT structure
- CONSTRUCTOR: Adds transaction inputs and outputs
- SIGNER (partial): Adds ECDH share and signature for input 0 only

This script:
1. Creates a PSBT with 3 inputs and 2 outputs
2. Adds ECDH share + DLEQ proof for input 0 (Alice's input)
3. Signs input 0
4. Saves the PSBT to output/psbt_step1.json for Bob

Input coverage after Alice:
- Input 0: ✅ Alice (ECDH + signature)
- Input 1: ⏳ Waiting for Bob
- Input 2: ⏳ Waiting for Charlie
"""

import sys
import os

# Add current directory to path for shared_utils import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared_utils import (
    get_transaction_inputs, get_transaction_outputs, get_alice_private_key,
    print_step_header, print_scenario_overview, print_ecdh_coverage_status,
    print_workflow_progress, reset_workflow
)

# Add parent directories to path for PSBT imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentPSBT

def alice_creates():
    """
    Alice creates the initial PSBT and processes her input (input 0)

    Roles: CREATOR + CONSTRUCTOR + partial SIGNER
    """
    print_step_header(1, "Alice Creates PSBT", "Alice")

    # Clean up current working file only (keep reference files)
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    if os.path.exists(output_dir):
        current_file = os.path.join(output_dir, "transfer.psbt")
        if os.path.exists(current_file):
            print("🧹 Cleaning up current working PSBT...")
            try:
                os.remove(current_file)
            except OSError:
                pass
            print()

    print_scenario_overview()

    # Get transaction data
    inputs = get_transaction_inputs()
    outputs = get_transaction_outputs()

    print("  CREATOR: Setting up PSBT structure...")
    psbt = SilentPaymentPSBT()

    print(" CONSTRUCTOR: Adding transaction inputs and outputs...")
    psbt.create_silent_payment_psbt(inputs, outputs)
    print(f"   Created PSBT with {len(inputs)} inputs and {len(outputs)} outputs")

    # Set Alice's private key for input 0
    alice_private_key = get_alice_private_key()
    inputs[0].private_key = alice_private_key
    print("   Set Alice's private key for input 0")

    print(" SIGNER (Alice): Processing input 0...")
    print("   Computing ECDH share and DLEQ proof for input 0")
    print("   Verifying DLEQ proofs from other signers (none yet)")
    print("   Checking ECDH coverage for output script computation")

    # Alice only controls input 0
    alice_controlled_inputs = [0]

    # Scan keys will be auto-extracted from PSBT outputs
    success = psbt.signer_role_partial(inputs, alice_controlled_inputs)

    if not success:
        print("❌ SIGNER role failed for Alice")
        return False

    # Print ECDH coverage status
    print_ecdh_coverage_status(psbt)

    # Save PSBT to files
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(output_dir, exist_ok=True)

    metadata = {
        "step": 1,
        "completed_by": "alice",
        "controlled_inputs": alice_controlled_inputs,
        "inputs_with_ecdh": psbt.get_inputs_with_ecdh_shares(),
        "inputs_with_signatures": alice_controlled_inputs,
        "ecdh_complete": psbt.can_compute_output_scripts(),
        "outputs_with_scripts": False,
        "description": "Alice created PSBT and processed input 0"
    }

    # Save/update common working file for next party
    current_file = os.path.join(output_dir, "transfer.psbt")
    psbt.save_psbt_to_file(current_file, metadata)

    print()
    print(" Next: Run bob_signs.py to continue the workflow")

    # Show updated workflow progress
    print_workflow_progress()

    # print(psbt.pretty_print())

    return True

if __name__ == "__main__":
    reset_workflow()
    try:
        success = alice_creates()
        if success:
            print("\n Alice's step completed successfully!")
        else:
            print("\n❌ Alice's step failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error in Alice's step: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)