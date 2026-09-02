#!/usr/bin/env python3
"""
Bob Signs PSBT - Step 2 of Multi-Signer Silent Payment

Bob acts as:
- SIGNER (partial): Verifies Alice's work and adds ECDH share + signature for input 1

This script:
1. Loads Alice's PSBT from output/psbt_step1.json
2. Verifies Alice's DLEQ proof for input 0
3. Adds ECDH share + DLEQ proof for input 1 (Bob's input)
4. Signs input 1
5. Saves the PSBT to output/psbt_step2.json for Charlie

Input coverage after Bob:
- Input 0: ✅ Alice (ECDH + signature)
- Input 1: ✅ Bob (ECDH + signature)
- Input 2: ⏳ Waiting for Charlie
"""

import sys
import os

# Add current directory to path for shared_utils import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared_utils import (
    get_transaction_inputs, get_bob_private_key, verify_file_exists,
    print_step_header, print_ecdh_coverage_status, print_workflow_progress
)

# Add parent directories to path for PSBT imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentPSBT

def bob_signs():
    """
    Bob loads Alice's PSBT and processes his input (input 1)

    Roles: SIGNER (partial)
    """
    print_step_header(2, "Bob Signs PSBT", "Bob")

    # Load current working PSBT
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    current_file = os.path.join(output_dir, "transfer.psbt")

    verify_file_exists(current_file, "current working PSBT")

    psbt, metadata = SilentPaymentPSBT.load_psbt_from_file(current_file)

    print(" Loaded previous work:")
    print(f"   Step: {metadata.get('step', 'unknown')}")
    print(f"   Completed by: {metadata.get('completed_by', 'unknown')}")
    print(f"   Previous controlled inputs: {metadata.get('controlled_inputs', [])}")
    print(f"   Description: {metadata.get('description', 'N/A')}")

    # Get transaction inputs and set Bob's private key
    inputs = get_transaction_inputs()
    bob_private_key = get_bob_private_key()
    inputs[1].private_key = bob_private_key
    print("   Set Bob's private key for input 1")

    # Print current ECDH coverage
    print("\n Current ECDH coverage (before Bob):")
    print_ecdh_coverage_status(psbt)

    print(" SIGNER (Bob): Processing input 1...")
    print("   Computing ECDH share and DLEQ proof for input 1")

    # Bob only controls input 1
    bob_controlled_inputs = [1]

    # Scan keys will be auto-extracted from PSBT outputs
    success = psbt.signer_role_partial(inputs, bob_controlled_inputs)

    if not success:
        print("❌ SIGNER role failed for Bob")
        return False

    # Print updated ECDH coverage
    print("\n Updated ECDH coverage (after Bob):")
    print_ecdh_coverage_status(psbt)

    # Save PSBT to files
    metadata = {
        "step": 2,
        "completed_by": "bob",
        "controlled_inputs": bob_controlled_inputs,
        "inputs_with_ecdh": psbt.get_inputs_with_ecdh_shares(),
        "inputs_with_signatures": [0, 1],  # Alice's and Bob's inputs
        "ecdh_complete": psbt.can_compute_output_scripts(),
        "outputs_with_scripts": False,
        "description": "Bob verified Alice's work and processed input 1"
    }

    # Update common working file for next party
    psbt.save_psbt_to_file(current_file, metadata)

    print()
    print(" Next: Run charlie_finalizes.py to complete the workflow")

    # Show updated workflow progress
    print_workflow_progress()

    # print(psbt.pretty_print())

    return True

if __name__ == "__main__":
    try:
        success = bob_signs()
        if success:
            print("\n Bob's step completed successfully!")
        else:
            print("\n❌ Bob's step failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error in Bob's step: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)