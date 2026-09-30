#!/usr/bin/env python3
"""
Charlie Finalizes PSBT - Step 3 of Multi-Signer Silent Payment

Charlie acts as:
- SIGNER (final): Verifies all previous work, adds final ECDH share, computes output scripts, signs input 2
- EXTRACTOR: Extracts the final transaction

This script:
1. Loads Bob's PSBT from output/psbt_step2.json
2. Verifies Alice's and Bob's DLEQ proofs
3. Adds ECDH share + DLEQ proof for input 2 (Charlie's input)
4. Achieves complete ECDH coverage, triggering output script computation
5. Sets modifiable flags to False
6. Signs input 2
7. Extracts the final transaction
8. Saves transaction to output/final_transaction.hex

Input coverage after Charlie:
- Input 0: ✅ Alice (ECDH + signature)
- Input 1: ✅ Bob (ECDH + signature)
- Input 2: ✅ Charlie (ECDH + signature)
- Output scripts: ✅ Computed
- Transaction: ✅ Complete
"""

import sys
import os

# Add current directory to path for shared_utils import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shared_utils import (
    get_transaction_inputs, get_charlie_private_key, verify_file_exists,
    print_step_header, print_ecdh_coverage_status, print_workflow_progress
)

# Add parent directories to path for PSBT imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from psbt_sp.psbt import SilentPaymentPSBT, PSBTKeyType
from psbt_sp.roles import PSBTExtractor
def charlie_finalizes():
    """
    Charlie loads Bob's PSBT, finalizes everything, and extracts the transaction

    Roles: SIGNER (final) + EXTRACTOR
    """
    print_step_header(3, "Charlie Finalizes PSBT", "Charlie")

    # Load current working PSBT
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    current_file = os.path.join(output_dir, "transfer.psbt")

    verify_file_exists(current_file, "current working PSBT")

    psbt, metadata = SilentPaymentPSBT.load_psbt_from_file(current_file)

    print(" Loaded previous work:")
    print(f"   Step: {metadata.get('step', 'unknown')}")
    print(f"   Completed by: {metadata.get('completed_by', 'unknown')}")
    print(f"   Inputs with ECDH: {metadata.get('inputs_with_ecdh', [])}")
    print(f"   Inputs with signatures: {metadata.get('inputs_with_signatures', [])}")
    print(f"   Description: {metadata.get('description', 'N/A')}")

    # Get transaction inputs and set Charlie's private key
    inputs = get_transaction_inputs()
    charlie_private_key = get_charlie_private_key()
    inputs[2].private_key = charlie_private_key
    print("   Set Charlie's private key for input 2")

    # Print current ECDH coverage
    print("\n Current ECDH coverage (before Charlie):")
    print_ecdh_coverage_status(psbt)

    print("\n SIGNER (Charlie): Processing final input 2...")
    print("   Computing ECDH share and DLEQ proof for input 2")
    print("   This will complete ECDH coverage!")

    # Charlie only controls input 2
    charlie_controlled_inputs = [2]

    # Scan keys will be auto-extracted from PSBT outputs
    success = psbt.signer_role_partial(inputs, charlie_controlled_inputs)

    if not success:
        print("❌ SIGNER role failed for Charlie")
        return False

    # Print final ECDH coverage
    print("\n Final ECDH coverage (after Charlie):")
    print_ecdh_coverage_status(psbt)

    # Check if output scripts were computed
    output_scripts_computed = any(
        any(field.key_type == PSBTKeyType.PSBT_OUT_SCRIPT for field in output_fields)
        for output_fields in psbt.output_maps
    )

    if output_scripts_computed:
        print("\n Complete ECDH coverage achieved!")
        print("    Silent payment output scripts computed")
        print("    Modifiable flags set to False")
        print("    All inputs signed")
    else:
        print("\n❌ Output scripts not computed - something went wrong")
        return False

    print("\n EXTRACTOR: Creating final transaction...")

    try:
        # Extract final transaction
        transaction_bytes = psbt.extract_transaction()

        # Save transaction to hex file
        transaction_file = os.path.join(output_dir, "final_transaction.hex")
        PSBTExtractor.save_transaction(transaction_bytes, transaction_file)

        print(f"   Transaction extracted successfully ({len(transaction_bytes)} bytes)")
        print(f" Saved transaction to {transaction_file}")

        # Save final PSBT state
        metadata = {
            "step": 3,
            "completed_by": "charlie",
            "controlled_inputs": charlie_controlled_inputs,
            "inputs_with_ecdh": psbt.get_inputs_with_ecdh_shares(),
            "inputs_with_signatures": [0, 1, 2],  # All inputs signed
            "ecdh_complete": True,
            "outputs_with_scripts": True,
            "transaction_complete": True,
            "transaction_size_bytes": len(transaction_bytes),
            "description": "Charlie completed the workflow and extracted final transaction"
        }

        # Save reference file for this step
        step_file = os.path.join(output_dir, "psbt_step3.json")
        psbt.save_psbt_to_file(step_file, metadata)

        # Update common working file (now finalized)
        psbt.save_psbt_to_file(current_file, metadata)

        print(" Multi-signer silent payment transaction complete!")

        # Show final workflow progress
        print_workflow_progress()

        # print(psbt.pretty_print())

        # Display transaction summary
        print("\n Transaction Summary:")
        inputs = get_transaction_inputs()
        total_input = sum(utxo.amount for utxo in inputs)
        print(f"   Total Input:  {total_input:,} sats")
        print("   Change:       100,000 sats")
        print("   Silent Payment: 340,000 sats")
        print("   Fee:          10,000 sats")
        print(f"   Transaction:  {len(transaction_bytes)} bytes")
        print(f"   Hex: {transaction_bytes.hex()}")

        return True

    except Exception as e:
        print(f"❌ Transaction extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = charlie_finalizes()
        if success:
            print("\n Charlie's step completed successfully!")
            print(" Multi-signer silent payment workflow complete!")
        else:
            print("\n❌ Charlie's step failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error in Charlie's step: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)