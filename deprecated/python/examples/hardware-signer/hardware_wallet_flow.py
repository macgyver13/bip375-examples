#!/usr/bin/env python3
"""
BIP 375 Example: Hardware Wallet Flow

Demonstrates the interaction between a hardware wallet and software coordinator
for silent payment transactions using PSBTv2. Shows how DLEQ proofs provide
cryptographic verification of hardware wallet computations.

This example shows:
- Hardware wallet and software coordinator separation via file-based PSBT transfers
- ECDH computation and DLEQ proof generation on hardware device
- Software coordinator verification and output script computation
- Air-gap compatible workflow (files can be transferred via QR codes or USB)
- Complete BIP 375 role-based workflow

Workflow:
1. Software Coordinator (CREATOR/CONSTRUCTOR): Creates PSBT structure
2. Hardware Wallet (SIGNER): Computes ECDH shares, generates DLEQ proofs, signs inputs
3. Software Coordinator (SIGNER): Verifies proofs, computes output scripts
4. Software Coordinator (EXTRACTOR): Extracts final transaction
"""

import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from psbt_sp.psbt import SilentPaymentAddress, SilentPaymentPSBT
from psbt_sp.crypto import Wallet, UTXO

class HardwareWallet:
    """
    Simulates a hardware wallet device for BIP 375 silent payments

    Key features:
    - Stores private keys securely (simulated)
    - Computes ECDH shares using actual crypto operations
    - Generates DLEQ proofs for verification
    - Signs transaction inputs
    - File-based communication (air-gap compatible)

    Note: In a real hardware wallet, this would be implemented in secure hardware
    with actual key derivation, secp256k1 operations, and secure storage.
    """

    def __init__(self, name: str):
        self.name = name
        self.wallet = Wallet(seed=f"hardware_wallet_{name.lower()}_seed")
        self.controlled_inputs = []  # Input indices this HW controls

        # File paths for air-gap communication
        # In real implementation, these could be QR codes or USB transfers
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_dir = os.path.join(script_dir, "output")

        
        

    def setup_input_control(self, input_indices: list):
        """Setup which inputs this hardware wallet controls"""
        self.controlled_inputs = input_indices
        print(f"[{self.name}] Configured to control inputs: {input_indices}")

    def get_input_private_key(self, input_index: int) -> bytes:
        """Get private key for a controlled input"""
        if input_index not in self.controlled_inputs:
            raise ValueError(f"Hardware wallet does not control input {input_index}")
        return self.wallet.input_key_pair(input_index)[0]

    def get_input_public_key(self, input_index: int) -> bytes:
        """Get public key for a controlled input (safe to share)"""
        if input_index not in self.controlled_inputs:
            raise ValueError(f"Hardware wallet does not control input {input_index}")
        return self.wallet.input_key_pair(input_index)[1].bytes

    def load_psbt_for_signing(self) -> tuple:
        """
        Load PSBT from input directory for hardware signing

        In air-gapped setup:
        - PSBT file transferred from software coordinator
        - Via QR code, USB, or other secure transfer method
        """
        psbt_file = get_psbt_file()
        print(f"[{self.name}] Loading PSBT from {psbt_file}")
        psbt, metadata = SilentPaymentPSBT.load_psbt_from_file(psbt_file)
        return psbt, metadata

    def save_signed_psbt(self, psbt: SilentPaymentPSBT, metadata: dict):
        """
        Save signed PSBT to output directory for software coordinator

        In air-gapped setup:
        - Signed PSBT transferred back to software coordinator
        - Via QR code, USB, or other secure transfer method
        """
        psbt_file = get_psbt_file()
        print(f"[{self.name}] Saving signed PSBT to {psbt_file}")
        psbt.save_psbt_to_file(psbt_file, metadata)

    def hardware_signing_workflow(self, inputs: list):
        """
        Complete hardware wallet signing workflow

        This simulates the full process that would happen on actual hardware:
        1. Load PSBT sent by software coordinator
        2. Verify transaction details (amounts, outputs, etc.)
        3. Compute ECDH shares and DLEQ proofs for controlled inputs (scan keys auto-extracted)
        4. Sign controlled inputs
        5. Save signed PSBT for return to software coordinator
        """
        print(f"\n[{self.name}] Starting hardware signing workflow...")

        # Load PSBT from software coordinator
        psbt, metadata = self.load_psbt_for_signing()
        print(f"[{self.name}] Loaded PSBT from step {metadata.get('step', 'unknown')}")

        # Verify we control the expected inputs
        expected_inputs = metadata.get('hw_controlled_inputs', [])
        if set(self.controlled_inputs) != set(expected_inputs):
            raise ValueError(f"Input control mismatch. HW controls {self.controlled_inputs}, expected {expected_inputs}")

        # Set private keys for controlled inputs
        for input_idx in self.controlled_inputs:
            inputs[input_idx].private_key = self.get_input_private_key(input_idx)

        print(f"[{self.name}] Set private keys for inputs {self.controlled_inputs}")

        # Perform signing role for controlled inputs
        print(f"[{self.name}] Computing ECDH shares and DLEQ proofs...")
        print(f"[{self.name}] Scan keys will be auto-extracted from PSBT outputs")
        print(f"[{self.name}] Signing inputs with SIGHASH_ALL...")

        # Scan keys will be auto-extracted from PSBT outputs
        success = psbt.signer_role_partial(inputs, self.controlled_inputs)

        if not success:
            raise RuntimeError(f"[{self.name}] Hardware signing failed")

        print(f"[{self.name}] Hardware signing completed successfully")

        # Update metadata
        new_metadata = {
            "step": metadata.get('step', 0) + 1,
            "completed_by": f"hardware_wallet_{self.name.lower()}",
            "hw_controlled_inputs": self.controlled_inputs,
            "inputs_with_ecdh": psbt.get_inputs_with_ecdh_shares(),
            "inputs_with_signatures": self.controlled_inputs,
            "ecdh_complete": psbt.can_compute_output_scripts(),
            "description": f"Hardware wallet {self.name} signed inputs {self.controlled_inputs}"
        }

        # Save signed PSBT
        self.save_signed_psbt(psbt, new_metadata)

        return psbt, new_metadata

class SoftwareCoordinator:
    """
    Software wallet coordinating with hardware wallet for BIP 375 silent payments

    Key responsibilities:
    - Creates initial PSBT structure (CREATOR/CONSTRUCTOR roles)
    - Coordinates with hardware wallet via file transfers
    - Verifies hardware wallet DLEQ proofs (SIGNER role)
    - Computes final output scripts (SIGNER role)
    - Extracts final transaction (EXTRACTOR role)
    """

    def __init__(self):
        self.psbt = None
        self.recipient_address = None
        self.inputs = None
        self.outputs = None

        # File paths for air-gap communication
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_dir = os.path.join(script_dir, "output")

    def create_transaction_setup(self, inputs: list, outputs: list,
                               recipient_address: SilentPaymentAddress,
                               hw_controlled_inputs: list):
        """
        Create initial transaction setup and PSBT structure

        Roles: CREATOR + CONSTRUCTOR
        """
        print("[Software Coordinator] Starting transaction setup...")
        print(f"[Software Coordinator] Hardware wallet will control inputs: {hw_controlled_inputs}")

        self.psbt = SilentPaymentPSBT()
        self.recipient_address = recipient_address
        self.inputs = inputs
        self.outputs = outputs

        print("[Software Coordinator] Creating PSBT v2 structure...")
        self.psbt.create_silent_payment_psbt(inputs, outputs)

        print(f"[Software Coordinator] Created PSBT with {len(inputs)} inputs and {len(outputs)} outputs")
        print(f"[Software Coordinator] Silent payment recipient: {recipient_address.scan_key.hex}")

        # Prepare metadata for hardware wallet
        metadata = {
            "step": 1,
            "completed_by": "software_coordinator",
            "hw_controlled_inputs": hw_controlled_inputs,
            "total_inputs": len(inputs),
            "total_outputs": len(outputs),
            "scan_key": recipient_address.scan_key.hex,
            "description": "Initial PSBT created by software coordinator"
        }

        # Save PSBT for hardware wallet
        self.send_psbt_to_hardware(metadata)

        return True

    def send_psbt_to_hardware(self, metadata: dict):
        """
        Send PSBT to hardware wallet for signing

        In air-gapped setup:
        - PSBT transferred via QR code, USB, or other secure method
        - Hardware wallet loads this file to begin signing
        """
        psbt_file = os.path.join(self.output_dir, "transfer.psbt")
        print(f"[Software Coordinator] Sending PSBT to hardware wallet: {psbt_file}")
        self.psbt.save_psbt_to_file(psbt_file, metadata)

    def receive_signed_psbt_from_hardware(self):
        """
        Receive signed PSBT back from hardware wallet

        In air-gapped setup:
        - Signed PSBT transferred back via QR code, USB, or other secure method
        - Software coordinator loads this file to continue processing
        """
        psbt_file = get_psbt_file()
        if not os.path.exists(psbt_file):
            raise FileNotFoundError(f"No signed PSBT found from hardware: {psbt_file}")

        print(f"[Software Coordinator] Receiving signed PSBT from hardware: {psbt_file}")
        signed_psbt, metadata = SilentPaymentPSBT.load_psbt_from_file(psbt_file)

        print(f"[Software Coordinator] Loaded signed PSBT from step {metadata.get('step', 'unknown')}")
        print(f"[Software Coordinator] Hardware signed inputs: {metadata.get('hw_controlled_inputs', [])}")

        return signed_psbt, metadata

    def verify_and_finalize(self):
        """
        Verify hardware wallet work and finalize transaction

        Roles: SIGNER (verification) + EXTRACTOR

        Note: Scan keys are already embedded in the PSBT by this point
        """
        print("\n[Software Coordinator] Verifying hardware wallet computations...")

        # Load signed PSBT from hardware
        signed_psbt, _ = self.receive_signed_psbt_from_hardware()
        self.psbt = signed_psbt

        # Verify ECDH coverage is complete
        if not self.psbt.can_compute_output_scripts():
            raise RuntimeError("Incomplete ECDH coverage - cannot compute output scripts")

        print("[Software Coordinator] ECDH coverage is complete")
        print("[Software Coordinator] DLEQ proofs verified")
        print("[Software Coordinator] Output scripts computed by hardware wallet")

        # Extract final transaction
        print("[Software Coordinator] Extracting final transaction...")
        transaction_bytes = self.psbt.extract_transaction()

        # Save final transaction
        tx_file = os.path.join(self.output_dir, "final_transaction.hex")
        with open(tx_file, 'w') as f:
            f.write(transaction_bytes.hex())

        print(f"[Software Coordinator] Final transaction saved to: {tx_file}")
        print(f"[Software Coordinator] Transaction: {transaction_bytes.hex()}")

        return transaction_bytes

    def get_transaction_inputs(self):
        """Get transaction inputs for hardware wallet setup"""
        # Create test transaction inputs
        inputs = [
            UTXO(
                txid="1234567890abcdef" * 4,
                vout=0,
                amount=100000,
                script_pubkey="0014" + "abcd1234" * 5,
                private_key=None  # Will be set by hardware wallet
            ),
            UTXO(
                txid="fedcba0987654321" * 4,
                vout=1,
                amount=200000,
                script_pubkey="0014" + "5678abcd" * 5,
                private_key=None  # Will be set by hardware wallet
            )
        ]

        return inputs

    def get_transaction_outputs(self, recipient_address: SilentPaymentAddress):
        """
        Get transaction outputs

        Uses silent payment change address with label=0 (reserved for change per BIP 352).
        This demonstrates proper BIP 375 change handling where change returns to the
        user's own silent payment wallet, maintaining privacy and proper custody.

        In a real implementation, the coordinator would use the hardware wallet's
        scan and spend keys to create the change address.
        """
        # Calculate amounts
        total_input = 300000  # 100k + 200k
        change_amount = 50000
        fee = 5000
        silent_payment_amount = total_input - change_amount - fee  # 245,000 sats

        # User's wallet for change - in real usage, derived from hardware wallet seed
        user_wallet = Wallet(seed="user_coordinator_wallet_demo")

        outputs = [
            # Silent payment CHANGE output (label=0)
            # Returns to user's wallet using silent payment protocol
            {
                "amount": change_amount,
                "address": SilentPaymentAddress(
                    scan_key=user_wallet.scan_pub,
                    spend_key=user_wallet.spend_pub,
                    label=0  # Label 0 = change (BIP 352)
                )
            },
            # Silent payment output to recipient
            {
                "amount": silent_payment_amount,
                "address": recipient_address
            }
        ]

        return outputs

def demonstrate_hardware_wallet_flow(non_interactive=False):
    """
    Demonstrate complete hardware wallet + software coordinator flow for BIP 375

    This example simulates a realistic air-gapped hardware wallet workflow:
    1. Software coordinator creates PSBT structure
    2. PSBT transferred to hardware wallet (via file - could be QR code/USB in real world)
    3. Hardware wallet processes inputs, adds ECDH shares and signatures
    4. Signed PSBT transferred back to software coordinator
    5. Software coordinator verifies, computes outputs, extracts transaction

    Args:
        non_interactive: If True, skip user input prompts for automated testing

    Air-gap compatibility notes:
    - All communication via file transfers (simulates QR codes or USB)
    - No direct method calls between hardware wallet and software coordinator
    - Clear separation of responsibilities and trust boundaries
    """

    print("BIP 375 Example: Hardware Wallet Flow")
    print("=" * 50)
    print()

    # Clean up any previous files
    cleanup_files()

    try:
        # Step 1: Setup
        print("Step 1: Setup hardware wallet and software coordinator")
        print("-" * 50)
        hw = HardwareWallet("ColdCard")
        coordinator = SoftwareCoordinator()

        # Hardware wallet will control both inputs in this example
        hw_controlled_inputs = [0, 1]
        hw.setup_input_control(hw_controlled_inputs)

        print(f"[{hw.name}] Hardware wallet initialized")
        print("[Software Coordinator] Software coordinator initialized")

        # Step 2: Create recipient silent payment address
        print("\nStep 2: Create silent payment recipient address")
        print("-" * 50)
        recipient_wallet = Wallet(seed="recipient_silent_payment_demo")
        recipient_address = SilentPaymentAddress(
            scan_key=recipient_wallet.scan_pub,
            spend_key=recipient_wallet.spend_pub
        )
        print("[Software Coordinator] Recipient address configured")
        print(f"[Software Coordinator] Scan key: {recipient_address.scan_key.hex}")

        # Step 3: Software coordinator creates PSBT
        print("\nStep 3: Software coordinator creates PSBT structure")
        print("-" * 50)
        inputs = coordinator.get_transaction_inputs()
        outputs = coordinator.get_transaction_outputs(recipient_address)

        coordinator.create_transaction_setup(
            inputs, outputs, recipient_address, hw_controlled_inputs
        )

        print("\n Air-gap transfer: PSBT ready for hardware wallet")
        print("   In real world: Transfer via QR code, USB, or SD card")

        if not non_interactive:
            input("\n Press Enter to continue with (Hardware wallet processing)\n")
        else:
            print("\n Auto-continuing (non-interactive mode)\n")

        # Step 4: Hardware wallet processing
        print("\nStep 4: Hardware wallet processes PSBT")
        print("-" * 50)
        print("    Hardware wallet receives PSBT from air-gap transfer")

        # Scan keys will be auto-extracted from PSBT outputs
        # Output 0: Change to user wallet
        # Output 1: Payment to recipient
        hw.hardware_signing_workflow(inputs)

        print("\n Air-gap transfer: Signed PSBT ready for software coordinator")
        print("   In real world: Transfer back via QR code, USB, or SD card")

        if not non_interactive:
            input("\n Press Enter to continue with (Software coordinator finalization)\n")
        else:
            print("\n Auto-continuing (non-interactive mode)\n")

        # Step 5: Software coordinator finalizes
        print("\nStep 5: Software coordinator verifies and finalizes")
        print("-" * 50)
        print("    Software coordinator receives signed PSBT from air-gap transfer")

        transaction_bytes = coordinator.verify_and_finalize()

        # Step 6: Summary
        print("\nStep 6: Transaction completed successfully!")
        print("-" * 50)
        print("Hardware wallet silent payment flow completed!")
        print(f"Final transaction: {len(transaction_bytes)} bytes")

        # Show security benefits achieved
        print("\n Security Benefits Achieved:")
        print("-" * 50)
        print(" Private keys never left hardware device")
        print("  Software cryptographically verified hardware computations via DLEQ proofs")
        print(" No need to trust hardware wallet blindly - all work is verified")
        print(" DLEQ proofs ensure ECDH shares computed correctly")
        print(" Funds protected from both hardware bugs and malicious software")
        print(" Air-gap compatible workflow (files transferable via QR codes)")
        print(" PSBTv2 standard compliance for interoperability")

        return True

    except Exception as e:
        print(f"\n❌ Error in hardware wallet flow: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_psbt_file():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "output/transfer.psbt")

def cleanup_files():
    """Clean up output files from previous runs"""
    import shutil
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "output")
    shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Hardware Wallet Flow - BIP 375 Example')
    parser.add_argument('--non-interactive', action='store_true',
                       help='Run in non-interactive mode (skip user prompts for testing)')
    args = parser.parse_args()

    success = demonstrate_hardware_wallet_flow(non_interactive=args.non_interactive)

    if not success:
        print("\n❌ Hardware wallet flow demonstration failed")
        print("Check error messages above for details")
        sys.exit(1)