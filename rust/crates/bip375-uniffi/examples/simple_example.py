#!/usr/bin/env python3
"""
Simple example demonstrating BIP-375 Python bindings.

This example shows:
1. Creating a PSBT with Silent Payment outputs
2. Adding ECDH shares with DLEQ proofs
3. Signing inputs
4. Finalizing and extracting the transaction
5. Saving/loading PSBTs with metadata
"""

import bip375
# Import the role functions directly from bip375
from bip375 import (
    roles_create_psbt,
    roles_add_inputs, 
    roles_add_outputs,
    roles_finalize_inputs,
    roles_extract_transaction,
    Utxo,
    Output,
    SilentPaymentAddress
)


def main():
    print("BIP-375 Python Bindings - Simple Example")
    print("=" * 50)

    # Example keys (DO NOT use in production - these are for demo only!)
    privkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
    pubkey = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

    scan_key = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    spend_key = bytes.fromhex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

    print("\n1. Creating PSBT with Silent Payment output")
    print("-" * 50)

    # Define inputs
    inputs = [
        Utxo(
            txid="a" * 64,  # Example txid
            vout=0,
            amount=100000,  # 100,000 sats
            script_pubkey=bytes.fromhex("0014") + bytes(20),  # P2WPKH placeholder
            private_key=privkey,
            sequence=0xfffffffd,
        )
    ]

    # Define outputs with silent payment
    outputs = [
        Output(
            amount=90000,  # 90,000 sats (10k fee)
            script_pubkey=None,
            sp_address=SilentPaymentAddress(
                scan_key=scan_key,
                spend_key=spend_key,
                label=None,
            ),
        )
    ]

    # Create PSBT
    psbt = roles_create_psbt(inputs, outputs)
    print(f"✓ Created PSBT")

    print("\n2. Computing ECDH shares")
    print("-" * 50)

    # # Compute ECDH share manually (for demonstration)
    # ecdh_share = bip352.compute_ecdh_share(privkey, scan_key)
    # print(f"✓ ECDH share: {ecdh_share.hex()}")

    # # Generate DLEQ proof
    # aux_rand = bytes(32)  # Should be random in production
    # proof = dleq.generate_proof(privkey, scan_key, aux_rand)
    # print(f"✓ DLEQ proof generated: {len(proof)} bytes")

    # # Verify the proof
    # is_valid = dleq.verify_proof(pubkey, scan_key, ecdh_share, proof)
    # print(f"✓ DLEQ proof valid: {is_valid}")

    # print("\n3. Adding ECDH shares to PSBT")
    # print("-" * 50)

    # # Add ECDH shares for all inputs (with DLEQ proofs)
    # scan_keys = [scan_key]
    # roles.add_ecdh_shares_full(psbt, inputs, scan_keys, include_dleq=True)
    # print("✓ ECDH shares added to PSBT")

    # # Check ECDH shares were added
    # input_shares = psbt.get_input_ecdh_shares(0)
    # print(f"✓ Input 0 has {len(input_shares)} ECDH share(s)")
    # if input_shares:
    #     share = input_shares[0]
    #     print(f"  - Scan key: {share.scan_key.hex()[:16]}...")
    #     print(f"  - Share point: {share.share_point.hex()[:16]}...")
    #     if share.dleq_proof:
    #         print(f"  - DLEQ proof: {len(share.dleq_proof)} bytes")

    # print("\n4. Aggregating ECDH shares")
    # print("-" * 50)

    # # Aggregate ECDH shares
    # aggregated = aggregation.aggregate_ecdh_shares(psbt)
    # print(f"✓ Aggregated shares for {len(aggregated.scan_keys())} scan key(s)")

    # for scan_key_bytes in aggregated.scan_keys():
    #     share_point = aggregated.get_share_point(scan_key_bytes)
    #     if share_point:
    #         print(f"  - Scan key: {scan_key_bytes.hex()[:16]}...")
    #         print(f"    Aggregated point: {share_point.hex()[:16]}...")

    # print("\n5. Signing inputs")
    # print("-" * 50)

    # roles.sign_inputs(psbt, inputs)
    # print("✓ All inputs signed")

    # print("\n6. Finalizing PSBT")
    # print("-" * 50)

    # # Finalize (compute output scripts from silent payment addresses)
    # roles.finalize_inputs(psbt)
    # print("✓ PSBT finalized (output scripts computed)")

    # # Check output script was computed
    # output_script = psbt.get_output_script(0)
    # if output_script:
    #     print(f"  - Output 0 script: {output_script.hex()[:32]}...")

    # print("\n7. Extracting transaction")
    # print("-" * 50)

    # # Extract final transaction
    # tx_bytes = roles.extract_transaction(psbt)
    # print(f"✓ Transaction extracted: {len(tx_bytes)} bytes")
    # print(f"  Transaction (hex): {tx_bytes.hex()[:64]}...")

    # print("\n8. Saving and loading PSBT")
    # print("-" * 50)

    # # Save with metadata
    # metadata = bip375.PsbtMetadata(
    #     creator="simple-example",
    #     stage="finalized",
    #     description="Example silent payment transaction",
    # )

    # # Save as binary
    # binary_path = "/tmp/example.psbt"
    # file_io.save_psbt_binary(psbt, binary_path)
    # print(f"✓ Saved PSBT to {binary_path}")

    # # Load back
    # loaded_psbt = file_io.load_psbt_binary(binary_path)
    # print(f"✓ Loaded PSBT: {loaded_psbt.num_inputs()} inputs, {loaded_psbt.num_outputs()} outputs")

    # # Save as JSON with metadata
    # json_path = "/tmp/example.json"
    # file_io.save_psbt_json(psbt, json_path, metadata)
    # print(f"✓ Saved PSBT with metadata to {json_path}")

    print("\n" + "=" * 50)
    print("Example completed successfully!")
    print("\nThe Rust bindings provide:")
    print("- Fast cryptographic operations")
    print("- Memory-safe PSBT handling")
    print("- Full BIP-375 support")
    print("- Compatible API with pure Python implementation")


if __name__ == "__main__":
    main()
