"""
Basic tests for BIP-375 Python bindings.
"""

import pytest
import bip375

from bip375 import *


# Test fixtures
@pytest.fixture
def test_keys():
    """Provide test keys (DO NOT use in production)."""
    return {
        "privkey": bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001"),
        "pubkey": bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        "scan_key": bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        "spend_key": bytes.fromhex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
    }


@pytest.fixture
def sample_psbt(test_keys):
    """Create a sample PSBT for testing."""
    inputs = [
        Utxo(
            txid="a" * 64,
            vout=0,
            amount=100000,
            script_pubkey=bytes.fromhex("0014") + bytes(20),
            private_key=test_keys["privkey"],
            sequence=0xfffffffd,
        )
    ]

    outputs = [
        Output(
            amount=90000,
            recipient=OutputRecipient.SILENT_PAYMENT(
                address=SilentPaymentAddress(
                    scan_key=test_keys["scan_key"],
                    spend_key=test_keys["spend_key"],
                    label=None,
                )
            ),
        )
    ]

    psbt = SilentPaymentPsbt.create(len(inputs), len(outputs))
    psbt.add_inputs(inputs)
    psbt.add_outputs(outputs)
    return psbt


class TestCoreTypes:
    """Test core data types."""

    def test_silent_payment_address(self, test_keys):
        """Test SilentPaymentAddress creation."""
        addr = SilentPaymentAddress(
            scan_key=test_keys["scan_key"],
            spend_key=test_keys["spend_key"],
            label=None,
        )
        assert addr.scan_key == test_keys["scan_key"]
        assert addr.spend_key == test_keys["spend_key"]
        assert addr.label is None

    def test_silent_payment_address_with_label(self, test_keys):
        """Test SilentPaymentAddress with label."""
        addr = SilentPaymentAddress(
            scan_key=test_keys["scan_key"],
            spend_key=test_keys["spend_key"],
            label=42,
        )
        assert addr.label == 42

    def test_ecdh_share(self, test_keys):
        """Test EcdhShare creation."""
        share = bip375.EcdhShare(
            scan_key=test_keys["scan_key"],
            share_point=test_keys["pubkey"],
            dleq_proof=None,
        )
        assert share.scan_key == test_keys["scan_key"]
        assert share.share_point == test_keys["pubkey"]
        assert share.dleq_proof is None


class TestPsbt:
    """Test PSBT operations."""

    def test_create_psbt(self, sample_psbt):
        """Test PSBT creation."""
        assert sample_psbt.num_inputs() == 1
        assert sample_psbt.num_outputs() == 1

    def test_psbt_serialization(self, sample_psbt):
        """Test PSBT serialization/deserialization."""
        serialized = sample_psbt.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

        # Deserialize
        deserialized = bip375.SilentPaymentPsbt.deserialize(serialized)
        assert deserialized.num_inputs() == sample_psbt.num_inputs()
        assert deserialized.num_outputs() == sample_psbt.num_outputs()

    def test_get_output_sp_address(self, sample_psbt, test_keys):
        """Test getting silent payment address from output."""
        addr = sample_psbt.get_output_sp_address(0)
        assert addr is not None
        assert addr.scan_key == test_keys["scan_key"]
        assert addr.spend_key == test_keys["spend_key"]


class TestCrypto:
    """Test cryptographic functions."""

    def test_compute_ecdh_share(self, test_keys):
        """Test ECDH share computation."""
        share = bip352_compute_ecdh_share(test_keys["privkey"], test_keys["scan_key"])
        assert isinstance(share, bytes)
        assert len(share) == 33  # Compressed public key

    def test_dleq_proof_generation_and_verification(self, test_keys):
        """Test DLEQ proof generation and verification."""
        aux_rand = bytes(32)
        proof = dleq_generate_proof(test_keys["privkey"], test_keys["scan_key"], aux_rand)
        assert isinstance(proof, bytes)
        assert len(proof) > 0

        # Compute ECDH share for verification
        ecdh_share = bip352_compute_ecdh_share(test_keys["privkey"], test_keys["scan_key"])

        # Verify proof
        is_valid = dleq_verify_proof(
            test_keys["pubkey"], test_keys["scan_key"], ecdh_share, proof
        )
        assert is_valid is True


class TestRoles:
    """Test PSBT role functions."""

    def test_add_ecdh_shares(self, sample_psbt, test_keys):
        """Test adding ECDH shares."""
        inputs = [
            bip375.Utxo(
                txid="a" * 64,
                vout=0,
                amount=100000,
                script_pubkey=bytes.fromhex("0014") + bytes(20),
                private_key=test_keys["privkey"],
                sequence=0xfffffffd,
            )
        ]

        scan_keys = [test_keys["scan_key"]]
        sample_psbt.add_ecdh_shares_full(inputs, scan_keys)

        # Verify shares were added
        shares = sample_psbt.get_input_ecdh_shares(0)
        assert len(shares) > 0
        assert shares[0].dleq_proof is not None  # DLEQ proof should be included

    # def test_aggregation(self, sample_psbt, test_keys):
    #     """Test ECDH share aggregation."""
    #     # First add ECDH shares
    #     inputs = [
    #         bip375.Utxo(
    #             txid="a" * 64,
    #             vout=0,
    #             amount=100000,
    #             script_pubkey=bytes.fromhex("0014") + bytes(20),
    #             private_key=test_keys["privkey"],
    #         )
    #     ]

    #     scan_keys = [test_keys["scan_key"]]
    #     roles_add_ecdh_shares_full(sample_psbt, inputs, scan_keys, include_dleq=False)

    #     # Aggregate
    #     aggregated = aggregation.aggregate_ecdh_shares(sample_psbt)
    #     assert len(aggregated.scan_keys()) > 0

    #     # Get share point
    #     share_point = aggregated.get_share_point(test_keys["scan_key"])
    #     assert share_point is not None
    #     assert isinstance(share_point, bytes)


class TestFileIO:
    """Test file I/O operations."""

    def test_save_load_binary(self, sample_psbt, tmp_path):
        """Test binary PSBT save/load."""
        file_path = str(tmp_path / "test.psbt")

        # Save
        sample_psbt.save(file_path, None)

        # Load
        loaded = sample_psbt.load(file_path)
        assert loaded.num_inputs() == sample_psbt.num_inputs()
        assert loaded.num_outputs() == sample_psbt.num_outputs()

    def test_save_load_with_metadata(self, sample_psbt, tmp_path):
        """Test JSON PSBT save/load with metadata."""
        file_path = str(tmp_path / "test.json")

        metadata = bip375.PsbtMetadata(
            creator="test-suite",
            stage="created",
            description="Test PSBT",
            created_at=None,
            modified_at=None,
        )

        # Save
        sample_psbt.save(file_path, metadata)

        # Load (returns PSBT directly, metadata is stored in file but not returned)
        loaded = SilentPaymentPsbt.load(file_path)
        assert loaded.num_inputs() == sample_psbt.num_inputs()
        assert loaded.num_outputs() == sample_psbt.num_outputs()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
