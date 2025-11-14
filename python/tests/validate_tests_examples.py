#!/usr/bin/env python3
"""
BIP 375 Development Test Suite

Comprehensive automated testing script that runs all example workflows:
1. Multi-signer workflow (Alice, Bob, Charlie)
2. Hardware wallet workflow (wallet_coordinator + hw_device)
3. Hardware wallet flow (integrated script)

This script provides automated testing for continuous integration and development.
"""

import subprocess
import sys
import time
from pathlib import Path

# ANSI color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

class TestResult:
    def __init__(self, name):
        self.name = name
        self.passed = False
        self.error = None
        self.duration = 0

def print_header(text):
    """Print a formatted header"""
    print(f"\n{BOLD}{BLUE}{'=' * 70}{RESET}")
    print(f"{BOLD}{BLUE}{text:^70}{RESET}")
    print(f"{BOLD}{BLUE}{'=' * 70}{RESET}\n")

def print_test_start(test_name):
    """Print test start message"""
    print(f"{BOLD}Testing: {test_name}{RESET}")
    print(f"{'-' * 70}")

def print_test_result(result: TestResult):
    """Print test result"""
    status = f"{GREEN}PASS{RESET}" if result.passed else f"{RED}FAIL{RESET}"
    print(f"\n{status} {result.name} ({result.duration:.2f}s)")
    if result.error:
        print(f"{RED}Error: {result.error}{RESET}")

def run_command(cmd, cwd=None, description=None):
    """Run a command and return success status"""
    if description:
        print(f"  {description}")

    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"{RED}  ✗ Command failed with return code {result.returncode}{RESET}")
            if result.stderr:
                print(f"{RED}  stderr: {result.stderr[:500]}{RESET}")
            return False

        print(f"{GREEN}  ✓ Success{RESET}")
        return True

    except subprocess.TimeoutExpired:
        print(f"{RED}  ✗ Command timed out{RESET}")
        return False
    except Exception as e:
        print(f"{RED}  ✗ Error: {e}{RESET}")
        return False

def test_multi_signer_workflow():
    """Test the multi-signer workflow (Alice, Bob, Charlie)"""
    result = TestResult("Multi-Signer Workflow")
    start_time = time.time()

    try:
        print_test_start("Multi-Signer Workflow (Alice + Bob + Charlie)")

        # Get bip-0375 root directory (parent of tests/)
        bip_dir = Path(__file__).parent.parent
        examples_dir = bip_dir / "examples" / "multi-signer"

        # Reset any existing state
        print("\n  Step 1: Clean up previous run")
        run_command(
            ["python3", "alice_creates.py"],
            cwd=examples_dir,
            description="Reset and prepare Alice's PSBT"
        )

        # Alice creates PSBT
        print("\n  Step 2: Alice creates PSBT")
        if not run_command(
            ["python3", "alice_creates.py"],
            cwd=examples_dir,
            description="Alice creates initial PSBT"
        ):
            result.error = "Alice failed to create PSBT"
            return result

        # Bob signs
        print("\n  Step 3: Bob signs")
        if not run_command(
            ["python3", "bob_signs.py"],
            cwd=examples_dir,
            description="Bob signs input 1"
        ):
            result.error = "Bob failed to sign"
            return result

        # Charlie finalizes
        print("\n  Step 4: Charlie finalizes")
        if not run_command(
            ["python3", "charlie_finalizes.py"],
            cwd=examples_dir,
            description="Charlie signs input 2 and finalizes"
        ):
            result.error = "Charlie failed to finalize"
            return result

        # Check that final transaction was created
        tx_file = examples_dir / "output" / "final_transaction.hex"
        if not tx_file.exists():
            result.error = "Final transaction file not created"
            return result

        print(f"\n{GREEN}  Final transaction created: {tx_file}{RESET}")
        result.passed = True

    except Exception as e:
        result.error = str(e)

    finally:
        result.duration = time.time() - start_time

    return result

def test_hardware_wallet_workflow():
    """Test the hardware wallet workflow (coordinator + device)"""
    result = TestResult("Hardware Wallet Workflow")
    start_time = time.time()

    try:
        print_test_start("Hardware Wallet Workflow (Coordinator + Device)")

        # Get bip-0375 root directory (parent of tests/)
        bip_dir = Path(__file__).parent.parent
        hw_dir = bip_dir / "examples" / "hardware-signer"

        # Step 1: Reset
        print("\n  Step 1: Reset previous state")
        if not run_command(
            ["python3", "wallet_coordinator.py", "reset"],
            cwd=hw_dir,
            description="Clean up previous files"
        ):
            result.error = "Failed to reset"
            return result

        # Step 2: Coordinator creates PSBT
        print("\n  Step 2: Coordinator creates PSBT")
        if not run_command(
            ["python3", "wallet_coordinator.py", "create"],
            cwd=hw_dir,
            description="Wallet coordinator creates PSBT"
        ):
            result.error = "Coordinator failed to create PSBT"
            return result

        # Step 3: Hardware device signs
        print("\n  Step 3: Hardware device signs")
        if not run_command(
            ["python3", "hw_device.py", "--auto-read", "--auto-approve"],
            cwd=hw_dir,
            description="Hardware wallet signs PSBT"
        ):
            result.error = "Hardware device failed to sign"
            return result

        # Step 4: Coordinator finalizes
        print("\n  Step 4: Coordinator finalizes")
        if not run_command(
            ["python3", "wallet_coordinator.py", "read", "--auto-read", "--auto-broadcast"],
            cwd=hw_dir,
            description="Coordinator verifies and finalizes"
        ):
            result.error = "Coordinator failed to finalize"
            return result

        # Check that final transaction was created
        tx_file = hw_dir / "output" / "final_transaction.hex"
        if not tx_file.exists():
            result.error = "Final transaction file not created"
            return result

        print(f"\n{GREEN}  Final transaction created: {tx_file}{RESET}")
        result.passed = True

    except Exception as e:
        result.error = str(e)

    finally:
        result.duration = time.time() - start_time

    return result

def test_hardware_wallet_attack_detection():
    """Test that hardware wallet attack mode is properly detected"""
    result = TestResult("Hardware Wallet Attack Detection")
    start_time = time.time()

    try:
        print_test_start("Hardware Wallet Attack Detection")

        # Get bip-0375 root directory (parent of tests/)
        bip_dir = Path(__file__).parent.parent
        hw_dir = bip_dir / "examples" / "hardware-signer"

        # Step 1: Reset
        print("\n  Step 1: Reset previous state")
        run_command(
            ["python3", "wallet_coordinator.py", "reset"],
            cwd=hw_dir,
            description="Clean up previous files"
        )

        # Step 2: Coordinator creates PSBT
        print("\n  Step 2: Coordinator creates PSBT")
        if not run_command(
            ["python3", "wallet_coordinator.py", "create"],
            cwd=hw_dir,
            description="Wallet coordinator creates PSBT"
        ):
            result.error = "Coordinator failed to create PSBT"
            return result

        # Step 3: Hardware device signs with ATTACK mode
        print("\n  Step 3: Hardware device signs with ATTACK mode")
        if not run_command(
            ["python3", "hw_device.py", "--auto-read", "--auto-approve", "--attack"],
            cwd=hw_dir,
            description="Hardware wallet signs with malicious scan key"
        ):
            result.error = "Hardware device failed to sign in attack mode"
            return result

        # Step 4: Coordinator should REJECT
        print("\n  Step 4: Coordinator should detect and reject")
        # We expect this to FAIL because the attack should be detected
        cmd_result = subprocess.run(
            ["python3", "wallet_coordinator.py", "read", "--auto-read", "--auto-broadcast"],
            cwd=hw_dir,
            capture_output=True,
            text=True,
            timeout=30
        )

        if cmd_result.returncode == 0:
            result.error = "Coordinator ACCEPTED malicious PSBT (attack not detected!)"
            return result

        # Check that the error message indicates DLEQ verification failure
        if "DLEQ" in cmd_result.stdout or "verification" in cmd_result.stdout.lower():
            print(f"{GREEN}  Attack properly detected and rejected{RESET}")
            result.passed = True
        else:
            result.error = "Attack rejected but not for DLEQ verification reasons"

    except Exception as e:
        result.error = str(e)

    finally:
        result.duration = time.time() - start_time

    return result

def test_hardware_wallet_flow():
    """Test the integrated hardware_wallet_flow.py script"""
    result = TestResult("Hardware Wallet Flow (Integrated)")
    start_time = time.time()

    try:
        print_test_start("Hardware Wallet Flow (Integrated Script)")

        # Get bip-0375 root directory (parent of tests/)
        bip_dir = Path(__file__).parent.parent
        hw_dir = bip_dir / "examples" / "hardware-signer"

        print("\n  Running integrated hardware wallet flow")
        if not run_command(
            ["python3", "hardware_wallet_flow.py", "--non-interactive"],
            cwd=hw_dir,
            description="Execute integrated hardware wallet flow"
        ):
            result.error = "Hardware wallet flow failed"
            return result

        # Check that final transaction was created
        tx_file = hw_dir / "output" / "final_transaction.hex"
        if not tx_file.exists():
            result.error = "Final transaction file not created"
            return result

        print(f"\n{GREEN}  ✓ Final transaction created: {tx_file}{RESET}")
        result.passed = True

    except Exception as e:
        result.error = str(e)

    finally:
        result.duration = time.time() - start_time

    return result

def test_vectors():
    """Run the BIP 375 test vectors"""
    result = TestResult("BIP 375 Test Vectors (reference.py)")
    start_time = time.time()

    try:
        print_test_start("BIP 375 Test Vectors (reference.py)")

        # Get bip-0375 root directory (parent of tests/)
        bip_dir = Path(__file__).parent.parent

        print("\n  Running test vector suite with reference.py")
        if not run_command(
            ["python3", "reference.py"],
            cwd=bip_dir,
            description="Execute all test vectors"
        ):
            result.error = "Test vectors failed"
            return result

        result.passed = True

    except Exception as e:
        result.error = str(e)

    finally:
        result.duration = time.time() - start_time

    return result

def test_vector_validator():
    """Run the BIP 375 test vector validator"""
    result = TestResult("BIP 375 Test Vector Validator")
    start_time = time.time()

    try:
        print_test_start("BIP 375 Test Vector Validator (test_vector_validator.py)")

        # Get bip-0375 root directory (parent of tests/)
        bip_dir = Path(__file__).parent.parent
        tests_dir = bip_dir / "tests"

        print("\n  Running test vector validator with psbt_sp package")
        if not run_command(
            ["python3", "test_vector_validator.py"],
            cwd=tests_dir,  # Run from tests/ directory
            description="Validate test vectors using psbt_sp implementation"
        ):
            result.error = "Test vector validator failed"
            return result

        result.passed = True

    except Exception as e:
        result.error = str(e)

    finally:
        result.duration = time.time() - start_time

    return result

def main():
    """Run all tests and report results"""
    print_header("BIP 375 Development Test Suite")
    print(f"{BOLD}Running comprehensive automated tests...{RESET}\n")

    results = []

    # Run all tests
    tests = [
        ("Multi-Signer", test_multi_signer_workflow),
        ("Hardware Wallet", test_hardware_wallet_workflow),
        ("Attack Detection", test_hardware_wallet_attack_detection),
        ("Hardware Flow", test_hardware_wallet_flow),
    ]

    for test_name, test_func in tests:
        result = test_func()
        results.append(result)
        print_test_result(result)
        time.sleep(0.5)  # Small delay between tests

    # Print summary
    print_header("Test Summary")

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    total = len(results)

    print(f"Total Tests: {BOLD}{total}{RESET}")
    print(f"Passed:      {GREEN}{BOLD}{passed}{RESET}")
    print(f"Failed:      {RED}{BOLD}{failed}{RESET}")
    print()

    # Print details of failed tests
    if failed > 0:
        print(f"{RED}{BOLD}Failed Tests:{RESET}")
        for result in results:
            if not result.passed:
                print(f"  {RED}- {result.name}: {result.error}{RESET}")
        print()

    # Print success rate
    success_rate = (passed / total) * 100 if total > 0 else 0
    print(f"Success Rate: {BOLD}{success_rate:.1f}%{RESET}")

    # Overall result
    if failed == 0:
        print(f"\n{GREEN}{BOLD}ALL TESTS PASSED!{RESET}\n")
        return 0
    else:
        print(f"\n{RED}{BOLD}SOME TESTS FAILED{RESET}\n")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Tests interrupted by user{RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}Unexpected error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
