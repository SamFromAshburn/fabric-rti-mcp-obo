#!/usr/bin/env python3
"""Test script to validate private key loading improvements."""

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def test_key_loading_logic():
    """Test the improved key loading logic with different formats."""

    # Generate a test RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Test different formats
    test_cases = []

    # 1. PEM format (standard)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    test_cases.append(("PEM", pem_private_key.decode()))

    # 2. DER format (base64 encoded)
    der_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    test_cases.append(("DER base64", base64.b64encode(der_private_key).decode()))

    # 3. Invalid format
    test_cases.append(("Invalid", "this-is-not-a-valid-key"))

    for test_name, key_data in test_cases:
        print(f"\nTesting {test_name} format...")
        try:
            # Simulate the improved loading logic from our fix
            loaded_key = None
            try:
                # First try PEM format without password
                loaded_key = serialization.load_pem_private_key(
                    key_data.encode(), password=None, backend=default_backend()
                )
                print(f"✓ Successfully loaded as PEM")
            except ValueError as pem_error:
                print(f"- PEM loading failed: {pem_error}")
                try:
                    # Try DER format
                    # If the private key is base64 encoded DER, decode it first
                    try:
                        der_data = base64.b64decode(key_data)
                        loaded_key = serialization.load_der_private_key(
                            der_data, password=None, backend=default_backend()
                        )
                        print(f"✓ Successfully loaded as DER (base64 decoded)")
                    except Exception:
                        # Try raw DER if it's not base64 encoded
                        loaded_key = serialization.load_der_private_key(
                            key_data.encode(), password=None, backend=default_backend()
                        )
                        print(f"✓ Successfully loaded as raw DER")
                except ValueError as der_error:
                    print(f"- DER loading failed: {der_error}")
                    print(f"✗ All formats failed")

                    # Provide helpful hints based on the data format
                    if key_data.startswith("-----BEGIN"):
                        hint = "Key appears to be PEM format but may be encrypted or corrupted."
                    elif len(key_data) % 4 == 0 and all(
                        c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in key_data
                    ):
                        hint = "Key appears to be base64 encoded. It may be DER, PKCS#12, or encrypted PEM."
                    else:
                        hint = "Key format is not recognized. Ensure it's in PEM or DER format."
                    print(f"  Hint: {hint}")

            if loaded_key:
                print(f"  Key type: {type(loaded_key).__name__}")

        except Exception as e:
            print(f"✗ Unexpected error: {e}")


if __name__ == "__main__":
    test_key_loading_logic()
