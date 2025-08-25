"""Test script to verify authentication flow and logging."""

import asyncio
import os
import sys
from typing import Optional

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fabric_rti_mcp.auth.azure_certificate_oauth_provider import AzureCertificateOAuthProvider
from fabric_rti_mcp.common import logger


async def test_token_verification():
    """Test token verification directly."""
    logger.info("=== TESTING TOKEN VERIFICATION ===")

    try:
        # Create OAuth provider
        logger.info("Creating AzureCertificateOAuthProvider...")
        provider = AzureCertificateOAuthProvider()
        logger.info("Provider created successfully")

        # Get the token verifier
        logger.info("Getting token verifier...")
        token_verifier = provider._create_token_verifier(["User.Read", "email", "openid", "profile"])
        logger.info("Token verifier obtained")

        # Test with a dummy token (this will fail but should show the logging)
        logger.info("Testing token verification with dummy token...")
        dummy_token = "dummy_token_for_testing"
        result = await token_verifier.verify_token(dummy_token)
        logger.info(f"Token verification result: {result}")

    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")


def test_environment_variables():
    """Test environment variable setup."""
    logger.info("=== TESTING ENVIRONMENT VARIABLES ===")

    oauth_env_vars = [
        "FASTMCP_SERVER_AUTH_AZURE_CERT_CLIENT_ID",
        "FASTMCP_SERVER_AUTH_AZURE_CERT_TENANT_ID",
        "FASTMCP_SERVER_AUTH_AZURE_CERT_KEYVAULT_URL",
        "FASTMCP_SERVER_AUTH_AZURE_CERT_CERTIFICATE_NAME",
        "FASTMCP_SERVER_AUTH_AZURE_CERT_KEYVAULT_CLIENT_ID",
    ]

    logger.info("OAuth Provider Environment Variables:")
    all_set = True
    for var in oauth_env_vars:
        value = os.getenv(var)
        is_set = value is not None and value.strip() != ""
        logger.info(f"  {var}: {'SET' if is_set else 'NOT SET'}")
        if not is_set:
            all_set = False

    if all_set:
        logger.info("✓ All required OAuth environment variables are set")
    else:
        logger.warning("✗ Some required OAuth environment variables are missing")

    # Test OBO variables too
    obo_env_vars = [
        "USE_OBO",
        "KEYVAULT_URL",
        "AZURE_CLIENT_CERTIFICATE_NAME",
        "KEYVAULT_CLIENT_ID",
        "TENANT_ID",
        "APP_CLIENT_ID",
    ]

    logger.info("OBO Environment Variables:")
    for var in obo_env_vars:
        value = os.getenv(var)
        is_set = value is not None and value.strip() != ""
        logger.info(f"  {var}: {'SET' if is_set else 'NOT SET'}")


def main():
    """Main test function."""
    logger.info("=== AUTHENTICATION DEBUG TEST STARTED ===")

    # Test environment variables first
    test_environment_variables()

    # Test OAuth provider creation and token verification
    try:
        asyncio.run(test_token_verification())
    except Exception as e:
        logger.error(f"Async test failed: {str(e)}")

    logger.info("=== AUTHENTICATION DEBUG TEST COMPLETED ===")


if __name__ == "__main__":
    main()
