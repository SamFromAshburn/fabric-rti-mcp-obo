"""Custom authentication handler for certificate-based Azure authentication.

This module provides a custom authentication approach that bypasses FastMCP's
OAuth proxy when using certificate-based authentication with Azure.
"""

import os
from typing import Dict, Optional

from azure.identity import ManagedIdentityCredential, OnBehalfOfCredential
from azure.keyvault.secrets import SecretClient
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class CertificateAuthHandler:
    """Handles certificate-based authentication for Azure scenarios."""

    def __init__(self):
        self.keyvault_url = os.getenv("KEYVAULT_URL", "")
        self.certificate_name = os.getenv("AZURE_CLIENT_CERTIFICATE_NAME", "")
        self.keyvault_client_id = os.getenv("KEYVAULT_CLIENT_ID", "")
        self.app_client_id = os.getenv("APP_CLIENT_ID", "")
        self.tenant_id = os.getenv("TENANT_ID", "")

        if not all([self.keyvault_url, self.certificate_name, self.app_client_id, self.tenant_id]):
            raise ValueError("Missing required environment variables for certificate authentication")

    def get_certificate_from_keyvault(self) -> bytes:
        """Retrieve certificate from Azure Key Vault."""
        try:
            credential = ManagedIdentityCredential(client_id=self.keyvault_client_id)
            secret_client = SecretClient(vault_url=self.keyvault_url, credential=credential)

            logger.info(f"Retrieving certificate '{self.certificate_name}' from Key Vault")
            certificate_secret = secret_client.get_secret(self.certificate_name)

            if not certificate_secret.value:
                raise Exception("Certificate secret value is empty")

            logger.info(f"Successfully retrieved certificate: {self.certificate_name}")
            return certificate_secret.value.encode("utf-8")

        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Key Vault: {str(e)}")
            raise

    def create_obo_credential(self, user_token: str) -> OnBehalfOfCredential:
        """Create OnBehalfOfCredential for the user token."""
        certificate = self.get_certificate_from_keyvault()

        return OnBehalfOfCredential(
            tenant_id=self.tenant_id,
            user_assertion=user_token,
            client_id=self.app_client_id,
            client_certificate=certificate,
        )

    def get_user_info_from_token(self, access_token: str) -> Dict[str, Optional[str]]:
        """Extract user information from access token using Microsoft Graph."""
        import asyncio

        import httpx

        async def _get_user_info() -> Dict[str, Optional[str]]:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/me",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "User-Agent": "FastMCP-Azure-Certificate",
                    },
                )

                if response.status_code == 200:
                    user_data = response.json()
                    return {
                        "azure_id": user_data.get("id"),
                        "email": user_data.get("mail") or user_data.get("userPrincipalName"),
                        "name": user_data.get("displayName"),
                        "job_title": user_data.get("jobTitle"),
                        "office_location": user_data.get("officeLocation"),
                    }
                else:
                    logger.warning(f"Failed to get user info: {response.status_code}")
                    return {
                        "azure_id": None,
                        "email": None,
                        "name": None,
                        "job_title": None,
                        "office_location": None,
                    }

        try:
            return asyncio.run(_get_user_info())
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            return {
                "azure_id": None,
                "email": None,
                "name": None,
                "job_title": None,
                "office_location": None,
            }
