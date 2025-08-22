"""Custom Azure OAuth provider for FastMCP with certificate-based authentication.

This provider extends the standard Azure provider to support certificate-based
authentication instead of client secrets, compatible with OBO (On-Behalf-Of) flows.
"""

from __future__ import annotations

import os

import httpx
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class AzureCertificateTokenVerifier(TokenVerifier):
    """Token verifier for Azure tokens using Microsoft Graph API."""

    def __init__(self, required_scopes: list[str] | None = None, timeout_seconds: int = 10):
        self.required_scopes = required_scopes or []
        self.timeout_seconds = timeout_seconds

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify an Azure access token using Microsoft Graph API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                # Use Microsoft Graph API to validate token and get user info
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/me",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "User-Agent": "FastMCP-Azure-Certificate-OAuth",
                    },
                )

                if response.status_code != 200:
                    logger.debug(
                        "Azure token verification failed: %d - %s",
                        response.status_code,
                        response.text[:200],
                    )
                    return None

                user_data = response.json()

                # Create AccessToken with Azure user info
                return AccessToken(
                    token=token,
                    client_id=str(user_data.get("id", "unknown")),
                    scopes=self.required_scopes or [],
                    expires_at=None,
                    claims={
                        "sub": user_data.get("id"),
                        "email": user_data.get("mail") or user_data.get("userPrincipalName"),
                        "name": user_data.get("displayName"),
                        "job_title": user_data.get("jobTitle"),
                        "office_location": user_data.get("officeLocation"),
                    },
                )
        except Exception as e:
            logger.debug("Azure token verification error: %s", str(e))
            return None


class AzureCertificateProvider(OAuthProxy):
    """Azure OAuth provider with certificate-based authentication.

    This provider supports certificate-based authentication for Azure/Microsoft Entra ID
    OAuth flows, retrieving certificates from Azure Key Vault for secure authentication.

    Environment Variables Required:
        - TENANT_ID: Azure tenant ID
        - APP_CLIENT_ID: Azure application (client) ID
        - KEYVAULT_URL: Azure Key Vault URL
        - AZURE_CLIENT_CERTIFICATE_NAME: Certificate name in Key Vault
        - KEYVAULT_CLIENT_ID: Client ID for Key Vault access (managed identity)
        - BASE_URL: Public URL of your FastMCP server
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        tenant_id: str | None = None,
        base_url: str | None = None,
        redirect_path: str = "/auth/callback",
        required_scopes: list[str] | None = None,
        timeout_seconds: int = 10,
        keyvault_url: str | None = None,
        certificate_name: str | None = None,
        keyvault_client_id: str | None = None,
    ):
        """Initialize Azure Certificate OAuth provider.

        Args:
            client_id: Azure application (client) ID
            tenant_id: Azure tenant ID
            base_url: Public URL of your FastMCP server
            redirect_path: Redirect path (defaults to "/auth/callback")
            required_scopes: Required scopes (defaults to ["User.Read", "email", "openid", "profile"])
            timeout_seconds: HTTP request timeout
            keyvault_url: Azure Key Vault URL
            certificate_name: Certificate name in Key Vault
            keyvault_client_id: Client ID for Key Vault access
        """
        # Get configuration from environment or parameters
        self.client_id = client_id or os.getenv("APP_CLIENT_ID", "")
        self.tenant_id = tenant_id or os.getenv("TENANT_ID", "")
        self.base_url = base_url or os.getenv("BASE_URL", "http://localhost:8000")
        self.keyvault_url = keyvault_url or os.getenv("KEYVAULT_URL", "")
        self.certificate_name = certificate_name or os.getenv("AZURE_CLIENT_CERTIFICATE_NAME", "")
        self.keyvault_client_id = keyvault_client_id or os.getenv("KEYVAULT_CLIENT_ID", "")

        # Validate required settings
        if not self.client_id:
            raise ValueError("client_id is required - set via parameter or APP_CLIENT_ID environment variable")

        if not self.tenant_id:
            raise ValueError("tenant_id is required - set via parameter or TENANT_ID environment variable")

        if not self.keyvault_url:
            raise ValueError("keyvault_url is required - set via parameter or KEYVAULT_URL environment variable")

        if not self.certificate_name:
            raise ValueError(
                "certificate_name is required - set via parameter or AZURE_CLIENT_CERTIFICATE_NAME environment variable"
            )

        # Default scopes for Azure
        self.scopes = required_scopes or [
            "User.Read",
            "email",
            "openid",
            "profile",
        ]

        # Get certificate from Key Vault
        try:
            self.client_certificate = self._get_certificate_from_keyvault()
        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Key Vault: {e}")
            raise ValueError(f"Certificate retrieval failed: {e}")

        # Create token verifier
        token_verifier = AzureCertificateTokenVerifier(
            required_scopes=self.scopes,
            timeout_seconds=timeout_seconds,
        )

        # Build Azure OAuth endpoints
        authorization_endpoint = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        token_endpoint = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        # Initialize OAuth proxy with certificate-based authentication
        super().__init__(
            upstream_authorization_endpoint=authorization_endpoint,
            upstream_token_endpoint=token_endpoint,
            upstream_client_id=self.client_id,
            upstream_client_secret="",  # Not used with certificate auth
            token_verifier=token_verifier,
            base_url=self.base_url,
            redirect_path=redirect_path,
            issuer_url=self.base_url,
        )

        logger.info(
            "Initialized Azure Certificate OAuth provider for client %s with tenant %s",
            self.client_id,
            self.tenant_id,
        )

    def _get_certificate_from_keyvault(self) -> str:
        """Retrieve certificate from Azure Key Vault.

        Returns:
            Base64-encoded certificate with private key
        """
        try:
            # Create credential using managed identity
            credential = ManagedIdentityCredential(client_id=self.keyvault_client_id)
            secret_client = SecretClient(vault_url=self.keyvault_url, credential=credential)

            logger.info(f"Retrieving certificate '{self.certificate_name}' from Key Vault")

            # Get the certificate with private key as a secret
            certificate_secret = secret_client.get_secret(self.certificate_name)

            if not certificate_secret.value:
                raise Exception("Certificate secret value is empty")

            logger.info(f"Successfully retrieved certificate: {self.certificate_name}")

            # Return the certificate in the format expected by Azure authentication
            return certificate_secret.value

        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Key Vault: {str(e)}")
            raise
