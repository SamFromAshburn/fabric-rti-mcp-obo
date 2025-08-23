"""Azure Certificate-based OAuth Provider.

This provider uses certificate-based client authentication instead of client secrets
for OAuth flows with Azure Entra ID.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from azure.identity import ManagedIdentityCredential
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.utilities.logging import get_logger
from fastmcp.utilities.types import NotSet, NotSetT
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = get_logger(__name__)


class AzureCertificateProviderSettings(BaseSettings):
    """Settings for Azure Certificate OAuth provider."""

    model_config = SettingsConfigDict(
        env_prefix="FASTMCP_SERVER_AUTH_AZURE_CERT_",
        env_file=".env",
        extra="ignore",
    )

    client_id: str | None = None
    tenant_id: str | None = None
    keyvault_url: str | None = None
    certificate_name: str | None = None
    keyvault_client_id: str | None = None
    base_url: str | None = None
    redirect_path: str | None = None
    required_scopes: list[str] | None = None
    timeout_seconds: int | None = None


class AzureCertificateOAuthProvider(OAuthProxy):
    """Azure OAuth provider using certificate-based client authentication with Key Vault.

    This provider uses certificates stored in Azure Key Vault instead of client secrets
    for authenticating to Azure during the OAuth flow. This is more secure and is
    preferred for production scenarios.

    Setup Requirements:
    1. Register an application in Azure Portal
    2. Upload a certificate to the app registration
    3. Store the certificate in Azure Key Vault
    4. Store the private key as a secret in Key Vault (named {certificate_name})
    5. Configure managed identity access to Key Vault

    Environment Variables:
        - FASTMCP_SERVER_AUTH_AZURE_CERT_CLIENT_ID: Azure application (client) ID
        - FASTMCP_SERVER_AUTH_AZURE_CERT_TENANT_ID: Azure tenant ID
        - FASTMCP_SERVER_AUTH_AZURE_CERT_KEYVAULT_URL: Azure Key Vault URL
        - FASTMCP_SERVER_AUTH_AZURE_CERT_CERTIFICATE_NAME: Certificate name in Key Vault
        - FASTMCP_SERVER_AUTH_AZURE_CERT_KEYVAULT_CLIENT_ID: Managed identity client ID for Key Vault access

    Example:
        ```python
        from fastmcp import FastMCP

        auth = AzureCertificateOAuthProvider(
            client_id="your-client-id",
            tenant_id="your-tenant-id",
            keyvault_url="https://your-keyvault.vault.azure.net/",
            certificate_name="your-certificate-name",
            keyvault_client_id="your-managed-identity-client-id",
            base_url="https://your-app.com"
        )

        mcp = FastMCP("My App", auth=auth)
        ```
    """

    def __init__(
        self,
        *,
        client_id: str | NotSetT = NotSet,
        tenant_id: str | NotSetT = NotSet,
        keyvault_url: str | NotSetT = NotSet,
        certificate_name: str | NotSetT = NotSet,
        keyvault_client_id: str | NotSetT = NotSet,
        base_url: str | NotSetT = NotSet,
        redirect_path: str | NotSetT = NotSet,
        required_scopes: list[str] | None | NotSetT = NotSet,
        timeout_seconds: int | NotSetT = NotSet,
    ):
        """Initialize Azure Certificate OAuth provider.

        Args:
            client_id: Azure application (client) ID
            tenant_id: Azure tenant ID
            keyvault_url: Azure Key Vault URL
            certificate_name: Name of certificate in Key Vault
            keyvault_client_id: Client ID for Key Vault access (managed identity)
            base_url: Public URL of your FastMCP server
            redirect_path: Redirect path for OAuth callbacks
            required_scopes: Required OAuth scopes
            timeout_seconds: HTTP request timeout
        """
        settings = AzureCertificateProviderSettings.model_validate(
            {
                k: v
                for k, v in {
                    "client_id": client_id,
                    "tenant_id": tenant_id,
                    "keyvault_url": keyvault_url,
                    "certificate_name": certificate_name,
                    "keyvault_client_id": keyvault_client_id,
                    "base_url": base_url,
                    "redirect_path": redirect_path,
                    "required_scopes": required_scopes,
                    "timeout_seconds": timeout_seconds,
                }.items()
                if v is not NotSet
            }
        )

        # Validate required settings
        if not settings.client_id:
            raise ValueError("client_id is required")
        if not settings.tenant_id:
            raise ValueError("tenant_id is required")
        if not settings.keyvault_url:
            raise ValueError("keyvault_url is required")
        if not settings.certificate_name:
            raise ValueError("certificate_name is required")

        self.settings = settings

        # Load certificate and private key from Key Vault
        # self._load_certificate_from_keyvault()

        # Apply defaults
        base_url_final = settings.base_url or "http://localhost:8000"
        redirect_path_final = settings.redirect_path or "/auth/callback"
        scopes_final = settings.required_scopes or [
            "User.Read",
            "email",
            "openid",
            "profile",
        ]

        # Build Azure OAuth endpoints
        authorization_endpoint = f"https://login.microsoftonline.com/{settings.tenant_id}/oauth2/v2.0/authorize"
        token_endpoint = f"https://login.microsoftonline.com/{settings.tenant_id}/oauth2/v2.0/token"

        # Initialize OAuth proxy - we'll override the token exchange method
        super().__init__(
            upstream_authorization_endpoint=authorization_endpoint,
            upstream_token_endpoint=token_endpoint,
            upstream_client_id=settings.client_id,
            upstream_client_secret="",  # Not used with certificate auth
            token_verifier=self._create_token_verifier(scopes_final),
            base_url=base_url_final,
            redirect_path=redirect_path_final,
            issuer_url=base_url_final,
        )

    def _create_client_assertion(self) -> str:
        """Create a JWT client assertion for certificate-based authentication."""

        from azure.keyvault.keys import KeyClient

        credential = ManagedIdentityCredential(client_id=self.settings.keyvault_client_id)
        key_client = KeyClient(vault_url=str(self.settings.keyvault_url), credential=credential)
        key = key_client.get_key(str(self.settings.certificate_name))
        crypto_client = CryptographyClient(key, credential=credential)

        # JWT header and payload
        header = {"alg": "RS256", "typ": "JWT"}
        payload: dict[str, Any] = {
            "iss": self.settings.client_id,
            "sub": self.settings.client_id,
            "aud": f"https://login.microsoftonline.com/{self.settings.tenant_id}/v2.0",
            "jti": str(uuid.uuid4()),
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        # Encode header and payload
        def b64url_encode(data: dict[str, Any]) -> bytes:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=")

        encoded_header = b64url_encode(header)
        encoded_payload = b64url_encode(payload)
        message = encoded_header + b"." + encoded_payload

        # Sign the message
        sign_result = crypto_client.sign(SignatureAlgorithm.rs256, message)
        signature = base64.urlsafe_b64encode(sign_result.signature).rstrip(b"=")

        # Construct JWT
        jwt_token = message + b"." + signature
        return jwt_token.decode()

    def _create_token_verifier(self, scopes: list[str]) -> TokenVerifier:
        """Create token verifier that validates tokens via Microsoft Graph."""

        class CertificateTokenVerifier(TokenVerifier):
            def __init__(self, required_scopes: list[str], timeout: int = 10):
                super().__init__(required_scopes=required_scopes)
                self.timeout = timeout

            async def verify_token(self, token: str) -> AccessToken | None:
                """Verify token by calling Microsoft Graph API."""
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        response = await client.get(
                            "https://graph.microsoft.com/v1.0/me", headers={"Authorization": f"Bearer {token}"}
                        )

                        if response.status_code != 200:
                            logger.warning(f"Token verification failed: {response.status_code}")
                            return None

                        user_data = response.json()

                        return AccessToken(
                            token=token,
                            client_id=str(user_data.get("id", "unknown")),
                            scopes=self.required_scopes or [],
                            expires_at=None,
                            claims={
                                "sub": user_data.get("id"),
                                "email": user_data.get("mail") or user_data.get("userPrincipalName"),
                                "name": user_data.get("displayName"),
                                "given_name": user_data.get("givenName"),
                                "family_name": user_data.get("surname"),
                                "job_title": user_data.get("jobTitle"),
                                "office_location": user_data.get("officeLocation"),
                            },
                        )
                except Exception as e:
                    logger.error(f"Error verifying token: {e}")
                    return None

        return CertificateTokenVerifier(scopes, self.settings.timeout_seconds or 10)

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Override token exchange to use certificate-based authentication."""
        client_assertion = self._create_client_assertion()

        token_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "client_id": str(self.settings.client_id),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://login.microsoftonline.com/{self.settings.tenant_id}/oauth2/v2.0/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                raise Exception("Token exchange failed")

            return response.json()
