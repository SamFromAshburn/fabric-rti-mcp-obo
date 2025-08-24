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

from azure.identity import ManagedIdentityCredential
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.utilities.logging import get_logger
from fastmcp.utilities.types import NotSet, NotSetT
from pydantic_settings import BaseSettings, SettingsConfigDict

from fabric_rti_mcp.auth.http_logging import create_async_logging_client

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

        logger.info("AzureCertificateOAuthProvider initialized with the following settings:")
        logger.info(f"  Client ID: {settings.client_id}")
        logger.info(f"  Tenant ID: {settings.tenant_id}")
        logger.info(f"  Key Vault URL: {settings.keyvault_url}")
        logger.info(f"  Certificate Name: {settings.certificate_name}")
        logger.info(f"  Base URL: {base_url_final}")
        logger.info(f"  Redirect Path: {redirect_path_final}")
        logger.info(f"  Required Scopes: {scopes_final}")
        logger.info(f"  Timeout Seconds: {settings.timeout_seconds}")
        logger.info(f"  Authorization Endpoint: {authorization_endpoint}")
        logger.info(f"  Token Endpoint: {token_endpoint}")
        logger.info(f"  Key Vault Client ID: {settings.keyvault_client_id}")

        # Create token verifier before initializing OAuth proxy
        logger.info("Creating token verifier for OAuth proxy...")
        token_verifier = self._create_token_verifier(scopes_final)
        logger.info("Token verifier created successfully")

        # Initialize OAuth proxy - we'll override the token exchange method
        logger.info("Initializing OAuth proxy with certificate-based authentication...")
        super().__init__(
            upstream_authorization_endpoint=authorization_endpoint,
            upstream_token_endpoint=token_endpoint,
            upstream_client_id=settings.client_id,
            upstream_client_secret="",  # Not used with certificate auth
            token_verifier=token_verifier,
            base_url=base_url_final,
            redirect_path=redirect_path_final,
            issuer_url=base_url_final,
        )
        logger.info("OAuth proxy initialized successfully")

    def _create_client_assertion(self) -> str:
        """Create a JWT client assertion for certificate-based authentication."""
        logger.info("Creating client assertion for certificate-based authentication")
        logger.info(f"Using keyvault URL: {self.settings.keyvault_url}")
        logger.info(f"Using certificate name: {self.settings.certificate_name}")
        logger.info(f"Using keyvault client ID: {self.settings.keyvault_client_id}")

        from azure.keyvault.keys import KeyClient

        try:
            credential = ManagedIdentityCredential(client_id=self.settings.keyvault_client_id)
            logger.info("ManagedIdentityCredential created successfully")

            key_client = KeyClient(vault_url=str(self.settings.keyvault_url), credential=credential)
            logger.info("KeyClient created successfully")

            key = key_client.get_key(str(self.settings.certificate_name))
            logger.info(f"Key retrieved successfully: {key.name}")

            crypto_client = CryptographyClient(key, credential=credential)
            logger.info("CryptographyClient created successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Key Vault components: {str(e)}")
            raise

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

        logger.info("JWT payload created with the following claims:")
        logger.info(f"  iss (issuer): {payload['iss']}")
        logger.info(f"  sub (subject): {payload['sub']}")
        logger.info(f"  aud (audience): {payload['aud']}")
        logger.info(f"  jti (JWT ID): {payload['jti']}")
        logger.info(f"  exp (expiration): {payload['exp']}")
        logger.info(f"  iat (issued at): {payload['iat']}")

        # Encode header and payload
        def b64url_encode(data: dict[str, Any]) -> bytes:
            return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=")

        try:
            encoded_header = b64url_encode(header)
            encoded_payload = b64url_encode(payload)
            message = encoded_header + b"." + encoded_payload
            logger.info("JWT header and payload encoded successfully")

            # Sign the message
            sign_result = crypto_client.sign(SignatureAlgorithm.rs256, message)
            signature = base64.urlsafe_b64encode(sign_result.signature).rstrip(b"=")
            logger.info("JWT message signed successfully")

            # Construct JWT
            jwt_token = message + b"." + signature
            logger.info("JWT client assertion created successfully")
            logger.debug(f"Client assertion length: {len(jwt_token.decode())} characters")
            return jwt_token.decode()
        except Exception as e:
            logger.error(f"Failed to create JWT client assertion: {str(e)}")
            raise

    def _create_token_verifier(self, scopes: list[str]) -> TokenVerifier:
        """Create token verifier that validates tokens via Microsoft Graph."""
        logger.info("Creating CertificateTokenVerifier instance")
        logger.info(f"Required scopes: {scopes}")
        logger.info(f"Timeout seconds: {self.settings.timeout_seconds or 10}")

        class CertificateTokenVerifier(TokenVerifier):
            def __init__(self, required_scopes: list[str], timeout: int = 10):
                super().__init__(required_scopes=required_scopes)
                self.timeout = timeout
                logger.info(f"CertificateTokenVerifier initialized with timeout: {timeout}")
                logger.info(f"CertificateTokenVerifier required scopes: {required_scopes}")

            async def verify_token(self, token: str) -> AccessToken | None:
                """Verify token by calling Microsoft Graph API."""
                logger.info("=== TOKEN VERIFICATION STARTED ===")
                logger.info("Starting token verification via Microsoft Graph API")
                logger.debug(f"Token length: {len(token)} characters")
                logger.debug(f"Token prefix: {token[:20]}..." if len(token) > 20 else f"Token: {token}")

                try:
                    # Use the logging client for better debugging
                    client = create_async_logging_client(timeout=self.timeout)
                    async with client as http_client:
                        logger.info("Making request to Microsoft Graph API /me endpoint")
                        response = await http_client.get(
                            "https://graph.microsoft.com/v1.0/me",
                            headers={"Authorization": f"Bearer {token}", "User-Agent": "FastMCP-Azure-Certificate"},
                        )

                        logger.info(f"Microsoft Graph API response: {response.status_code}")

                        if response.status_code != 200:
                            logger.warning(f"Token verification failed with status {response.status_code}")
                            logger.info("=== TOKEN VERIFICATION FAILED ===")
                            return None

                        user_data = response.json()
                        logger.info("Token verification successful")
                        logger.info(f"User ID: {user_data.get('id', 'unknown')}")
                        logger.info(
                            f"User email: {user_data.get('mail') or user_data.get('userPrincipalName', 'unknown')}"
                        )
                        logger.info(f"User name: {user_data.get('displayName', 'unknown')}")

                        access_token = AccessToken(
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
                        logger.info("AccessToken created successfully")
                        logger.info("=== TOKEN VERIFICATION COMPLETED ===")
                        return access_token

                except Exception as e:
                    logger.error(f"Error verifying token: {str(e)}")
                    logger.error(f"Exception type: {type(e).__name__}")
                    logger.info("=== TOKEN VERIFICATION ERROR ===")
                    return None

        verifier = CertificateTokenVerifier(scopes, self.settings.timeout_seconds or 10)
        logger.info("CertificateTokenVerifier instance created and returned")
        return verifier

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Override token exchange to use certificate-based authentication."""
        logger.info("Starting OAuth code exchange with certificate-based authentication")
        logger.info(f"Authorization code length: {len(code)} characters")
        logger.info(f"Redirect URI: {redirect_uri}")

        try:
            client_assertion = self._create_client_assertion()
            logger.info("Client assertion created successfully for token exchange")
        except Exception as e:
            logger.error(f"Failed to create client assertion: {str(e)}")
            raise

        token_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "client_id": str(self.settings.client_id),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        logger.info("Token exchange request data prepared:")
        logger.info(f"  grant_type: {token_data['grant_type']}")
        logger.info(f"  client_id: {token_data['client_id']}")
        logger.info(f"  client_assertion_type: {token_data['client_assertion_type']}")
        logger.info(f"  client_assertion length: {len(token_data['client_assertion'])} characters")
        logger.info(f"  code length: {len(token_data['code'])} characters")
        logger.info(f"  redirect_uri: {token_data['redirect_uri']}")

        token_endpoint = f"https://login.microsoftonline.com/{self.settings.tenant_id}/oauth2/v2.0/token"
        logger.info(f"Making token exchange request to: {token_endpoint}")

        try:
            # Use the logging client for better debugging
            client = create_async_logging_client()
            async with client as http_client:
                response = await http_client.post(
                    token_endpoint,
                    data=token_data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "FastMCP-Azure-Certificate",
                    },
                )

                logger.info(f"Token exchange response status: {response.status_code}")

                if response.status_code != 200:
                    logger.error(f"Token exchange failed with status {response.status_code}")
                    raise Exception(f"Token exchange failed with status {response.status_code}: {response.text}")

                response_data = response.json()
                logger.info("Token exchange successful")
                logger.info(f"Access token received (length: {len(response_data.get('access_token', ''))} characters)")
                logger.info(f"Token type: {response_data.get('token_type', 'unknown')}")
                logger.info(f"Expires in: {response_data.get('expires_in', 'unknown')} seconds")
                logger.info(f"Scope: {response_data.get('scope', 'unknown')}")

                return response_data

        except Exception as e:
            logger.error(f"HTTP request failed during token exchange: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            raise
