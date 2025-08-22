from __future__ import annotations

import os
from typing import Any

from azure.identity import ManagedIdentityCredential
from azure.keyvault.certificates import CertificateClient
from fastmcp.server.auth.providers.bearer import BearerAuthProvider
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class AzureBearerTokenProvider(BearerAuthProvider):
    """Azure Bearer Token Provider for Azure/Microsoft Entra ID.

    This provider validates Azure AD/Entra ID JWT tokens using JWKS endpoint
    for signature verification and validates standard Azure token claims.

    Environment Variables:
        - APP_CLIENT_ID: Azure application (client) ID
        - TENANT_ID: Azure tenant ID
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        tenant_id: str | None = None,
        keyvault_url: str | None = None,
        certificate_name: str | None = None,
        keyvault_client_id: str | None = None,
        required_scopes: list[str] | None = None,
        **kwargs: Any,
    ):
        """Initialize Azure Bearer Token Provider.

        Args:
            client_id: Azure application (client) ID
            tenant_id: Azure tenant ID
            required_scopes: List of required scopes for token validation
            **kwargs: Additional arguments passed to BearerAuthProvider
        """
        self.client_id = client_id or os.getenv("APP_CLIENT_ID", "")
        self.tenant_id = tenant_id or os.getenv("TENANT_ID", "")
        self.keyvault_url = keyvault_url or os.getenv("KEYVAULT_URL", "")
        self.certificate_name = certificate_name or os.getenv("AZURE_CLIENT_CERTIFICATE_NAME", "")
        self.keyvault_client_id = keyvault_client_id or os.getenv("KEYVAULT_CLIENT_ID", "")

        if not self.client_id:
            raise ValueError("client_id is required - set via parameter or APP_CLIENT_ID environment variable")

        if not self.tenant_id:
            raise ValueError("tenant_id is required - set via parameter or TENANT_ID environment variable")

        # Azure AD JWKS endpoint for token signature verification
        # jwks_uri = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"

        # Azure token issuer format
        issuer = f"https://sts.windows.net/{self.tenant_id}/"

        # API audience - typically the client ID for Azure apps
        audience = f"api://{self.client_id}"

        # Default required scopes if none provided
        scopes = required_scopes or ["https://graph.microsoft.com/.default"]

        public_key_pem = self._get_certificate_from_keyvault()

        # Initialize parent BearerAuthProvider with Azure-specific configuration
        super().__init__(
            issuer=issuer,
            public_key=public_key_pem,  # Use extracted public key for verification
            algorithm="RS256",  # Azure Entra ID uses RS256
            audience=audience,
            required_scopes=scopes,
            **kwargs,
        )

        logger.info(
            "Initialized Azure Bearer Token Provider for client %s with tenant %s",
            self.client_id,
            self.tenant_id,
        )

    def _get_certificate_from_keyvault(self) -> str:
        """Retrieve certificate from Azure Key Vault and extract public key.

        Returns:
            PEM-encoded public key extracted from the certificate
        """
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        try:
            # Create credential using managed identity
            credential = ManagedIdentityCredential(client_id=self.keyvault_client_id)
            certificate_client = CertificateClient(vault_url=self.keyvault_url, credential=credential)

            logger.info(f"Retrieving certificate '{self.certificate_name}' from Key Vault")
            certificate = certificate_client.get_certificate(self.certificate_name)
            logger.info(f"Successfully retrieved certificate: {self.certificate_name}")

            # Extract the public key from the certificate
            cert_bytes = certificate.cer  # This is in DER format
            if cert_bytes is None:
                raise Exception("Certificate does not contain DER-encoded data")
            x509_cert = x509.load_der_x509_certificate(bytes(cert_bytes), default_backend())
            public_key = x509_cert.public_key()

            if not public_key:
                raise Exception("No public key could be extracted from the certificate")

            # Serialize public key to PEM format string
            from cryptography.hazmat.primitives import serialization

            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            logger.info(f"Successfully extracted public key from certificate: {self.certificate_name}")
            return public_key_pem.decode()

        except Exception as e:
            logger.error(f"Failed to retrieve certificate or extract public key from Key Vault: {str(e)}")
            raise
