import logging
import os
import sys
from typing import Optional

from azure.identity import (
    ChainedTokenCredential,
    DefaultAzureCredential,
    ManagedIdentityCredential,
    OnBehalfOfCredential,
)
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.ingest import KustoStreamingIngestClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class KustoConnection:
    query_client: KustoClient
    ingestion_client: KustoStreamingIngestClient
    default_database: str

    def __init__(
        self,
        cluster_uri: str,
        useOBO: Optional[bool],
        user_token: Optional[str],
        default_database: Optional[str] = None,
    ):

        cluster_uri = sanitize_uri(cluster_uri)
        kcsb = KustoConnectionStringBuilder.with_azure_token_credential(
            connection_string=cluster_uri,
            credential_from_login_endpoint=lambda login_endpoint: self._get_credential(
                login_endpoint, useOBO, user_token
            ),
        )

        self.query_client = KustoClient(kcsb)
        self.ingestion_client = KustoStreamingIngestClient(kcsb)

        default_database = default_database or KustoConnectionStringBuilder.DEFAULT_DATABASE_NAME
        default_database = default_database.strip()
        self.default_database = default_database

    def _get_credential(
        self, login_endpoint: str, useOBO: Optional[bool], user_token: Optional[str]
    ) -> ChainedTokenCredential:
        if useOBO and user_token:
            cert = self._get_certificate_from_keyvault(
                keyvault_url=os.environ.get("KEYVAULT_URL", ""),
                certificate_name=os.environ.get("AZURE_CLIENT_CERTIFICATE_NAME", ""),
                client_id=os.environ.get("CLIENT_ID", ""),
            )
            return ChainedTokenCredential(
                OnBehalfOfCredential(
                    tenant_id=os.environ.get(
                        "TENANT_ID", ""
                    ),
                    user_assertion=user_token,
                    client_id=os.environ.get(
                        "CLIENT_ID", ""
                    ),
                    client_certificate=cert,  
                )
            )

        return DefaultAzureCredential(
            exclude_shared_token_cache_credential=True,
            exclude_interactive_browser_credential=False,
            authority=login_endpoint,
        )

    def _get_certificate_from_keyvault(
        self, keyvault_url: str, certificate_name: str, client_id: Optional[str] = None
    ) -> bytes:
        """
        Retrieve a certificate from Azure Key Vault using managed identity.

        Args:
            keyvault_url: The URL of the Key Vault (e.g., "https://your-keyvault.vault.azure.net/")
            certificate_name: Name of the certificate in the Key Vault
            client_id: Optional client ID of the managed identity (if using user-assigned MI)

        Returns:
            Tuple of (certificate_bytes, certificate_format)

        Raises:
            Exception: If certificate retrieval fails
        """
        try:
            # Create credential - DefaultAzureCredential will try multiple auth methods
            # including managed identity
            credential = ManagedIdentityCredential(client_id=client_id)
            cert_client = CertificateClient(vault_url=keyvault_url, credential=credential)
            logger.info(f"Retrieving certificate '{certificate_name}' from Key Vault")

            # Get the certificate
            certificate = cert_client.get_certificate(certificate_name)

            logger.info(f"Successfully retrieved certificate: {certificate.name}")
            if certificate.properties and certificate.properties.x509_thumbprint:
                logger.info(f"Certificate thumbprint: {certificate.properties.x509_thumbprint.hex()}")
            else:
                logger.info("Certificate thumbprint: Not available")

            # The certificate object contains metadata, but to get the actual certificate data
            # we need to get it as a secret (which contains the private key if available)
            secret_client = SecretClient(vault_url=keyvault_url, credential=credential)

            # Get the certificate with private key as a secret
            certificate_secret = secret_client.get_secret(certificate_name)

            # The secret value contains the certificate in PFX format (with private key)
            if certificate_secret.value:
                certificate_bytes = certificate_secret.value.encode("utf-8")
            else:
                raise Exception("Certificate secret value is empty")

            return certificate_bytes

        except Exception as e:
            logger.error(f"Failed to retrieve certificate: {str(e)}")
            raise


def sanitize_uri(cluster_uri: str) -> str:
    cluster_uri = cluster_uri.strip()
    if cluster_uri.endswith("/"):
        cluster_uri = cluster_uri[:-1]
    return cluster_uri
