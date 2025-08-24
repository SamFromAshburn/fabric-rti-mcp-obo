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
        logger.info(f"Initializing KustoConnection for cluster: {cluster_uri}")
        logger.info(f"Use OBO: {useOBO}")
        logger.info(f"User token provided: {user_token is not None}")
        logger.info(f"Default database: {default_database}")

        cluster_uri = sanitize_uri(cluster_uri)
        logger.info(f"Sanitized cluster URI: {cluster_uri}")

        try:
            kcsb = KustoConnectionStringBuilder.with_azure_token_credential(
                connection_string=cluster_uri,
                credential_from_login_endpoint=lambda login_endpoint: self._get_credential(
                    login_endpoint, useOBO, user_token
                ),
            )
            logger.info("KustoConnectionStringBuilder created successfully")

            self.query_client = KustoClient(kcsb)
            logger.info("KustoClient created successfully")

            self.ingestion_client = KustoStreamingIngestClient(kcsb)
            logger.info("KustoStreamingIngestClient created successfully")

            default_database = default_database or KustoConnectionStringBuilder.DEFAULT_DATABASE_NAME
            default_database = default_database.strip()
            self.default_database = default_database
            logger.info(f"Default database set to: {self.default_database}")

        except Exception as e:
            logger.error(f"Failed to initialize KustoConnection: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            raise

    def _get_credential(
        self, login_endpoint: str, useOBO: Optional[bool], user_token: Optional[str]
    ) -> ChainedTokenCredential:
        logger.info(f"Creating credential for login endpoint: {login_endpoint}")
        logger.info(f"Use OBO: {useOBO}")
        logger.info(f"User token available: {user_token is not None}")

        if useOBO and user_token:
            logger.info("Creating OnBehalfOfCredential for OBO authentication")

            # Log environment variables (without sensitive values)
            keyvault_url = os.environ.get("KEYVAULT_URL", "")
            certificate_name = os.environ.get("AZURE_CLIENT_CERTIFICATE_NAME", "")
            keyvault_client_id = os.environ.get("KEYVAULT_CLIENT_ID", "")
            tenant_id = os.environ.get("TENANT_ID", "")
            app_client_id = os.environ.get("APP_CLIENT_ID", "")

            logger.info(f"Key Vault URL: {keyvault_url}")
            logger.info(f"Certificate name: {certificate_name}")
            logger.info(f"Key Vault client ID: {keyvault_client_id}")
            logger.info(f"Tenant ID: {tenant_id}")
            logger.info(f"App client ID: {app_client_id}")

            if not all([keyvault_url, certificate_name, tenant_id, app_client_id]):
                logger.error("Missing required environment variables for OBO authentication")
                raise ValueError("Missing required environment variables for OBO authentication")

            try:
                cert = self._get_certificate_from_keyvault(
                    keyvault_url=keyvault_url,
                    certificate_name=certificate_name,
                    client_id=keyvault_client_id,
                )
                logger.info("Certificate retrieved successfully for OBO credential")

                obo_credential = OnBehalfOfCredential(
                    tenant_id=tenant_id,
                    user_assertion=user_token,
                    client_id=app_client_id,
                    client_certificate=cert,
                )
                logger.info("OnBehalfOfCredential created successfully")

                return ChainedTokenCredential(obo_credential)

            except Exception as e:
                logger.error(f"Failed to create OnBehalfOfCredential: {str(e)}")
                raise

        logger.info("Creating DefaultAzureCredential for standard authentication")
        try:
            credential = DefaultAzureCredential(
                exclude_shared_token_cache_credential=True,
                exclude_interactive_browser_credential=False,
                authority=login_endpoint,
            )
            logger.info("DefaultAzureCredential created successfully")
            return credential
        except Exception as e:
            logger.error(f"Failed to create DefaultAzureCredential: {str(e)}")
            raise

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
            logger.info(f"Creating ManagedIdentityCredential with client ID: {client_id}")
            credential = ManagedIdentityCredential(client_id=client_id)

            cert_client = CertificateClient(vault_url=keyvault_url, credential=credential)
            logger.info(f"Retrieving certificate '{certificate_name}' from Key Vault: {keyvault_url}")

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
            logger.info("Created SecretClient for retrieving certificate private key")

            # Get the certificate with private key as a secret
            certificate_secret = secret_client.get_secret(certificate_name)
            logger.info("Certificate secret retrieved successfully")

            # The secret value contains the certificate in PFX format (with private key)
            if certificate_secret.value:
                certificate_bytes = certificate_secret.value.encode("utf-8")
                logger.info(f"Certificate bytes retrieved (length: {len(certificate_bytes)})")
            else:
                logger.error("Certificate secret value is empty")
                raise Exception("Certificate secret value is empty")

            return certificate_bytes

        except Exception as e:
            logger.error(f"Failed to retrieve certificate from Key Vault: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Key Vault URL: {keyvault_url}")
            logger.error(f"Certificate name: {certificate_name}")
            logger.error(f"Client ID: {client_id}")
            raise


def sanitize_uri(cluster_uri: str) -> str:
    cluster_uri = cluster_uri.strip()
    if cluster_uri.endswith("/"):
        cluster_uri = cluster_uri[:-1]
    return cluster_uri
