"""
Server with Azure certificate authentication support.

This approach bypasses FastMCP's OAuth when using certificates and handles
authentication directly through bearer tokens in HTTP headers.
"""

import os
import sys
from typing import Annotated, Any, Dict, List, Optional

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier

from fabric_rti_mcp import __version__
from fabric_rti_mcp.auth.auth_service import AuthService
from fabric_rti_mcp.common import logger
from fabric_rti_mcp.kusto.kusto_query_executor import KustoQueryExecutor
from fabric_rti_mcp.staticstrings import StaticStrings

# region Initialization
logger.info("Starting Fabric RTI MCP server")
logger.info(f"Version: {__version__}")
logger.info(f"Python version: {sys.version}")
logger.info(f"Platform: {sys.platform}")
logger.info(f"PID: {os.getpid()}")

# Log authentication-related environment variables
use_obo = os.getenv("USE_OBO", "").lower() == "true"
logger.info(f"USE_OBO: {use_obo}")
logger.info(f"BASE_URL: {os.getenv('BASE_URL', 'not set')}")

# Log OBO-related environment variables
obo_env_vars = ["KEYVAULT_URL", "AZURE_CLIENT_CERTIFICATE_NAME", "KEYVAULT_CLIENT_ID", "TENANT_ID", "APP_CLIENT_ID"]

logger.info("OBO Environment Variables:")
for var in obo_env_vars:
    value = os.getenv(var)
    logger.info(f"  {var}: {'set' if value else 'not set'}")

cert_auth_handler = None

if use_obo:
    try:
        # Initialize JWT Verifier for OBO flow. This verifier does not exchange tokens for
        # downstream. This happens when making the call in the tool.
        tenant_id = os.getenv("TENANT_ID", "")
        client_id = os.getenv("APP_CLIENT_ID", "")
        jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        
        # Accept both api:// prefixed and plain client ID as audience
        # This handles tokens requested with different resource formats
        audiences = [f"api://{client_id}", client_id]
        
        verifier = JWTVerifier(
            jwks_uri=jwks_url,
            issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            audience=audiences,
        )
        mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0", auth=verifier)
    except Exception as e:
        logger.error(f"Failed to initialize MCP Server: {e}")
        raise RuntimeError(f"Bearer Token setup failed: {e}")
else:
    # Create FastMCP instance without OAuth provider
    # No Authentication will be handled. Meant for local dev.
    mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
# endregion

# region Tools
# region Tools


@mcp.tool(name="get_user_info", description="Retrieves information about the authenticated Azure user.")
def get_user_info2() -> Dict[str, Optional[str]]:
    logger.info("=== GET_USER_INFO TOOL CALLED ===")
    try:
        result = AuthService.get_user_info()
        logger.info(f"User info retrieved: {result}")
        logger.info("=== GET_USER_INFO TOOL COMPLETED ===")
        return result
    except Exception as e:
        logger.error(f"Error in get_user_info tool: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.info("=== GET_USER_INFO TOOL FAILED ===")
        raise


@mcp.tool(name="kusto_query", description="Executes a KQL query on the specified Kusto database.")
def kusto_query(
    query: Annotated[str, "The KQL query to execute."],
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Optional[Annotated[str, "Optional database name. If not provided, uses the default database."]] = None,
) -> List[Dict[str, Any]]:
    """Execute Kusto query with certificate-based authentication when available."""
    logger.info("=== KUSTO_QUERY TOOL CALLED ===")
    logger.info(f"Query: {query[:100]}..." if len(query) > 100 else f"Query: {query}")
    logger.info(f"Cluster URI: {cluster_uri}")
    logger.info(f"Database: {database}")

    try:
        result = KustoQueryExecutor().execute(query, cluster_uri, readonly_override=False, database=database)
        logger.info(f"Kusto query returned {len(result)} rows")
        logger.info("=== KUSTO_QUERY TOOL COMPLETED ===")
        return result
    except Exception as e:
        logger.error(f"Error in kusto_query tool: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.info("=== KUSTO_QUERY TOOL FAILED ===")
        raise


@mcp.tool(name="kusto_command", description="Executes a Kusto management command on the specified database.")
def kusto_command(
    command: Annotated[str, "Executes a kusto management command on the specified database"],
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Optional[Annotated[str, "Optional database name. If not provided, uses the default database."]] = None,
) -> List[Dict[str, Any]]:
    """Execute Kusto command with certificate-based authentication when available."""
    return KustoQueryExecutor().execute(command, cluster_uri, readonly_override=True, database=database)


@mcp.tool(name="show_database", description="Retrieves a list of all databases in the Kusto cluster.")
def show_database(cluster_uri: Annotated[str, StaticStrings.cluster_uri]) -> List[Dict[str, Any]]:
    """Show databases with certificate-based authentication when available."""
    return KustoQueryExecutor().execute(".show databases", cluster_uri, readonly_override=True)


@mcp.tool(name="show_tables", description="Retrieves a list of all tables in the specified database.")
def show_tables(
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Annotated[str, "Name of the database to list tables from."],
) -> List[Dict[str, Any]]:
    """Show tables with certificate-based authentication when available."""
    return KustoQueryExecutor().execute(".show tables", cluster_uri, readonly_override=True, database=database)


# endregion
