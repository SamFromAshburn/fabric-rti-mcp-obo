"""
Server with Azure certificate authentication support.

This approach bypasses FastMCP's OAuth when using certificates and handles
authentication directly through bearer tokens in HTTP headers.
"""

import os
import sys
from typing import Annotated, Any, Dict, List, Optional

from fastmcp import FastMCP

from fabric_rti_mcp import __version__
from fabric_rti_mcp.auth.auth_service import AuthService
from fabric_rti_mcp.auth.azure_certificate_provider import AzureCertificateProvider
from fabric_rti_mcp.common import logger
from fabric_rti_mcp.kusto.kusto_query_executor import KustoQueryExecutor
from fabric_rti_mcp.staticstrings import StaticStrings

# region Initialization
logger.info("Starting Fabric RTI MCP server")
logger.info(f"Version: {__version__}")
logger.info(f"Python version: {sys.version}")
logger.info(f"Platform: {sys.platform}")
logger.info(f"PID: {os.getpid()}")
logger.info(f"USE OBO: {os.getenv('USE_OBO', '')}")

use_obo = os.getenv("USE_OBO", "").lower() == "true"
cert_auth_handler = None

if use_obo:
    try:
        # Documentation: https://gofastmcp.com/integrations/azure
        # FastMCP's Azure Provider does NOT accept certificates, only azure secrets. 
        # This overrides this behavior.
        provider = AzureCertificateProvider()
        logger.info("Certificate authentication handler initialized")
        mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0", auth=provider)
    except Exception as e:
        logger.error(f"Failed to initialize certificate authentication: {e}")
        raise RuntimeError(f"Certificate authentication setup failed: {e}")
else:
    # Create FastMCP instance without OAuth provider
    # No Authentication will be handled. Meant for local dev.
    mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0")
    logger.info("FastMCP initialized without OAuth (using certificate authentication)")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")

# endregion

# region Tools


@mcp.tool(name="get_user_info", description="Retrieves information about the authenticated Azure user.")
def get_user_info2() -> Dict[str, Optional[str]]:
    return AuthService.get_user_info()


@mcp.tool(name="kusto_query", description="Executes a KQL query on the specified Kusto database.")
def kusto_query(
    query: Annotated[str, "The KQL query to execute."],
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Optional[Annotated[str, "Optional database name. If not provided, uses the default database."]] = None,
) -> List[Dict[str, Any]]:
    """Execute Kusto query with certificate-based authentication when available."""
    return KustoQueryExecutor().execute(query, cluster_uri, readonly_override=False, database=database)


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
