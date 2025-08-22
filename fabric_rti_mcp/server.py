import os
import sys
from typing import Annotated, Any, Dict, List, Optional

from fastmcp import FastMCP
from fastmcp.server.auth.providers.azure import AzureProvider

from fabric_rti_mcp import __version__
from fabric_rti_mcp.auth.auth_service import AuthService
from fabric_rti_mcp.common import logger
from fabric_rti_mcp.kusto.kusto_query_executor import KustoQueryExecutor
from fabric_rti_mcp.staticstrings import StaticStrings

# region Initialization
# writing to stderr because stdout is used for the transport
# and we want to see the logs in the console
logger.info("Starting Fabric RTI MCP server")
logger.info(f"Version: {__version__}")
logger.info(f"Python version: {sys.version}")
logger.info(f"Platform: {sys.platform}")
logger.info(f"PID: {os.getpid()}")
logger.info(f"USE OBO: {os.getenv('USE_OBO', '')}")

if os.getenv("USE_OBO", "").lower() == "true":
    # Documentation: https://gofastmcp.com/integrations/azure
    auth_provider = AzureProvider(
        client_id=os.getenv("APP_CLIENT_ID", ""),  # Your Azure App Client ID
        tenant_id=os.getenv("TENANT_ID", ""),  # Your Azure Tenant ID (REQUIRED)
        base_url=os.getenv("BASE_URL", ""),  # Must match your App registration
        required_scopes=["User.Read", "email", "openid", "profile"],  # Microsoft Graph permissions
        # redirect_path="/auth/callback"                  # Default value, customize if needed
    )
    mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0", auth=auth_provider)
else:
    mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")

# endregion


# region Tools
@mcp.tool(name="get_user_info", description="Retrieves information about the authenticated Azure user.")
def get_user_info() -> Dict[str, Optional[str]]:
    return AuthService.get_user_info()


@mcp.tool(name="kusto_query", description="Executes a KQL query on the specified Kusto database.")
def kusto_query(
    query: Annotated[str, "The KQL query to execute."],
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Optional[Annotated[str, "Optional database name. If not provided, uses the default database."]] = None,
) -> List[Dict[str, Any]]:
    return KustoQueryExecutor().execute(query, cluster_uri, False, database)


@mcp.tool(name="kusto_command", description="Executes a Kusto management command on the specified database.")
def kusto_command(
    command: Annotated[str, "Executes a kusto management command on the specified database"],
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Optional[Annotated[str, "Optional database name. If not provided, uses the default database."]] = None,
) -> List[Dict[str, Any]]:
    return KustoQueryExecutor().execute(command, cluster_uri, database=database)


@mcp.tool(name="show_database", description="Retrieves a list of all databases in the Kusto cluster.")
def show_database(cluster_uri: Annotated[str, StaticStrings.cluster_uri]) -> List[Dict[str, Any]]:
    return KustoQueryExecutor().execute(".show databases", cluster_uri)


@mcp.tool(name="show_tables", description="Retrieves a list of all tables in the specified database.")
def show_tables(
    cluster_uri: Annotated[str, StaticStrings.cluster_uri],
    database: Annotated[str, "Name of the database to list tables from."],
) -> List[Dict[str, Any]]:
    return KustoQueryExecutor().execute(".show tables", cluster_uri, database=database)


# endregion
