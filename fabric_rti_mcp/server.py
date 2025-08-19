import os
import sys

from mcp.server.fastmcp import FastMCP
from fabric_rti_mcp import __version__
from fabric_rti_mcp.common import logger
from fabric_rti_mcp.eventstream import eventstream_tools
from fabric_rti_mcp.kusto import kusto_config, kusto_tools

def register_tools(mcp: FastMCP) -> None:
    logger.info("Kusto configuration keys found in environment:")
    logger.info(", ".join(kusto_config.KustoConfig.existing_env_vars()))
    kusto_tools.register_tools(mcp)
    eventstream_tools.register_tools(mcp)

def main() -> None:
    # writing to stderr because stdout is used for the transport
    # and we want to see the logs in the console
    logger.info("Starting Fabric RTI MCP server")
    logger.info(f"Version: {__version__}")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {sys.platform}")
    logger.error(f"PID: {os.getpid()}")
    # import later to allow for environment variables to be set from command line
    mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0", json_response=True)
    register_tools(mcp)
    logger.info(f"Registering tools for transport: streamable-http")
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()