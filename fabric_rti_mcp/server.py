import os
import sys

from fastmcp.server.auth.providers.jwt import JWTVerifier
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
    logger.info(f"PID: {os.getpid()}")
    logger.info(f"USE OBO: {os.getenv('USE_OBO', '')}")

    if os.getenv("USE_OBO", "").lower() == "true":
        # Documentation:
        APP_CLIENT_ID = os.getenv("APP_CLIENT_ID")
        TENANT_ID = os.getenv("TENANT_ID")
        # API audience
        API_AUDIENCE = f"api://{APP_CLIENT_ID}"

        # Azure Entra ID JWKS endpoint
        JWKS_URI = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

        # Configure Bearer Token authentication for Azure Entra ID
        logger.info("Configuring Bearer Token authentication with audience: %s", API_AUDIENCE)
        verifier = JWTVerifier(
            jwks_uri=JWKS_URI,
            issuer=f"https://sts.windows.net/{TENANT_ID}/",  # Match the token's issuer format in the API
            algorithm="RS256",  # Azure Entra ID uses RS256
            audience=API_AUDIENCE,  # required audience
            required_scopes=["execute"],  # Optional: add required scopes if needed
        )

        # import later to allow for environment variables to be set from command line
        mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0", token_verifier=verifier)
    else:
        mcp = FastMCP(name="fabric-rti-mcp-server", port=80, host="0.0.0.0")

    register_tools(mcp)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
