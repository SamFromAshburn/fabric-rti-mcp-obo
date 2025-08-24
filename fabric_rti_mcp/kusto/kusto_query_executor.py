from __future__ import annotations

import inspect
import os
import uuid
from typing import Any, Dict, List, Optional

from azure.kusto.data import ClientRequestProperties, KustoConnectionStringBuilder
from fastmcp.server.dependencies import AccessToken, get_access_token

from fabric_rti_mcp import __version__  # type: ignore
from fabric_rti_mcp.common import logger
from fabric_rti_mcp.kusto.kusto_config import KustoConfig
from fabric_rti_mcp.kusto.kusto_connection import KustoConnection, sanitize_uri
from fabric_rti_mcp.kusto.kusto_response_formatter import format_results

CONFIG = KustoConfig.from_env()
_DEFAULT_DB_NAME = KustoConnectionStringBuilder.DEFAULT_DATABASE_NAME


class KustoConnectionManager:
    def __init__(self) -> None:
        self._cache: Dict[str, KustoConnection] = {}

    def get(self, cluster_uri: str, use_obo: bool, user_token: Optional[str]) -> KustoConnection:
        """
        Retrieves a cached or new KustoConnection for the given URI.
        This method is the single entry point for accessing connections.
        """
        sanitized_uri = sanitize_uri(cluster_uri)

        if sanitized_uri in self._cache:
            return self._cache[sanitized_uri]

        # Connection not found, create a new one.
        known_services = KustoConfig.get_known_services()
        default_database = _DEFAULT_DB_NAME

        if sanitized_uri in known_services:
            default_database = known_services[sanitized_uri].default_database or _DEFAULT_DB_NAME
        elif not CONFIG.allow_unknown_services:
            raise ValueError(
                f"Service URI '{sanitized_uri}' is not in the list of approved services, "
                "and unknown connections are not permitted by the administrator."
            )

        connection = KustoConnection(
            sanitized_uri, useOBO=use_obo, user_token=user_token, default_database=default_database
        )

        self._cache[sanitized_uri] = connection
        return connection


class KustoQueryExecutor:
    """Handles execution of Kusto queries and commands with proper authentication and request properties."""

    def __init__(self) -> None:
        self._connection_manager = KustoConnectionManager()

    def _create_client_request_properties(
        self, action: str, is_destructive: bool, ignore_readonly: bool
    ) -> ClientRequestProperties:
        """Creates and configures ClientRequestProperties for a Kusto request."""
        crp: ClientRequestProperties = ClientRequestProperties()
        crp.application = f"fabric-rti-mcp{{{__version__}}}"  # type: ignore
        crp.client_request_id = f"KFRTI_MCP.{action}:{str(uuid.uuid4())}"  # type: ignore

        if not is_destructive and not ignore_readonly:
            crp.set_option("request_readonly", True)

        # Set global timeout if configured
        if CONFIG.timeout_seconds is not None:
            # Convert seconds to timespan format (HH:MM:SS)
            hours, remainder = divmod(CONFIG.timeout_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            timeout_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            crp.set_option("servertimeout", timeout_str)

        return crp

    def execute(
        self,
        query: str,
        cluster_uri: str,
        readonly_override: bool = False,
        database: Optional[str] = None,
        user_token_override: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Executes a Kusto query or command and returns formatted results.

        Args:
            query: The KQL query or command to execute
            cluster_uri: The Kusto cluster URI
            readonly_override: Whether to override readonly restrictions
            database: Optional database name
            user_token_override: Optional user token for certificate-based auth
        """
        caller_frame = inspect.currentframe().f_back  # type: ignore
        action_name = caller_frame.f_code.co_name  # type: ignore
        caller_func = caller_frame.f_globals.get(action_name)  # type: ignore
        is_destructive = hasattr(caller_func, "_is_destructive")

        use_obo = os.environ.get("USE_OBO", "false").lower() == "true"
        logger.info(f"Executing Kusto query with OBO mode: {use_obo}")
        logger.info(f"Target cluster URI: {cluster_uri}")
        logger.info(f"Database: {database or 'default'}")
        logger.info(f"Query length: {len(query)} characters")
        logger.info(f"Readonly override: {readonly_override}")

        # Try to get user token from override first, then from FastMCP context
        user_token_string: Optional[str] = None
        if user_token_override:
            user_token_string = user_token_override
            logger.info("Using provided user token override")
        else:
            user_token: AccessToken | None = get_access_token()
            if user_token:
                user_token_string = user_token.token
                logger.info("Retrieved user token from FastMCP context")
                logger.debug(f"Token length: {len(user_token_string)} characters")
                logger.debug(f"Token scopes: {getattr(user_token, 'scopes', 'unknown')}")
            else:
                logger.warning("No access token available from FastMCP context")

        if use_obo and user_token_string is None:
            logger.error("OBO mode enabled but no access token available")
            raise ValueError("No access token available for authentication (OBO mode requires user token)")
        elif not use_obo:
            logger.info("OBO mode disabled, proceeding without user token")

        connection = self._connection_manager.get(cluster_uri, use_obo, user_token_string)
        logger.info(f"Retrieved Kusto connection for URI: {cluster_uri}")

        client = connection.query_client
        logger.info("Retrieved Kusto query client from connection")

        # agents can send messy inputs
        query = query.strip()
        logger.debug(f"Cleaned query: {query[:100]}..." if len(query) > 100 else f"Query: {query}")

        database = database or connection.default_database
        database = database.strip()
        logger.info(f"Using database: {database}")

        crp = self._create_client_request_properties(action_name, is_destructive, readonly_override)
        logger.info(f"Created client request properties for action: {action_name}")
        logger.info(f"Request ID: {getattr(crp, 'client_request_id', 'unknown')}")

        try:
            logger.info("Executing Kusto query...")
            result_set = client.execute(database, query, crp)
            logger.info("Kusto query executed successfully")

            formatted_results = format_results(result_set)
            logger.info(f"Query returned {len(formatted_results)} rows")
            return formatted_results

        except Exception as e:
            logger.error(f"Kusto query execution failed: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Query that failed: {query}")
            logger.error(f"Database: {database}")
            raise
