from __future__ import annotations

import inspect
import os
import uuid
from typing import Any, Dict, List, Optional

from azure.kusto.data import ClientRequestProperties, KustoConnectionStringBuilder
from fastmcp.server.dependencies import AccessToken, get_access_token

from fabric_rti_mcp import __version__  # type: ignore
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
            sanitized_uri, default_database=default_database, useOBO=use_obo, user_token=user_token
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
    ) -> List[Dict[str, Any]]:
        """Executes a Kusto query or command and returns formatted results."""
        caller_frame = inspect.currentframe().f_back  # type: ignore
        action_name = caller_frame.f_code.co_name  # type: ignore
        caller_func = caller_frame.f_globals.get(action_name)  # type: ignore
        is_destructive = hasattr(caller_func, "_is_destructive")

        use_obo = os.environ.get("USE_OBO", "false").lower() == "true"
        user_token: AccessToken | None = get_access_token()
        if use_obo and user_token is None:
            raise ValueError("No access token available for authentication")

        connection = self._connection_manager.get(cluster_uri, use_obo, user_token.token if user_token else None)
        client = connection.query_client

        # agents can send messy inputs
        query = query.strip()

        database = database or connection.default_database
        database = database.strip()

        crp = self._create_client_request_properties(action_name, is_destructive, readonly_override)
        result_set = client.execute(database, query, crp)
        return format_results(result_set)
