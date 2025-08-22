"""Test global timeout configuration for Kusto tools."""

import os
from unittest.mock import patch

from fabric_rti_mcp.kusto.kusto_config import KustoConfig


def test_config_loads_timeout_from_env() -> None:
    """Test that KustoConfig loads timeout from FABRIC_RTI_KUSTO_TIMEOUT environment variable."""
    with patch.dict(os.environ, {"FABRIC_RTI_KUSTO_TIMEOUT": "300"}):
        test_config = KustoConfig.from_env()
        assert test_config.timeout_seconds == 300


def test_config_handles_invalid_timeout() -> None:
    """Test that KustoConfig handles invalid timeout values gracefully."""
    with patch.dict(os.environ, {"FABRIC_RTI_KUSTO_TIMEOUT": "invalid"}):
        test_config = KustoConfig.from_env()
        assert test_config.timeout_seconds is None


def test_config_no_timeout_env() -> None:
    """Test that KustoConfig handles missing environment variable."""
    with patch.dict(os.environ, {}, clear=True):
        test_config = KustoConfig.from_env()
        assert test_config.timeout_seconds is None
