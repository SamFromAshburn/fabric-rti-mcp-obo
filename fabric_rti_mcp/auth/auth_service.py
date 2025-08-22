from typing import Dict, Optional

from fastmcp.server.dependencies import get_access_token

# Create a local FastMCP instance for tool definitions


class AuthService:
    """Service for handling user authentication and authorization."""

    @staticmethod
    def get_user_info() -> Dict[str, Optional[str]]:
        """Returns information about the authenticated Azure user.

        Returns:
            Dict containing user information including azure_id, email, name,
            job_title, and office_location. Values will be None if not available.
        """
        token = get_access_token()
        if token is None or not hasattr(token, "claims"):
            return {"azure_id": None, "email": None, "name": None, "job_title": None, "office_location": None}

        # The AzureProvider stores user data in token claims
        return {
            "azure_id": token.claims.get("sub"),
            "email": token.claims.get("email"),
            "name": token.claims.get("name"),
            "job_title": token.claims.get("job_title"),
            "office_location": token.claims.get("office_location"),
        }
