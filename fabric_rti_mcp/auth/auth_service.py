from typing import Dict, Optional

from fastmcp.server.dependencies import get_access_token

from fabric_rti_mcp.common import logger

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
        logger.info("Retrieving user information from access token")

        try:
            token = get_access_token()
            logger.info(f"Access token retrieved: {token is not None}")

            if token is None:
                logger.warning("No access token available")
                return {"azure_id": None, "email": None, "name": None, "job_title": None, "office_location": None}

            if not hasattr(token, "claims"):
                logger.warning("Access token does not have claims attribute")
                return {"azure_id": None, "email": None, "name": None, "job_title": None, "office_location": None}

            logger.info("Extracting user information from token claims")
            logger.debug(f"Available claims: {list(token.claims.keys()) if token.claims else 'No claims'}")

            # The AzureProvider stores user data in token claims
            user_info = {
                "azure_id": token.claims.get("sub"),
                "email": token.claims.get("email"),
                "name": token.claims.get("name"),
                "job_title": token.claims.get("job_title"),
                "office_location": token.claims.get("office_location"),
            }

            logger.info(f"User info extracted successfully - ID: {user_info['azure_id']}, Email: {user_info['email']}")
            return user_info

        except Exception as e:
            logger.error(f"Error retrieving user info: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            return {"azure_id": None, "email": None, "name": None, "job_title": None, "office_location": None}
