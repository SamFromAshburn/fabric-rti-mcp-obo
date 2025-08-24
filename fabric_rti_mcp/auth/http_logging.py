"""HTTP request/response logging utilities for debugging authentication issues."""

import logging

import httpx

logger = logging.getLogger(__name__)


class HttpLoggingTransport(httpx.HTTPTransport):
    """HTTP transport that logs requests and responses for debugging."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Handle HTTP request with logging."""
        # Log request details
        logger.info(f"HTTP Request: {request.method} {request.url}")
        logger.info(f"Request headers: {dict(request.headers)}")

        # Log request body (be careful with sensitive data)
        if request.content:
            content_str = request.content.decode("utf-8", errors="ignore")
            if len(content_str) > 1000:
                logger.debug(f"Request body (first 1000 chars): {content_str[:1000]}...")
            else:
                logger.debug(f"Request body: {content_str}")

        # Execute the request
        response = super().handle_request(request)

        # Log response details
        logger.info(f"HTTP Response: {response.status_code} {response.reason_phrase}")
        logger.info(f"Response headers: {dict(response.headers)}")

        # Log response body for error cases
        if response.status_code >= 400:
            try:
                response_text = response.text
                if len(response_text) > 2000:
                    logger.error(f"Error response body (first 2000 chars): {response_text[:2000]}...")
                else:
                    logger.error(f"Error response body: {response_text}")
            except Exception as e:
                logger.error(f"Could not read response body: {e}")

        return response


class AsyncHttpLoggingTransport(httpx.AsyncHTTPTransport):
    """Async HTTP transport that logs requests and responses for debugging."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Handle async HTTP request with logging."""
        # Log request details
        logger.info(f"Async HTTP Request: {request.method} {request.url}")
        logger.info(f"Request headers: {dict(request.headers)}")

        # Log request body (be careful with sensitive data)
        if request.content:
            content_str = request.content.decode("utf-8", errors="ignore")
            if len(content_str) > 1000:
                logger.debug(f"Request body (first 1000 chars): {content_str[:1000]}...")
            else:
                logger.debug(f"Request body: {content_str}")

        # Execute the request
        response = await super().handle_async_request(request)

        # Log response details
        logger.info(f"Async HTTP Response: {response.status_code} {response.reason_phrase}")
        logger.info(f"Response headers: {dict(response.headers)}")

        # Log response body for error cases
        if response.status_code >= 400:
            try:
                response_text = response.text
                if len(response_text) > 2000:
                    logger.error(f"Error response body (first 2000 chars): {response_text[:2000]}...")
                else:
                    logger.error(f"Error response body: {response_text}")
            except Exception as e:
                logger.error(f"Could not read response body: {e}")

        return response


def create_logging_client(timeout: int = 10) -> httpx.Client:
    """Create an httpx client with request/response logging."""
    return httpx.Client(transport=HttpLoggingTransport(), timeout=timeout)


def create_async_logging_client(timeout: int = 10) -> httpx.AsyncClient:
    """Create an async httpx client with request/response logging."""
    return httpx.AsyncClient(transport=AsyncHttpLoggingTransport(), timeout=timeout)
