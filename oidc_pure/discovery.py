"""OIDC Discovery implementation."""

import httpx

from oidc_pure.exceptions import DiscoveryError, NetworkError
from oidc_pure.models import OIDCConfig


class OIDCDiscovery:
    """
    OIDC Discovery client for retrieving provider configuration.

    Implements OpenID Connect Discovery as specified in:
    https://openid.net/specs/openid-connect-discovery-1_0.html
    """

    def __init__(self, client: httpx.Client | None = None):
        """
        Initialize discovery client.

        Args:
            client: Optional httpx.Client for custom configuration
        """
        self._client = client
        self._own_client = client is None

    def __enter__(self):
        """Context manager entry."""
        if self._own_client:
            self._client = httpx.Client(timeout=30.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._own_client and self._client:
            self._client.close()

    def discover(self, issuer_url: str) -> OIDCConfig:
        """
        Discover OIDC provider configuration.

        Args:
            issuer_url: The issuer URL (e.g., https://keycloak.example.com/realms/myrealm)

        Returns:
            OIDCConfig with provider configuration

        Raises:
            DiscoveryError: If discovery fails
            NetworkError: If network request fails
        """
        # Normalize issuer URL (remove trailing slash)
        issuer_url = issuer_url.rstrip("/")

        # Build discovery URL
        discovery_url = f"{issuer_url}/.well-known/openid-configuration"

        try:
            client = self._client or httpx.Client(timeout=30.0)
            response = client.get(discovery_url)
            response.raise_for_status()

            data = response.json()

            # Validate required fields
            required_fields = [
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
                "userinfo_endpoint",
            ]

            missing_fields = [f for f in required_fields if f not in data]
            if missing_fields:
                raise DiscoveryError(
                    f"Discovery response missing required fields: {missing_fields}"
                )

            # Validate issuer matches
            if data["issuer"] != issuer_url:
                raise DiscoveryError(
                    f"Issuer mismatch: expected {issuer_url}, got {data['issuer']}"
                )

            return OIDCConfig.from_dict(data)

        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"HTTP error during discovery: {e.response.status_code}",
                error_code="http_error",
            ) from e
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error during discovery: {e}",
                error_code="network_error",
            ) from e
        except (KeyError, ValueError) as e:
            raise DiscoveryError(
                f"Invalid discovery response: {e}",
                error_code="invalid_response",
            ) from e
        finally:
            if self._own_client and not self._client:
                client.close()

    async def discover_async(self, issuer_url: str) -> OIDCConfig:
        """
        Discover OIDC provider configuration (async version).

        Args:
            issuer_url: The issuer URL

        Returns:
            OIDCConfig with provider configuration

        Raises:
            DiscoveryError: If discovery fails
            NetworkError: If network request fails
        """
        issuer_url = issuer_url.rstrip("/")
        discovery_url = f"{issuer_url}/.well-known/openid-configuration"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(discovery_url)
                response.raise_for_status()

                data = response.json()

                required_fields = [
                    "issuer",
                    "authorization_endpoint",
                    "token_endpoint",
                    "jwks_uri",
                    "userinfo_endpoint",
                ]

                missing_fields = [f for f in required_fields if f not in data]
                if missing_fields:
                    raise DiscoveryError(
                        f"Discovery response missing required fields: {missing_fields}"
                    )

                if data["issuer"] != issuer_url:
                    raise DiscoveryError(
                        f"Issuer mismatch: expected {issuer_url}, got {data['issuer']}"
                    )

                return OIDCConfig.from_dict(data)

        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"HTTP error during discovery: {e.response.status_code}",
                error_code="http_error",
            ) from e
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error during discovery: {e}",
                error_code="network_error",
            ) from e
        except (KeyError, ValueError) as e:
            raise DiscoveryError(
                f"Invalid discovery response: {e}",
                error_code="invalid_response",
            ) from e
