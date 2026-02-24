"""Tests for OIDC discovery."""

import httpx
import pytest
import respx

from oidc_pure.discovery import OIDCDiscovery
from oidc_pure.exceptions import DiscoveryError, NetworkError
from oidc_pure.models import OIDCConfig


class TestOIDCDiscovery:
    """Tests for OIDCDiscovery class."""

    def test_context_manager(self):
        """Test that OIDCDiscovery works as context manager."""
        with OIDCDiscovery() as discovery:
            assert discovery._client is not None

    @respx.mock
    def test_discover_success(self, mock_issuer_url: str, mock_discovery_response: dict):
        """Test successful OIDC discovery."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=mock_discovery_response)
        )

        discovery = OIDCDiscovery()
        config = discovery.discover(mock_issuer_url)

        assert isinstance(config, OIDCConfig)
        assert config.issuer == mock_issuer_url
        assert config.authorization_endpoint == mock_discovery_response["authorization_endpoint"]
        assert config.token_endpoint == mock_discovery_response["token_endpoint"]
        assert config.userinfo_endpoint == mock_discovery_response["userinfo_endpoint"]
        assert config.jwks_uri == mock_discovery_response["jwks_uri"]

    @respx.mock
    def test_discover_trailing_slash(self, mock_issuer_url: str, mock_discovery_response: dict):
        """Test discovery with trailing slash in issuer URL."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=mock_discovery_response)
        )

        discovery = OIDCDiscovery()
        config = discovery.discover(f"{mock_issuer_url}/")

        assert config.issuer == mock_issuer_url

    @respx.mock
    def test_discover_missing_required_fields(self, mock_issuer_url: str):
        """Test discovery failure with missing required fields."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        incomplete_response = {"issuer": mock_issuer_url}
        respx.get(discovery_url).mock(return_value=httpx.Response(200, json=incomplete_response))

        discovery = OIDCDiscovery()
        with pytest.raises(DiscoveryError, match="missing required fields"):
            discovery.discover(mock_issuer_url)

    @respx.mock
    def test_discover_issuer_mismatch(self, mock_issuer_url: str, mock_discovery_response: dict):
        """Test discovery failure with issuer mismatch."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        mock_discovery_response["issuer"] = "https://different-issuer.com"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=mock_discovery_response)
        )

        discovery = OIDCDiscovery()
        with pytest.raises(DiscoveryError, match="Issuer mismatch"):
            discovery.discover(mock_issuer_url)

    @respx.mock
    def test_discover_http_error(self, mock_issuer_url: str):
        """Test discovery failure with HTTP error."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(return_value=httpx.Response(404))

        discovery = OIDCDiscovery()
        with pytest.raises(NetworkError, match="HTTP error"):
            discovery.discover(mock_issuer_url)

    @respx.mock
    def test_discover_network_error(self, mock_issuer_url: str):
        """Test discovery failure with network error."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(side_effect=httpx.ConnectError("Connection failed"))

        discovery = OIDCDiscovery()
        with pytest.raises(NetworkError, match="Network error"):
            discovery.discover(mock_issuer_url)

    @respx.mock
    def test_discover_invalid_json(self, mock_issuer_url: str):
        """Test discovery failure with invalid JSON response."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(return_value=httpx.Response(200, text="invalid json"))

        discovery = OIDCDiscovery()
        with pytest.raises(DiscoveryError, match="Invalid discovery response"):
            discovery.discover(mock_issuer_url)

    @respx.mock
    def test_discover_with_custom_client(self, mock_issuer_url: str, mock_discovery_response: dict):
        """Test discovery with custom HTTP client."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=mock_discovery_response)
        )

        custom_client = httpx.Client(timeout=60.0)
        discovery = OIDCDiscovery(client=custom_client)
        config = discovery.discover(mock_issuer_url)

        assert config.issuer == mock_issuer_url
        custom_client.close()
