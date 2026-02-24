"""Integration tests with real Keycloak instance.

These tests require environment variables to be set:
- KEYCLOAK_URL: e.g., https://sso.apps.alcoal.net.br/auth/
- KEYCLOAK_REALM: e.g., SUDES
- CLIENT_ID: OAuth2 client ID
- CLIENT_SECRET: OAuth2 client secret
- TEST_USERNAME: (Optional) Test user username for Resource Owner Password Credentials
- TEST_PASSWORD: (Optional) Test user password

Note: MFA-protected flows cannot be fully automated in tests.
For flows requiring MFA, the tests will guide you through manual steps
or use client credentials flow which doesn't require user authentication.
"""

import os

import pytest

from oidc_pure import OIDCClient
from oidc_pure.exceptions import TokenError


@pytest.mark.integration
class TestKeycloakIntegration:
    """Integration tests with real Keycloak instance."""

    def test_discovery(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
    ):
        """Test OIDC discovery with real Keycloak."""
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        from oidc_pure.discovery import OIDCDiscovery

        discovery = OIDCDiscovery()
        config = discovery.discover(integration_issuer_url)

        assert config.issuer == integration_issuer_url
        assert config.authorization_endpoint
        assert config.token_endpoint
        assert config.userinfo_endpoint
        assert config.jwks_uri
        assert "authorization_code" in config.grant_types_supported

        print("\n✓ Discovery successful")
        print(f"  Issuer: {config.issuer}")
        print(f"  Authorization endpoint: {config.authorization_endpoint}")
        print(f"  Token endpoint: {config.token_endpoint}")

    def test_client_initialization(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Test OIDCClient initialization with real Keycloak."""
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        client = OIDCClient(
            issuer_url=integration_issuer_url,
            client_id=integration_client_id,
            client_secret=integration_client_secret,
        )

        assert client.config is not None
        assert client.config.issuer == integration_issuer_url

        print("\n✓ Client initialization successful")
        print(f"  Client ID: {integration_client_id}")
        print(f"  Issuer: {integration_issuer_url}")

    def test_client_credentials_flow(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Test client credentials flow with real Keycloak.

        Note: This flow works without user authentication and MFA.
        It requires the client to be configured for client credentials grant.
        """
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        client = OIDCClient(
            issuer_url=integration_issuer_url,
            client_id=integration_client_id,
            client_secret=integration_client_secret,
        )

        try:
            # Attempt client credentials flow
            token = client.client_credentials_grant()

            assert token.access_token
            assert token.token_type == "Bearer"

            print("\n✓ Client credentials flow successful")
            print(f"  Access token: {token.access_token[:20]}...")
            print(f"  Token type: {token.token_type}")
            print(f"  Expires in: {token.expires_in}s")

        except TokenError as e:
            # Client might not be configured for client credentials
            pytest.skip(f"Client credentials flow not available: {e.message}")

    def test_authorization_url_generation(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Test authorization URL generation.

        This test generates an authorization URL that could be used
        to initiate the authorization code flow. Due to MFA requirements,
        the actual flow cannot be automated.
        """
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        client = OIDCClient(
            issuer_url=integration_issuer_url,
            client_id=integration_client_id,
            client_secret=integration_client_secret,
            redirect_uri="http://localhost:8080/callback",
        )

        auth_url, state, verifier = client.get_authorization_url(scope="openid profile email")

        assert auth_url.startswith(client.config.authorization_endpoint)
        assert state
        assert verifier

        print("\n✓ Authorization URL generated successfully")
        print(f"  URL: {auth_url[:100]}...")
        print(f"  State: {state[:20]}...")
        print(f"  Verifier: {verifier[:20]}...")
        print("\nTo complete the flow manually:")
        print("1. Open the authorization URL in a browser")
        print("2. Log in with your credentials and complete MFA")
        print("3. Copy the 'code' parameter from the redirect URL")
        print("4. Use the code with the state and verifier to exchange for tokens")

    def test_resource_owner_password_credentials_with_mfa_note(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Test note about Resource Owner Password Credentials with MFA.

        This test documents that ROPC flow cannot work with MFA enabled.
        MFA requires interactive user authentication which is incompatible
        with automated testing.
        """
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        print("\n⚠ Note about MFA and automated testing:")
        print("  ")
        print("  The Keycloak instance has MFA enabled, which means:")
        print("  1. Resource Owner Password Credentials (ROPC) flow won't work")
        print("  2. Authorization Code Flow requires interactive browser authentication")
        print("  3. Automated testing is limited to:")
        print("     - Client Credentials Flow (no user context)")
        print("     - Discovery and configuration validation")
        print("     - Token validation and parsing")
        print("  ")
        print("  For testing with MFA:")
        print("  - Use client credentials for service-to-service authentication")
        print("  - Manually test authorization code flow in a browser")
        print("  - Consider using a test realm without MFA for automated tests")

    def test_token_introspection_endpoint_availability(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Test if token introspection endpoint is available."""
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        client = OIDCClient(
            issuer_url=integration_issuer_url,
            client_id=integration_client_id,
            client_secret=integration_client_secret,
        )

        # Check if introspection endpoint is in the configuration
        if hasattr(client.config, "introspection_endpoint"):
            print("\n✓ Token introspection endpoint available")
            print(f"  Endpoint: {client.config.introspection_endpoint}")
        else:
            print("\n⚠ Token introspection endpoint not advertised in discovery document")

    def test_supported_features(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Test and display supported features from Keycloak."""
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        client = OIDCClient(
            issuer_url=integration_issuer_url,
            client_id=integration_client_id,
            client_secret=integration_client_secret,
        )

        config = client.config

        print("\n✓ Keycloak Configuration:")
        print(f"  Scopes supported: {', '.join(config.scopes_supported)}")
        print(f"  Response types: {', '.join(config.response_types_supported)}")
        print(f"  Grant types: {', '.join(config.grant_types_supported)}")
        print(
            f"  Token endpoint auth methods: {', '.join(config.token_endpoint_auth_methods_supported)}"
        )
        print(f"  PKCE methods: {', '.join(config.code_challenge_methods_supported)}")

        assert "authorization_code" in config.grant_types_supported
        assert "openid" in config.scopes_supported


@pytest.mark.integration
@pytest.mark.manual
class TestManualAuthorizationFlow:
    """Manual integration tests requiring user interaction.

    These tests require manual steps and cannot run in CI/CD.
    Run them with: pytest -v -m manual
    """

    def test_full_authorization_code_flow_manual(
        self,
        integration_enabled: bool,
        integration_issuer_url: str,
        integration_client_id: str,
        integration_client_secret: str,
    ):
        """Manual test for full authorization code flow with PKCE.

        This test guides you through the manual authorization process.
        """
        if not integration_enabled:
            pytest.skip("Integration tests disabled - missing environment variables")

        print("\n" + "=" * 70)
        print("MANUAL TEST: Authorization Code Flow with PKCE")
        print("=" * 70)

        client = OIDCClient(
            issuer_url=integration_issuer_url,
            client_id=integration_client_id,
            client_secret=integration_client_secret,
            redirect_uri="http://localhost:8080/callback",
        )

        # Step 1: Generate authorization URL
        auth_url, state, verifier = client.get_authorization_url(scope="openid profile email")

        print("\nStep 1: Authorization URL generated")
        print(f"  URL: {auth_url}")
        print("\nStep 2: Complete these actions manually:")
        print("  1. Open the URL above in your browser")
        print("  2. Log in with your username and password")
        print("  3. Complete the MFA challenge")
        print("  4. After redirect, copy the FULL redirect URL")
        print("  5. Set it as TEST_CALLBACK_URL environment variable")
        print("\nStep 3: Run this test again after setting TEST_CALLBACK_URL")

        callback_url = os.getenv("TEST_CALLBACK_URL")
        if not callback_url:
            pytest.skip("TEST_CALLBACK_URL not set - complete manual steps above first")

        # Step 4: Exchange code for token
        print("\nStep 4: Exchanging authorization code for tokens...")
        try:
            token = client.handle_authorization_response(
                response_url=callback_url,
                expected_state=state,
                code_verifier=verifier,
            )

            print("\n✓ Token exchange successful!")
            print(f"  Access token: {token.access_token[:20]}...")
            print(f"  Token type: {token.token_type}")
            print(f"  Expires in: {token.expires_in}s")
            if token.refresh_token:
                print(f"  Refresh token: {token.refresh_token[:20]}...")
            if token.id_token:
                print(f"  ID token: {token.id_token[:20]}...")

            # Step 5: Get user info
            if token.access_token:
                print("\nStep 5: Fetching user information...")
                user_info = client.get_user_info(token.access_token)

                print("\n✓ User info retrieved!")
                print(f"  Subject: {user_info.sub}")
                print(f"  Name: {user_info.name}")
                print(f"  Email: {user_info.email}")
                print(f"  Username: {user_info.preferred_username}")

            # Step 6: Test token refresh if available
            if token.refresh_token:
                print("\nStep 6: Testing token refresh...")
                new_token = client.refresh_access_token(token.refresh_token)

                print("\n✓ Token refresh successful!")
                print(f"  New access token: {new_token.access_token[:20]}...")

            print("\n" + "=" * 70)
            print("✓ FULL AUTHORIZATION FLOW COMPLETED SUCCESSFULLY!")
            print("=" * 70)

        except Exception as e:
            print(f"\n✗ Error during token exchange: {e}")
            raise
