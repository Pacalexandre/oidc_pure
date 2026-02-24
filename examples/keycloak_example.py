"""
Example usage of the OIDC Pure library with Keycloak.

This example demonstrates:
1. OIDC Discovery
2. Authorization Code Flow with PKCE
3. Token exchange
4. User info retrieval
5. Token refresh
6. Token validation
"""

import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from oidc_pure import OIDCClient

# Configuration for Keycloak
KEYCLOAK_URL = "https://keycloak.example.com/realms/myrealm"
CLIENT_ID = "my-client"
CLIENT_SECRET = "your-client-secret"  # Optional for public clients
REDIRECT_URI = "http://localhost:8080/callback"


# Global variables to store authorization data
auth_code = None
auth_state = None


class CallbackHandler(BaseHTTPRequestHandler):
    """Simple HTTP server to handle OAuth2 callback."""

    def do_GET(self):
        """Handle GET request to callback endpoint."""
        global auth_code, auth_state

        # Parse query parameters
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/callback":
            # Store full URL for processing
            full_url = f"http://localhost:8080{self.path}"

            # Check for error
            if "error" in params:
                error = params["error"][0]
                error_desc = params.get("error_description", [""])[0]
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"Error: {error} - {error_desc}".encode())
                return

            # Extract code and state
            if "code" in params:
                auth_code = full_url
                auth_state = params.get("state", [None])[0]

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Authorization successful! You can close this window.")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing authorization code")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress server logs."""
        pass


def example_authorization_code_flow():
    """
    Example: Authorization Code Flow with PKCE.

    This is the recommended flow for web applications and native apps.
    """
    print("=" * 60)
    print("Example: Authorization Code Flow with PKCE")
    print("=" * 60)

    # Initialize OIDC client
    print(f"\n1. Initializing OIDC client for {KEYCLOAK_URL}...")

    with OIDCClient(
        issuer_url=KEYCLOAK_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
    ) as client:
        print("   ✓ Discovery completed")
        print(f"   - Authorization endpoint: {client.config.authorization_endpoint}")
        print(f"   - Token endpoint: {client.config.token_endpoint}")
        print(f"   - Userinfo endpoint: {client.config.userinfo_endpoint}")

        # Generate authorization URL
        print("\n2. Generating authorization URL...")
        auth_url, state, code_verifier = client.get_authorization_url(
            scope=["openid", "profile", "email"],
            use_pkce=True,
        )

        print("   ✓ Authorization URL generated")
        print(f"   - State: {state[:20]}...")
        print(f"   - Code verifier: {code_verifier[:20] if code_verifier else 'None'}...")

        # Open browser for user authorization
        print("\n3. Opening browser for user authorization...")
        print(f"   URL: {auth_url}")

        # Start local server to receive callback
        server = HTTPServer(("localhost", 8080), CallbackHandler)

        # Open browser
        webbrowser.open(auth_url)

        print("   Waiting for authorization callback...")

        # Wait for callback (handle single request)
        server.handle_request()

        if not auth_code:
            print("   ✗ Authorization failed or was cancelled")
            return

        print("   ✓ Authorization code received")

        # Exchange code for tokens
        print("\n4. Exchanging authorization code for tokens...")

        try:
            token_response = client.handle_authorization_response(
                response_url=auth_code,
                expected_state=state,
                code_verifier=code_verifier,
            )

            print("   ✓ Tokens received")
            print(f"   - Access token: {token_response.access_token[:20]}...")
            print(f"   - Token type: {token_response.token_type}")
            print(f"   - Expires in: {token_response.expires_in} seconds")

            if token_response.refresh_token:
                print(f"   - Refresh token: {token_response.refresh_token[:20]}...")
            if token_response.id_token:
                print(f"   - ID token: {token_response.id_token[:20]}...")

            # Get user information
            print("\n5. Retrieving user information...")

            user_info = client.get_user_info(token_response.access_token)

            print("   ✓ User info retrieved")
            print(f"   - Subject: {user_info.sub}")
            print(f"   - Name: {user_info.name}")
            print(f"   - Email: {user_info.email}")
            print(f"   - Username: {user_info.preferred_username}")

            if user_info.claims:
                print(f"   - Additional claims: {list(user_info.claims.keys())}")

            # Validate and decode tokens
            print("\n6. Validating tokens...")

            # Decode ID token (if available)
            if token_response.id_token:
                id_claims = client.decode_token(token_response.id_token)
                print("   ✓ ID token decoded")
                print(f"   - Subject: {id_claims.get('sub')}")
                print(f"   - Issued at: {id_claims.get('iat')}")
                print(f"   - Expires at: {id_claims.get('exp')}")

            # Validate access token (basic validation without signature)
            access_claims = client.validate_token(
                token_response.access_token,
                verify_signature=False,  # Set to True if using HMAC with client_secret
            )
            print("   ✓ Access token validated")
            print(f"   - Scopes: {access_claims.get('scope', 'N/A')}")

            # Refresh token (if available)
            if token_response.refresh_token:
                print("\n7. Refreshing access token...")

                new_token = client.refresh_token(token_response.refresh_token)

                print("   ✓ Token refreshed")
                print(f"   - New access token: {new_token.access_token[:20]}...")
                print(f"   - Expires in: {new_token.expires_in} seconds")

            # Generate logout URL
            print("\n8. Generating logout URL...")

            logout_url = client.logout_url(
                id_token_hint=token_response.id_token,
                post_logout_redirect_uri="http://localhost:8080",
            )

            if logout_url:
                print("   ✓ Logout URL generated")
                print(f"   - URL: {logout_url}")
            else:
                print("   - Logout endpoint not available")

            print("\n" + "=" * 60)
            print("Example completed successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"   ✗ Error: {e}")
            raise


def example_client_credentials():
    """
    Example: Client Credentials Flow.

    Used for machine-to-machine authentication.
    """
    print("\n" + "=" * 60)
    print("Example: Client Credentials Flow")
    print("=" * 60)

    print(f"\n1. Initializing OIDC client for {KEYCLOAK_URL}...")

    with OIDCClient(
        issuer_url=KEYCLOAK_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    ) as client:
        print("   ✓ Discovery completed")

        # Perform client credentials grant
        print("\n2. Performing client credentials grant...")

        try:
            token_response = client.client_credentials_grant(scope="api:read api:write")

            print("   ✓ Access token received")
            print(f"   - Access token: {token_response.access_token[:20]}...")
            print(f"   - Token type: {token_response.token_type}")
            print(f"   - Expires in: {token_response.expires_in} seconds")

            # Validate token
            print("\n3. Validating access token...")

            claims = client.validate_token(
                token_response.access_token,
                verify_signature=False,
            )

            print("   ✓ Token validated")
            print(f"   - Subject: {claims.get('sub')}")
            print(f"   - Scopes: {claims.get('scope', 'N/A')}")

            print("\n" + "=" * 60)
            print("Example completed successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"   ✗ Error: {e}")
            raise


def example_token_validation():
    """
    Example: Token validation and decoding.
    """
    print("\n" + "=" * 60)
    print("Example: Token Validation")
    print("=" * 60)

    # Sample JWT token (replace with real token)
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    print("\n1. Initializing token validator...")

    with OIDCClient(
        issuer_url=KEYCLOAK_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        auto_discover=False,  # Skip discovery for this example
    ) as client:
        print("   ✓ Validator initialized")

        # Decode token without validation
        print("\n2. Decoding token (without validation)...")

        try:
            claims = client.decode_token(sample_token)

            print("   ✓ Token decoded")
            print(f"   - Claims: {claims}")

        except Exception as e:
            print(f"   ✗ Error: {e}")


if __name__ == "__main__":
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 10 + "OIDC Pure Library - Examples" + " " * 20 + "║")
    print("╚" + "═" * 58 + "╝")

    print("\nBefore running these examples, configure:")
    print("1. KEYCLOAK_URL: Your Keycloak realm URL")
    print("2. CLIENT_ID: Your OAuth2 client ID")
    print("3. CLIENT_SECRET: Your client secret (if using confidential client)")
    print("4. REDIRECT_URI: Callback URL (must be configured in Keycloak)")

    print("\n" + "-" * 60)

    try:
        # Run authorization code flow example
        example_authorization_code_flow()

        # Uncomment to run other examples:
        # example_client_credentials()
        # example_token_validation()

    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user.")
    except Exception as e:
        print(f"\n\nError running examples: {e}")
        import traceback

        traceback.print_exc()
