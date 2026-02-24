"""
Integration example with Flask web application.
"""

from flask import Flask, jsonify, redirect, request, session, url_for

from oidc_pure import OIDCClient, OIDCError

app = Flask(__name__)
app.secret_key = "your-secret-key-change-in-production"

# OIDC Configuration
ISSUER_URL = "https://keycloak.example.com/realms/myrealm"
CLIENT_ID = "flask-app"
CLIENT_SECRET = "your-client-secret"
REDIRECT_URI = "http://localhost:5000/callback"

# Initialize OIDC client
oidc_client = OIDCClient(
    issuer_url=ISSUER_URL,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=REDIRECT_URI,
)


@app.route("/")
def index():
    """Home page."""
    if "access_token" in session:
        return redirect(url_for("profile"))
    return """
    <h1>OIDC Flask Example</h1>
    <p>Welcome! Please <a href="/login">login</a> to continue.</p>
    """


@app.route("/login")
def login():
    """Initiate OIDC login flow."""
    try:
        # Generate authorization URL with PKCE
        auth_url, state, code_verifier = oidc_client.get_authorization_url(
            scope="openid profile email",
            use_pkce=True,
        )

        # Store state and verifier in session
        session["oauth_state"] = state
        session["oauth_verifier"] = code_verifier

        # Redirect to authorization server
        return redirect(auth_url)

    except OIDCError as e:
        return f"Login failed: {e.message}", 500


@app.route("/callback")
def callback():
    """Handle OAuth2 callback."""
    try:
        # Get state and verifier from session
        expected_state = session.pop("oauth_state", None)
        code_verifier = session.pop("oauth_verifier", None)

        if not expected_state:
            return "Missing state in session", 400

        # Exchange authorization code for tokens
        token = oidc_client.handle_authorization_response(
            response_url=request.url,
            expected_state=expected_state,
            code_verifier=code_verifier,
        )

        # Store tokens in session
        session["access_token"] = token.access_token
        session["refresh_token"] = token.refresh_token
        session["id_token"] = token.id_token

        # Redirect to profile page
        return redirect(url_for("profile"))

    except OIDCError as e:
        return f"Callback failed: {e.message}", 400


@app.route("/profile")
def profile():
    """User profile page."""
    access_token = session.get("access_token")

    if not access_token:
        return redirect(url_for("login"))

    try:
        # Get user information
        user_info = oidc_client.get_user_info(access_token)

        # Render profile
        return f"""
        <h1>User Profile</h1>
        <ul>
            <li><strong>Name:</strong> {user_info.name}</li>
            <li><strong>Email:</strong> {user_info.email}</li>
            <li><strong>Username:</strong> {user_info.preferred_username}</li>
            <li><strong>Subject:</strong> {user_info.sub}</li>
        </ul>
        <p>
            <a href="/api/me">View JSON</a> |
            <a href="/refresh">Refresh Token</a> |
            <a href="/logout">Logout</a>
        </p>
        """

    except OIDCError:
        # Token might be expired, try to refresh
        return redirect(url_for("refresh"))


@app.route("/api/me")
def api_me():
    """API endpoint for user information."""
    access_token = session.get("access_token")

    if not access_token:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        user_info = oidc_client.get_user_info(access_token)

        return jsonify(
            {
                "sub": user_info.sub,
                "name": user_info.name,
                "email": user_info.email,
                "username": user_info.preferred_username,
                "claims": user_info.claims,
            }
        )

    except OIDCError as e:
        return jsonify({"error": e.message}), 500


@app.route("/refresh")
def refresh():
    """Refresh access token."""
    refresh_token = session.get("refresh_token")

    if not refresh_token:
        return redirect(url_for("login"))

    try:
        # Refresh token
        new_token = oidc_client.refresh_token(refresh_token)

        # Update session
        session["access_token"] = new_token.access_token
        if new_token.refresh_token:
            session["refresh_token"] = new_token.refresh_token

        return redirect(url_for("profile"))

    except OIDCError:
        # Refresh failed, need to login again
        session.clear()
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    """Logout and clear session."""
    id_token = session.get("id_token")

    # Clear session
    session.clear()

    # Generate logout URL
    logout_url = oidc_client.logout_url(
        id_token_hint=id_token,
        post_logout_redirect_uri=url_for("index", _external=True),
    )

    if logout_url:
        return redirect(logout_url)
    else:
        return redirect(url_for("index"))


if __name__ == "__main__":
    print("Starting Flask application...")
    print("Visit: http://localhost:5000")
    app.run(debug=True, port=5000)
