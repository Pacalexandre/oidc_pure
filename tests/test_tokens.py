"""Tests for JWT token validation."""

import base64
import hashlib
import hmac
import json
import time

import pytest

from oidc_pure.exceptions import ValidationError
from oidc_pure.tokens import (
    TokenValidator,
    create_pkce_challenge,
    generate_code_verifier,
)


class TestTokenValidator:
    """Tests for TokenValidator class."""

    @pytest.fixture
    def validator(self, mock_issuer_url: str, mock_client_id: str, mock_client_secret: str):
        """Create a token validator instance."""
        return TokenValidator(
            issuer=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
        )

    def test_decode_valid_token(self, validator: TokenValidator):
        """Test decoding a valid JWT token."""
        # Create a simple JWT token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        decoded = validator.decode_token(token)

        assert decoded["header"]["alg"] == "HS256"
        assert decoded["payload"]["sub"] == "1234567890"
        assert decoded["signature"] == signature

    def test_decode_invalid_format(self, validator: TokenValidator):
        """Test decoding token with invalid format."""
        with pytest.raises(ValidationError, match="must have 3 parts"):
            validator.decode_token("invalid.token")

    def test_decode_invalid_base64(self, validator: TokenValidator):
        """Test decoding token with invalid base64."""
        with pytest.raises(ValidationError, match="Failed to decode token"):
            validator.decode_token("invalid!!!.invalid!!!.signature")

    def test_validate_token_with_hmac(
        self,
        validator: TokenValidator,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test validating token with HMAC signature."""
        current_time = int(time.time())

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        # Create valid HMAC signature
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(mock_client_secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        validated_payload = validator.validate_token(token, verify_signature=True)

        assert validated_payload["sub"] == "1234567890"
        assert validated_payload["iss"] == mock_issuer_url

    def test_validate_token_expired(
        self, validator: TokenValidator, mock_issuer_url: str, mock_client_id: str
    ):
        """Test validating expired token."""
        expired_time = int(time.time()) - 3600

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": expired_time,
            "iat": expired_time - 3600,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Token has expired"):
            validator.validate_token(token, verify_signature=False)

    def test_validate_token_not_yet_valid(
        self, validator: TokenValidator, mock_issuer_url: str, mock_client_id: str
    ):
        """Test validating token that is not yet valid."""
        future_time = int(time.time()) + 3600

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "nbf": future_time,
            "exp": future_time + 3600,
            "iat": int(time.time()),
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Token not yet valid"):
            validator.validate_token(token, verify_signature=False)

    def test_validate_token_invalid_issuer(self, validator: TokenValidator, mock_client_id: str):
        """Test validating token with invalid issuer."""
        current_time = int(time.time())

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": "https://wrong-issuer.com",
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Invalid issuer"):
            validator.validate_token(token, verify_signature=False)

    def test_validate_token_invalid_audience(self, validator: TokenValidator, mock_issuer_url: str):
        """Test validating token with invalid audience."""
        current_time = int(time.time())

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": "wrong-client-id",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Invalid audience"):
            validator.validate_token(token, verify_signature=False)

    def test_validate_token_without_signature_verification(
        self, validator: TokenValidator, mock_issuer_url: str, mock_client_id: str
    ):
        """Test validating token without signature verification."""
        current_time = int(time.time())

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "invalid_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        # Should succeed without signature verification
        validated_payload = validator.validate_token(token, verify_signature=False)
        assert validated_payload["sub"] == "1234567890"


class TestPKCEFunctions:
    """Tests for PKCE helper functions."""

    def test_generate_code_verifier(self):
        """Test code verifier generation."""
        verifier = generate_code_verifier()

        assert isinstance(verifier, str)
        assert len(verifier) >= 43
        assert len(verifier) <= 128

    def test_create_pkce_challenge(self):
        """Test PKCE challenge creation."""
        verifier = "test_verifier_1234567890_test_verifier_1234567890"
        challenge, method = create_pkce_challenge(verifier)

        assert isinstance(challenge, str)
        assert isinstance(method, str)
        assert len(challenge) > 0
        assert method == "S256"

        # Verify it's base64url encoded
        assert all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for c in challenge
        )

    def test_pkce_challenge_deterministic(self):
        """Test that PKCE challenge is deterministic."""
        verifier = "test_verifier_1234567890_test_verifier_1234567890"
        challenge1, method1 = create_pkce_challenge(verifier)
        challenge2, method2 = create_pkce_challenge(verifier)

        assert challenge1 == challenge2
        assert method1 == method2
