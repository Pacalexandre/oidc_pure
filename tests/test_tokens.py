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

    def test_pkce_challenge_invalid_verifier_too_short(self):
        """Test PKCE challenge with verifier too short."""
        verifier = "short"  # Less than 43 characters

        with pytest.raises(ValueError, match="Code verifier must be 43-128 characters"):
            create_pkce_challenge(verifier)

    def test_pkce_challenge_invalid_verifier_too_long(self):
        """Test PKCE challenge with verifier too long."""
        verifier = "x" * 129  # More than 128 characters

        with pytest.raises(ValueError, match="Code verifier must be 43-128 characters"):
            create_pkce_challenge(verifier)

    def test_generate_verifier_invalid_length_too_short(self):
        """Test generate_code_verifier with length too short."""
        with pytest.raises(ValueError, match="Length must be between 43 and 128"):
            generate_code_verifier(length=42)

    def test_generate_verifier_invalid_length_too_long(self):
        """Test generate_code_verifier with length too long."""
        with pytest.raises(ValueError, match="Length must be between 43 and 128"):
            generate_code_verifier(length=129)

    def test_generate_verifier_custom_length(self):
        """Test generate_code_verifier with custom valid length."""
        verifier = generate_code_verifier(length=50)
        assert len(verifier) == 50

        verifier_min = generate_code_verifier(length=43)
        assert len(verifier_min) == 43

        verifier_max = generate_code_verifier(length=128)
        assert len(verifier_max) == 128


class TestTokenValidatorEdgeCases:
    """Tests for TokenValidator edge cases and error conditions."""

    @pytest.fixture
    def validator(self, mock_issuer_url: str, mock_client_id: str, mock_client_secret: str):
        """Create a token validator instance."""
        return TokenValidator(
            issuer=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
        )

    @pytest.fixture
    def validator_no_secret(self, mock_issuer_url: str, mock_client_id: str):
        """Create a token validator without client secret."""
        return TokenValidator(
            issuer=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=None,
        )

    def test_token_without_alg_field(self, validator: TokenValidator):
        """Test validating token with missing 'alg' field in header."""
        current_time = int(time.time())

        header = {"typ": "JWT"}  # Missing 'alg' field
        payload = {
            "sub": "1234567890",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Token header missing 'alg' field"):
            validator.validate_token(token, verify_signature=True)

    def test_hmac_without_client_secret(
        self, validator_no_secret: TokenValidator, mock_issuer_url: str, mock_client_id: str
    ):
        """Test HMAC validation without client secret."""
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
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(
            ValidationError, match="Client secret required for HMAC signature verification"
        ):
            validator_no_secret.validate_token(token, verify_signature=True)

    def test_algorithm_none_rejected(self, validator: TokenValidator):
        """Test that algorithm 'none' is rejected."""
        current_time = int(time.time())

        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = ""

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Algorithm 'none' not allowed"):
            validator.validate_token(token, verify_signature=True)

    def test_unsupported_algorithm_rs256(self, validator: TokenValidator):
        """Test that RS256 algorithm is not supported."""
        current_time = int(time.time())

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Algorithm RS256 not supported"):
            validator.validate_token(token, verify_signature=True)

    def test_unsupported_algorithm_es256(self, validator: TokenValidator):
        """Test that ES256 algorithm is not supported."""
        current_time = int(time.time())

        header = {"alg": "ES256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Algorithm ES256 not supported"):
            validator.validate_token(token, verify_signature=True)

    def test_token_issued_in_future(
        self, validator: TokenValidator, mock_issuer_url: str, mock_client_id: str
    ):
        """Test validating token with iat (issued at) in the future."""
        current_time = int(time.time())
        future_time = current_time + 3600

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": future_time + 3600,
            "iat": future_time,  # Issued in the future
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        with pytest.raises(ValidationError, match="Token issued in the future"):
            validator.validate_token(token, verify_signature=False)

    def test_unsupported_hmac_algorithm(
        self,
        validator: TokenValidator,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test HMAC validation with unsupported algorithm."""
        current_time = int(time.time())

        header = {"alg": "HS999", "typ": "JWT"}  # Invalid HMAC algorithm
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(mock_client_secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        with pytest.raises(ValidationError, match="Unsupported HMAC algorithm: HS999"):
            validator.validate_token(token, verify_signature=True)

    def test_invalid_hmac_signature(
        self,
        validator: TokenValidator,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test HMAC validation with invalid signature."""
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

        # Create an INVALID signature (using wrong secret)
        wrong_signature = hmac.new(
            b"wrong_secret", f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
        ).digest()
        wrong_signature_b64 = base64.urlsafe_b64encode(wrong_signature).decode().rstrip("=")

        token = f"{header_b64}.{payload_b64}.{wrong_signature_b64}"

        with pytest.raises(ValidationError, match="Invalid token signature"):
            validator.validate_token(token, verify_signature=True)

    def test_extract_claims_method(self, validator: TokenValidator):
        """Test extract_claims method."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "John Doe", "admin": True}

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        claims = validator.extract_claims(token)

        assert claims["sub"] == "1234567890"
        assert claims["name"] == "John Doe"
        assert claims["admin"] is True

    def test_audience_as_list(
        self, validator: TokenValidator, mock_issuer_url: str, mock_client_id: str
    ):
        """Test validating token with audience as list."""
        current_time = int(time.time())

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": [mock_client_id, "another-client-id"],  # Audience as list
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        token = f"{header_b64}.{payload_b64}.{signature}"

        # Should succeed - client_id is in the audience list
        validated = validator.validate_token(token, verify_signature=False)
        assert validated["sub"] == "1234567890"

    def test_hmac_hs384_algorithm(
        self,
        validator: TokenValidator,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test HMAC validation with HS384 algorithm."""
        current_time = int(time.time())

        header = {"alg": "HS384", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(mock_client_secret.encode(), message.encode(), hashlib.sha384).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        validated_payload = validator.validate_token(token, verify_signature=True)
        assert validated_payload["sub"] == "1234567890"

    def test_hmac_hs512_algorithm(
        self,
        validator: TokenValidator,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test HMAC validation with HS512 algorithm."""
        current_time = int(time.time())

        header = {"alg": "HS512", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(mock_client_secret.encode(), message.encode(), hashlib.sha512).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        validated_payload = validator.validate_token(token, verify_signature=True)
        assert validated_payload["sub"] == "1234567890"

    def test_verify_hmac_signature_without_secret(
        self,
        validator: TokenValidator,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test _verify_hmac_signature internal check for client_secret."""
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
        message = f"{header_b64}.{payload_b64}"

        signature = hmac.new(mock_client_secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        # Temporarily remove client_secret to trigger line 147
        # This tests the defensive check inside _verify_hmac_signature
        original_secret = validator.client_secret
        validator.client_secret = None

        with pytest.raises(ValidationError, match="Client secret required for HMAC validation"):
            validator._verify_hmac_signature(token, "HS256")

        # Restore original secret
        validator.client_secret = original_secret
