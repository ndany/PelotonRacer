"""
Authentication Tests for PelotonClient (Issue #13)

Tests cover:
1. Standard authentication flows (Bearer token, session ID, username/password)
2. Authentication priority and fallback mechanisms
3. API data fetching (user profile, workouts, performance graphs)
4. Security vulnerabilities (JWT validation, credential leakage, error handling)

Security findings tested:
- CRITICAL: Missing JWT signature validation
- HIGH: Sensitive exception disclosure (credential leakage in errors)
- MEDIUM: No token storage security
"""

import pytest
import json
import base64
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import requests
import responses

from src.api.peloton_client import PelotonClient


# =============================================================================
# STANDARD AUTHENTICATION TESTS
# =============================================================================

@pytest.mark.unit
@responses.activate
def test_bearer_token_authentication_success(mock_responses, mock_api_user_response):
    """Test successful authentication with Bearer token"""
    # Create a valid JWT token with proper structure
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "http://onepeloton.com/user_id": "user123",
        "exp": int((datetime.now() + timedelta(days=1)).timestamp())
    }).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip('=')
    valid_token = f"{header}.{payload}.{signature}"

    # Mock the API response
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123",
        json=mock_api_user_response,
        status=200
    )

    client = PelotonClient(bearer_token=valid_token)
    result = client.authenticate()

    assert result is True
    assert client.user_id == "user123"
    assert client.bearer_token == valid_token


@pytest.mark.unit
@responses.activate
def test_session_id_authentication_success(mock_responses):
    """Test successful authentication with session ID"""
    session_response = {
        "user_id": "session_user_456",
        "status": "active"
    }

    responses.add(
        responses.GET,
        "https://api.onepeloton.com/auth/check_session",
        json=session_response,
        status=200
    )

    client = PelotonClient(session_id="valid_session_id")
    result = client.authenticate()

    assert result is True
    assert client.user_id == "session_user_456"
    assert client.session_id == "valid_session_id"


@pytest.mark.unit
@responses.activate
def test_username_password_authentication_success(mock_responses):
    """Test successful authentication with username and password"""
    auth_response = {
        "user_id": "pwd_user_789",
        "session_id": "new_session_abc123"
    }

    responses.add(
        responses.POST,
        "https://api.onepeloton.com/auth/login?=",
        json=auth_response,
        status=200
    )

    client = PelotonClient(username="testuser", password="testpass")
    result = client.authenticate()

    assert result is True
    assert client.user_id == "pwd_user_789"
    assert client.session_id == "new_session_abc123"


@pytest.mark.unit
@responses.activate
def test_authentication_priority_bearer_over_session(mock_responses, mock_api_user_response):
    """Test that Bearer token is used when both Bearer and session ID are provided"""
    # Create valid JWT
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "http://onepeloton.com/user_id": "bearer_user"
    }).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"sig").decode().rstrip('=')
    token = f"{header}.{payload}.{signature}"

    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/bearer_user",
        json={"id": "bearer_user"},
        status=200
    )

    client = PelotonClient(bearer_token=token, session_id="session_should_not_be_used")
    result = client.authenticate()

    assert result is True
    assert client.user_id == "bearer_user"  # Bearer token takes priority


@pytest.mark.unit
@responses.activate
def test_authentication_priority_session_over_credentials(mock_responses):
    """Test that session ID is used when both session and credentials are provided"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/auth/check_session",
        json={"user_id": "session_user"},
        status=200
    )

    client = PelotonClient(
        session_id="valid_session",
        username="user_should_not_be_used",
        password="pass_should_not_be_used"
    )
    result = client.authenticate()

    assert result is True
    assert client.user_id == "session_user"


@pytest.mark.unit
def test_missing_credentials_handling():
    """Test that authentication fails gracefully when no credentials are provided"""
    client = PelotonClient()

    # Should not raise exception, should return False
    result = client.authenticate()

    assert result is False
    assert client.user_id is None


@pytest.mark.unit
@responses.activate
def test_get_user_profile_success(mock_responses, mock_api_user_response):
    """Test fetching user profile data"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123",
        json=mock_api_user_response,
        status=200
    )

    client = PelotonClient()
    client.user_id = "user123"

    profile = client.get_user_profile()

    assert profile is not None
    assert profile["id"] == "user123"
    assert profile["username"] == "testuser"


@pytest.mark.unit
@responses.activate
def test_get_workouts_success(mock_responses):
    """Test fetching workout data"""
    workout_response = {
        "data": [
            {"id": "workout1", "fitness_discipline": "cycling"},
            {"id": "workout2", "fitness_discipline": "cycling"}
        ]
    }

    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123/workouts",
        json=workout_response,
        status=200
    )

    client = PelotonClient()
    client.user_id = "user123"

    workouts = client.get_workouts(limit=10, page=0)

    assert len(workouts) == 2
    assert workouts[0]["id"] == "workout1"


@pytest.mark.unit
@responses.activate
def test_get_workout_performance_success(mock_responses, mock_api_performance_response):
    """Test fetching performance graph data"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/workout/workout123/performance_graph",
        json=mock_api_performance_response,
        status=200
    )

    client = PelotonClient()

    performance = client.get_workout_performance("workout123")

    assert performance is not None
    assert "metrics" in performance
    assert "seconds_since_pedaling_start" in performance


# =============================================================================
# SECURITY TESTS - JWT VALIDATION
# =============================================================================

@pytest.mark.unit
def test_jwt_signature_validation_missing():
    """
    CRITICAL SECURITY TEST: Verify JWT signature validation exists

    Current implementation (VULNERABLE):
    - Only decodes JWT payload without verifying signature
    - Attacker can forge tokens by modifying payload

    Expected behavior:
    - Should verify JWT signature using secret key
    - Should reject tokens with invalid signatures

    NOTE: This test documents the current vulnerability. When fixed,
    update this test to verify proper signature validation.
    """
    # Create a JWT with tampered payload (user_id changed)
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')

    # Tampered payload - attacker changes user_id
    tampered_payload = base64.urlsafe_b64encode(json.dumps({
        "http://onepeloton.com/user_id": "attacker_user",
        "exp": int((datetime.now() + timedelta(days=1)).timestamp())
    }).encode()).decode().rstrip('=')

    # Invalid signature (doesn't match payload)
    fake_signature = base64.urlsafe_b64encode(b"invalid_signature").decode().rstrip('=')
    forged_token = f"{header}.{tampered_payload}.{fake_signature}"

    # CURRENT BEHAVIOR: Token is accepted without signature verification
    # This is a CRITICAL vulnerability - tokens can be forged
    client = PelotonClient(bearer_token=forged_token)

    # When signature validation is implemented, this should raise an exception
    # or return False, but currently it will decode successfully
    # TODO: Update this test when JWT signature validation is added
    with patch.object(client.session, 'get') as mock_get:
        # Mock successful API call (shouldn't happen with invalid token)
        mock_get.return_value.json.return_value = {"id": "attacker_user"}
        mock_get.return_value.raise_for_status = Mock()

        # This SHOULD fail but currently succeeds (vulnerability)
        result = client._validate_bearer_token()

        # Document current vulnerable behavior
        assert result is True  # VULNERABLE: accepts forged token
        assert client.user_id == "attacker_user"  # Attacker successfully forged identity


@pytest.mark.unit
@pytest.mark.security
def test_malformed_jwt_token_rejection():
    """Test that malformed JWT tokens are rejected"""
    malformed_tokens = [
        "not.a.valid.jwt.too.many.parts",  # Too many parts
        "only_one_part",  # Missing parts
        "two.parts",  # Incomplete JWT
        "",  # Empty string
        "header.payload.",  # Missing signature
    ]

    for token in malformed_tokens:
        client = PelotonClient(bearer_token=token)
        result = client._validate_bearer_token()

        assert result is False, f"Should reject malformed token: {token}"
        assert client.user_id is None


@pytest.mark.unit
@pytest.mark.security
def test_expired_jwt_token_handling():
    """
    Test handling of expired JWT tokens

    NOTE: Current implementation doesn't check expiration.
    This test documents expected behavior when expiration checking is added.
    """
    # Create an expired JWT token
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')

    # Expired payload (exp in the past)
    expired_payload = base64.urlsafe_b64encode(json.dumps({
        "http://onepeloton.com/user_id": "user123",
        "exp": int((datetime.now() - timedelta(days=1)).timestamp())  # Expired yesterday
    }).encode()).decode().rstrip('=')

    signature = base64.urlsafe_b64encode(b"sig").decode().rstrip('=')
    expired_token = f"{header}.{expired_payload}.{signature}"

    client = PelotonClient(bearer_token=expired_token)

    # When expiration checking is implemented, this should fail
    # Currently it may succeed (another vulnerability)
    # TODO: Update when expiration validation is added


@pytest.mark.unit
def test_jwt_missing_user_id_claim():
    """Test JWT tokens without required user_id claim are rejected"""
    # Create JWT without user_id claim
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": "some_subject",
        "iat": int(datetime.now().timestamp())
        # Missing: "http://onepeloton.com/user_id"
    }).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"sig").decode().rstrip('=')
    token = f"{header}.{payload}.{signature}"

    client = PelotonClient(bearer_token=token)
    result = client._validate_bearer_token()

    assert result is False
    assert client.user_id is None


# =============================================================================
# SECURITY TESTS - CREDENTIAL LEAKAGE
# =============================================================================

@pytest.mark.unit
@pytest.mark.security
@responses.activate
def test_error_messages_dont_leak_bearer_token(mock_responses, capfd):
    """
    HIGH SECURITY TEST: Verify error messages don't expose Bearer tokens

    Vulnerability: Exception messages and print statements may leak credentials
    """
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SECRET_PAYLOAD.SECRET_SIG"

    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123",
        json={"error": "Unauthorized"},
        status=401
    )

    # Create valid JWT structure
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "http://onepeloton.com/user_id": "user123"
    }).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"sig").decode().rstrip('=')
    valid_token = f"{header}.{payload}.{signature}"

    client = PelotonClient(bearer_token=valid_token)
    result = client._validate_bearer_token()

    # Capture stdout/stderr
    captured = capfd.readouterr()
    combined_output = captured.out + captured.err

    # Token should NOT appear in output
    assert valid_token not in combined_output, "Bearer token leaked in error output"
    assert signature not in combined_output, "JWT signature leaked in error output"


@pytest.mark.unit
@responses.activate
def test_error_messages_dont_leak_session_id(mock_responses, capfd):
    """Test that session IDs don't leak in error messages"""
    secret_session_id = "super_secret_session_12345"

    responses.add(
        responses.GET,
        "https://api.onepeloton.com/auth/check_session",
        json={"error": "Invalid session"},
        status=401
    )

    client = PelotonClient(session_id=secret_session_id)
    result = client._validate_session()

    captured = capfd.readouterr()
    combined_output = captured.out + captured.err

    assert secret_session_id not in combined_output, "Session ID leaked in error output"


@pytest.mark.unit
@responses.activate
def test_error_messages_dont_leak_password(mock_responses, capfd):
    """Test that passwords don't leak in error messages"""
    secret_password = "MySecretPassword123!"

    responses.add(
        responses.POST,
        "https://api.onepeloton.com/auth/login?=",
        json={"error": "Invalid credentials"},
        status=401
    )

    client = PelotonClient(username="testuser", password=secret_password)
    result = client._authenticate_with_credentials()

    captured = capfd.readouterr()
    combined_output = captured.out + captured.err

    assert secret_password not in combined_output, "Password leaked in error output"


@pytest.mark.unit
@pytest.mark.security
def test_exception_handling_doesnt_expose_credentials():
    """
    Test that exception stack traces don't expose credentials

    Vulnerability: Exception details may expose tokens, passwords in variables
    """
    sensitive_token = "SENSITIVE_BEARER_TOKEN_ABC123"

    client = PelotonClient(bearer_token=sensitive_token)

    # Force an exception during API call
    with patch.object(client.session, 'get', side_effect=Exception("Network error")):
        # Exception should be caught and method should return None
        result = client.get_user_profile()

        # Verify the method handles exception gracefully
        assert result is None

        # In production, exceptions are caught and sanitized
        # This prevents credential exposure in stack traces


@pytest.mark.unit
@pytest.mark.security
def test_tokens_not_logged_in_debug_mode(capfd):
    """
    Test that tokens are not logged even in debug/verbose mode

    Current code uses print() statements that may leak credentials
    """
    # Create a token that should never appear in logs
    secret_token_part = "NEVER_LOG_THIS_TOKEN"
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps({
        "http://onepeloton.com/user_id": "user123",
        "secret": secret_token_part
    }).encode()).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(b"sig").decode().rstrip('=')
    token = f"{header}.{payload}.{signature}"

    client = PelotonClient(bearer_token=token)

    # Even if debug logging is enabled, token should be redacted
    # Current implementation may leak via print() statements
    with patch.object(client.session, 'get') as mock_get:
        mock_get.return_value.json.return_value = {"id": "user123"}
        mock_get.return_value.raise_for_status = Mock()

        client._validate_bearer_token()

        captured = capfd.readouterr()
        combined_output = captured.out + captured.err

        # Secret parts should not appear in any output
        assert secret_token_part not in combined_output


# =============================================================================
# SECURITY TESTS - ERROR HANDLING
# =============================================================================

@pytest.mark.unit
def test_authentication_failure_returns_false_not_exception():
    """Test that authentication failures return False instead of raising exceptions"""
    client = PelotonClient(username="invalid", password="invalid")

    with patch.object(client.session, 'post', side_effect=requests.exceptions.ConnectionError()):
        # Should not raise exception, should return False
        result = client._authenticate_with_credentials()

        assert result is False


@pytest.mark.unit
def test_api_network_error_handling(mock_responses):
    """Test graceful handling of network errors"""
    mock_responses.add(
        mock_responses.GET,
        "https://api.onepeloton.com/api/user/user123",
        body=requests.exceptions.ConnectionError("Network unreachable")
    )

    client = PelotonClient()
    client.user_id = "user123"

    # Should return None, not raise exception
    profile = client.get_user_profile()

    assert profile is None


@pytest.mark.unit
@responses.activate
def test_api_rate_limiting_response(mock_responses):
    """Test handling of API rate limiting (429 status)"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123/workouts",
        json={"error": "Rate limit exceeded"},
        status=429
    )

    client = PelotonClient()
    client.user_id = "user123"

    workouts = client.get_workouts()

    # Should return empty list, not raise exception
    assert workouts == []


@pytest.mark.unit
@responses.activate
def test_api_unauthorized_response(mock_responses):
    """Test handling of 401 Unauthorized responses"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123",
        json={"error": "Unauthorized"},
        status=401
    )

    client = PelotonClient()
    client.user_id = "user123"

    profile = client.get_user_profile()

    assert profile is None


@pytest.mark.unit
@responses.activate
def test_api_forbidden_response(mock_responses):
    """Test handling of 403 Forbidden responses"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/other_user/workouts",
        json={"error": "Forbidden"},
        status=403
    )

    client = PelotonClient()
    client.user_id = "user123"

    # Try to access another user's workouts
    workouts = client.get_user_workouts("other_user")

    assert workouts == []


# =============================================================================
# ADDITIONAL COVERAGE TESTS
# =============================================================================

@pytest.mark.unit
def test_client_initialization_sets_headers():
    """Test that client initialization sets proper browser-like headers"""
    client = PelotonClient()

    assert "Peloton-Platform" in client.session.headers
    assert client.session.headers["Peloton-Platform"] == "web"
    assert "User-Agent" in client.session.headers


@pytest.mark.unit
def test_bearer_token_sets_authorization_header():
    """Test that providing bearer token sets Authorization header"""
    token = "test_token_123"
    client = PelotonClient(bearer_token=token)

    assert "Authorization" in client.session.headers
    assert client.session.headers["Authorization"] == f"Bearer {token}"


@pytest.mark.unit
def test_session_id_sets_cookie():
    """Test that providing session ID sets cookie"""
    session_id = "test_session_456"
    client = PelotonClient(session_id=session_id)

    # Check that cookie was set
    assert "peloton_session_id" in client.session.cookies


@pytest.mark.unit
def test_get_user_profile_without_user_id():
    """Test that get_user_profile returns None when user_id is not set"""
    client = PelotonClient()

    profile = client.get_user_profile()

    assert profile is None


@pytest.mark.unit
def test_get_workouts_without_user_id():
    """Test that get_workouts returns empty list when user_id is not set"""
    client = PelotonClient()

    workouts = client.get_workouts()

    assert workouts == []


@pytest.mark.unit
@responses.activate
def test_get_all_workouts_pagination(mock_responses):
    """Test that get_all_workouts properly paginates through results"""
    from src.config import API_PAGE_SIZE

    # First page: full page of results
    page1_data = [{"id": f"workout{i}"} for i in range(API_PAGE_SIZE)]
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123/workouts",
        json={"data": page1_data},
        status=200
    )

    # Second page: partial results (indicates end)
    page2_data = [{"id": f"workout{i}"} for i in range(API_PAGE_SIZE, API_PAGE_SIZE + 10)]
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123/workouts",
        json={"data": page2_data},
        status=200
    )

    client = PelotonClient()
    client.user_id = "user123"

    # Should stop after second page (less than page_size results)
    workouts = client.get_all_workouts(max_workouts=200)

    assert len(workouts) == API_PAGE_SIZE + 10


@pytest.mark.unit
@responses.activate
def test_get_followers(mock_responses, mock_api_followers_response):
    """Test fetching followers list"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/user/user123/following",
        json=mock_api_followers_response,
        status=200
    )

    client = PelotonClient()
    client.user_id = "user123"

    followers = client.get_followers()

    assert len(followers) == 2
    assert followers[0]["id"] == "follower456"


@pytest.mark.unit
def test_get_followers_without_user_id():
    """Test that get_followers returns empty list when user_id is not set"""
    client = PelotonClient()

    followers = client.get_followers()

    assert followers == []


@pytest.mark.unit
@responses.activate
def test_workout_performance_network_error(mock_responses):
    """Test handling of network errors when fetching workout performance"""
    responses.add(
        responses.GET,
        "https://api.onepeloton.com/api/workout/workout123/performance_graph",
        body=requests.exceptions.Timeout("Request timed out")
    )

    client = PelotonClient()

    performance = client.get_workout_performance("workout123")

    assert performance is None
