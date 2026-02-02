"""
Peloton OAuth Authentication Module
Implements Auth0 PKCE flow for headless authentication with Peloton API.

This module replicates the browser login flow programmatically:
1. Generate PKCE parameters (code_verifier, code_challenge)
2. Initiate authorization flow
3. Submit credentials to Auth0
4. Exchange authorization code for tokens
5. Support token refresh

Based on the implementation from:
https://github.com/philosowaffle/peloton-to-garmin
"""

import base64
import hashlib
import secrets
import time
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from urllib.parse import urlencode, urlparse, parse_qs

import requests


@dataclass
class OAuthConfig:
    """OAuth configuration for Peloton Auth0"""
    client_id: str = "WVoJxVDdPoFx4RNewvvg6ch2mZ7bwnsM"
    auth_domain: str = "auth.onepeloton.com"
    audience: str = "https://api.onepeloton.com/"
    scope: str = "offline_access openid peloton-api.members:default"
    redirect_uri: str = "https://members.onepeloton.com/callback"
    authorize_path: str = "/authorize"
    token_path: str = "/oauth/token"
    auth0_client_payload: str = "eyJuYW1lIjoiYXV0aDAuanMtdWxwIiwidmVyc2lvbiI6IjkuMTQuMyJ9"
    
    # PKCE parameters (generated per auth flow)
    code_verifier: str = ""
    code_challenge: str = ""
    state: str = ""
    nonce: str = ""


@dataclass
class TokenResponse:
    """Token response from OAuth flow"""
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int = 172800  # Default 48 hours
    scope: str = ""
    expires_at: float = 0  # Unix timestamp when token expires
    
    def __post_init__(self):
        if self.expires_at == 0:
            self.expires_at = time.time() + self.expires_in
    
    def is_expired(self) -> bool:
        """Check if token is expired (with 5 min buffer)"""
        return time.time() >= (self.expires_at - 300)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "id_token": self.id_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
            "expires_at": self.expires_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "TokenResponse":
        """Create from dictionary"""
        return cls(
            access_token=data.get("access_token", ""),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 172800),
            scope=data.get("scope", ""),
            expires_at=data.get("expires_at", 0),
        )


class PelotonAuthError(Exception):
    """Exception raised for authentication errors"""
    pass


class PelotonAuth:
    """
    Handles Peloton authentication via Auth0 PKCE flow.
    
    This is a headless implementation that authenticates using only HTTP requests,
    replicating what the browser does when you log into members.onepeloton.com.
    
    Usage:
        auth = PelotonAuth()
        token = auth.login("email@example.com", "password")
        # Use token.access_token for API calls
        
        # Later, refresh the token:
        new_token = auth.refresh(token)
    """
    
    def __init__(self, config: Optional[OAuthConfig] = None):
        self.config = config or OAuthConfig()
        self.session = requests.Session()
        self._setup_session()
    
    def _setup_session(self):
        """Configure session with browser-like headers"""
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        })
    
    @staticmethod
    def _generate_random_string(length: int = 64) -> str:
        """Generate a cryptographically secure random string"""
        return secrets.token_urlsafe(length)[:length]
    
    @staticmethod
    def _generate_code_challenge(verifier: str) -> str:
        """Generate S256 code challenge from verifier"""
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    def _generate_pkce_params(self):
        """Generate PKCE parameters for authorization flow"""
        self.config.code_verifier = self._generate_random_string(64)
        self.config.code_challenge = self._generate_code_challenge(self.config.code_verifier)
        self.config.state = self._generate_random_string(32)
        self.config.nonce = self._generate_random_string(32)
    
    def _build_authorize_url(self) -> str:
        """Build the authorization URL with PKCE parameters"""
        params = {
            "client_id": self.config.client_id,
            "audience": self.config.audience,
            "scope": self.config.scope,
            "response_type": "code",
            "response_mode": "query",
            "redirect_uri": self.config.redirect_uri,
            "state": self.config.state,
            "nonce": self.config.nonce,
            "code_challenge": self.config.code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": self.config.auth0_client_payload,
        }
        return f"https://{self.config.auth_domain}{self.config.authorize_path}?{urlencode(params)}"
    
    def _initiate_auth_flow(self) -> Tuple[str, str]:
        """
        Initiate the authorization flow by requesting the authorize endpoint.
        
        Returns:
            Tuple of (login_url, csrf_token)
        """
        authorize_url = self._build_authorize_url()
        
        # Follow redirects to get to the login page
        response = self.session.get(authorize_url, allow_redirects=True)
        
        if response.status_code != 200:
            raise PelotonAuthError(f"Failed to initiate auth flow: HTTP {response.status_code}")
        
        # Extract CSRF token from cookies
        csrf_token = None
        for cookie in self.session.cookies:
            if cookie.name == "_csrf" and cookie.path == "/usernamepassword/login":
                csrf_token = cookie.value
                break
        
        if not csrf_token:
            # Try to find it in response cookies
            csrf_token = self.session.cookies.get("_csrf")
        
        if not csrf_token:
            raise PelotonAuthError("Failed to obtain CSRF token from auth flow")
        
        # Extract state from final URL if it changed
        final_url = response.url
        parsed = urlparse(final_url)
        query_params = parse_qs(parsed.query)
        if "state" in query_params:
            self.config.state = query_params["state"][0]
        
        return final_url, csrf_token
    
    def _submit_credentials(self, login_url: str, csrf_token: str, email: str, password: str) -> str:
        """
        Submit credentials to Auth0 login endpoint.
        
        Returns:
            The URL to follow for authorization code (callback with code)
        """
        login_endpoint = f"https://{self.config.auth_domain}/usernamepassword/login"
        
        payload = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "tenant": "peloton-prod",
            "response_type": "code",
            "scope": self.config.scope,
            "audience": self.config.audience,
            "_csrf": csrf_token,
            "state": self.config.state,
            "_intstate": "deprecated",
            "nonce": self.config.nonce,
            "username": email,
            "password": password,
            "connection": "pelo-user-password",
            "code_challenge": self.config.code_challenge,
            "code_challenge_method": "S256",
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Origin": f"https://{self.config.auth_domain}",
            "Referer": login_url,
            "Auth0-Client": self.config.auth0_client_payload,
        }
        
        response = self.session.post(
            login_endpoint,
            json=payload,
            headers=headers,
            allow_redirects=False,
        )
        
        # Check for redirect (successful credential submission)
        if response.status_code in (301, 302, 303):
            location = response.headers.get("Location")
            if location:
                return self._ensure_absolute_url(location)
        
        # If no redirect, the response should contain a hidden form to submit
        if response.status_code == 200:
            return self._parse_and_submit_hidden_form(response.text)
        
        # Check for error in response
        try:
            error_data = response.json()
            error_msg = error_data.get("description") or error_data.get("error_description") or error_data.get("error")
            if error_msg:
                raise PelotonAuthError(f"Login failed: {error_msg}")
        except (ValueError, KeyError):
            pass
        
        raise PelotonAuthError(f"Credential submission failed: HTTP {response.status_code}")
    
    def _parse_and_submit_hidden_form(self, html: str) -> str:
        """
        Parse hidden form from Auth0 response and submit it.
        Auth0 returns an HTML page with a form that auto-submits to complete the flow.
        
        Returns:
            The callback URL with authorization code
        """
        import html as html_module
        
        # Extract form action
        action_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if not action_match:
            raise PelotonAuthError("Could not find form action in auth response")
        
        action = action_match.group(1)
        action = html_module.unescape(action)  # Decode HTML entities like &#x2F;
        
        # Extract hidden fields
        fields = {}
        # Pattern: name="..." value="..."
        input_pattern = re.compile(
            r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        # Also try alternate attribute order
        input_pattern_alt = re.compile(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\'][^>]+type=["\']hidden["\']',
            re.IGNORECASE
        )
        # Pattern for name before value without type first
        input_pattern_nv = re.compile(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        
        for match in input_pattern.finditer(html):
            fields[match.group(1)] = html_module.unescape(match.group(2))
        for match in input_pattern_alt.finditer(html):
            fields[match.group(1)] = html_module.unescape(match.group(2))
        for match in input_pattern_nv.finditer(html):
            name = match.group(1)
            if name not in fields:
                fields[name] = html_module.unescape(match.group(2))
        
        # Also handle value before name
        input_pattern_val_first = re.compile(
            r'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\']',
            re.IGNORECASE
        )
        for match in input_pattern_val_first.finditer(html):
            name = match.group(2)
            value = match.group(1)
            if name not in fields:
                fields[name] = html_module.unescape(value)
        
        if not fields:
            raise PelotonAuthError("No hidden form fields found in auth response")
        
        # Submit the form
        form_url = self._ensure_absolute_url(action)
        
        # Use proper headers for form submission
        form_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Origin': f'https://{self.config.auth_domain}',
            'Referer': f'https://{self.config.auth_domain}/usernamepassword/login',
        }
        
        response = self.session.post(
            form_url,
            data=fields,
            headers=form_headers,
            allow_redirects=False,
        )
        
        return self._follow_auth_redirects(response)
    
    def _follow_auth_redirects(self, initial_response: requests.Response) -> str:
        """
        Follow redirects until we get the callback URL with authorization code.
        
        Returns:
            Authorization code extracted from callback URL
        """
        response = initial_response
        max_redirects = 15  # Auth0 can have many redirects through SSO
        
        for i in range(max_redirects):
            if response.status_code not in (301, 302, 303, 307, 308):
                break
            
            location = response.headers.get("Location")
            if not location:
                break
            
            location = self._ensure_absolute_url(location)
            
            # Check if this is the callback URL with the code
            parsed = urlparse(location)
            query_params = parse_qs(parsed.query)
            
            if "code" in query_params:
                return query_params["code"][0]
            
            # Follow the redirect
            response = self.session.get(location, allow_redirects=False)
        
        # Check final URL
        final_url = response.url if hasattr(response, 'url') else None
        if final_url:
            parsed = urlparse(final_url)
            query_params = parse_qs(parsed.query)
            if "code" in query_params:
                return query_params["code"][0]
        
        raise PelotonAuthError("Failed to obtain authorization code from auth flow")
    
    def _exchange_code_for_token(self, code: str) -> TokenResponse:
        """
        Exchange authorization code for access token.
        
        Returns:
            TokenResponse with access_token and optionally refresh_token
        """
        token_endpoint = f"https://{self.config.auth_domain}{self.config.token_path}"
        
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "code_verifier": self.config.code_verifier,
            "code": code,
            "redirect_uri": self.config.redirect_uri,
        }
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        response = self.session.post(
            token_endpoint,
            json=payload,
            headers=headers,
        )
        
        if response.status_code != 200:
            try:
                error_data = response.json()
                error_msg = error_data.get("error_description") or error_data.get("error")
                raise PelotonAuthError(f"Token exchange failed: {error_msg}")
            except ValueError:
                raise PelotonAuthError(f"Token exchange failed: HTTP {response.status_code}")
        
        data = response.json()
        
        if not data.get("access_token"):
            raise PelotonAuthError("Token response missing access_token")
        
        return TokenResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 172800),
            scope=data.get("scope", ""),
        )
    
    def _ensure_absolute_url(self, url: str) -> str:
        """Ensure URL is absolute"""
        if url.startswith("http://") or url.startswith("https://"):
            return url
        if url.startswith("/"):
            return f"https://{self.config.auth_domain}{url}"
        return f"https://{self.config.auth_domain}/{url}"
    
    def login(self, email: str, password: str) -> TokenResponse:
        """
        Authenticate with Peloton using email and password.
        
        This performs the full Auth0 PKCE flow:
        1. Generate PKCE parameters
        2. Initiate auth flow and get CSRF token
        3. Submit credentials
        4. Exchange code for token
        
        Args:
            email: Peloton account email
            password: Peloton account password
            
        Returns:
            TokenResponse with access_token, refresh_token, etc.
            
        Raises:
            PelotonAuthError: If authentication fails
        """
        # Reset session for fresh auth
        self.session = requests.Session()
        self._setup_session()
        
        # Generate fresh PKCE parameters
        self._generate_pkce_params()
        
        # Step 1: Initiate auth flow
        login_url, csrf_token = self._initiate_auth_flow()
        
        # Step 2: Submit credentials
        code = self._submit_credentials(login_url, csrf_token, email, password)
        
        # Step 3: Exchange code for token
        token = self._exchange_code_for_token(code)
        
        return token
    
    def refresh(self, token: TokenResponse) -> TokenResponse:
        """
        Refresh an existing token using the refresh_token.
        
        Args:
            token: Existing TokenResponse with refresh_token
            
        Returns:
            New TokenResponse with fresh access_token
            
        Raises:
            PelotonAuthError: If refresh fails or no refresh_token available
        """
        if not token.refresh_token:
            raise PelotonAuthError("No refresh token available")
        
        token_endpoint = f"https://{self.config.auth_domain}{self.config.token_path}"
        
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": token.refresh_token,
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        
        response = self.session.post(
            token_endpoint,
            data=payload,
            headers=headers,
        )
        
        if response.status_code != 200:
            try:
                error_data = response.json()
                error_msg = error_data.get("error_description") or error_data.get("error")
                raise PelotonAuthError(f"Token refresh failed: {error_msg}")
            except ValueError:
                raise PelotonAuthError(f"Token refresh failed: HTTP {response.status_code}")
        
        data = response.json()
        
        return TokenResponse(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token", token.refresh_token),  # Keep old if not returned
            id_token=data.get("id_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 172800),
            scope=data.get("scope", ""),
        )


def get_user_id_from_token(access_token: str) -> Optional[str]:
    """
    Extract user_id from JWT access token.
    
    Args:
        access_token: JWT access token
        
    Returns:
        User ID string or None if extraction fails
    """
    try:
        # JWT format: header.payload.signature
        parts = access_token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode payload (add padding if needed)
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        import json
        decoded = base64.urlsafe_b64decode(payload)
        claims = json.loads(decoded)
        
        return claims.get("http://onepeloton.com/user_id")
    except Exception:
        return None
