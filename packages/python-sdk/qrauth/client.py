"""QRAuth Python SDK client."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote

import httpx

from .errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    QRAuthError,
    RateLimitError,
    ValidationError,
)
from .types import (
    AuthSessionResponse,
    AuthSessionStatus,
    AuthSessionVerifyResult,
    BulkCreateResponse,
    ClaimEphemeralSessionOptions,
    EphemeralSessionClaimResult,
    EphemeralSessionDetail,
    EphemeralSessionResponse,
    PaginatedResponse,
    QRCodeDetail,
    QRCodeResponse,
    VerificationResult,
)

_DEFAULT_BASE_URL = "https://qrauth.io"
_USER_AGENT = "qrauth-python/0.1.0"
_DURATION_RE = re.compile(r"^(\d+)(s|m|h|d|w|mo|y)$")


class QRAuth:
    """QRAuth API client.

    Supports two authentication modes:

    - **API key** — for QR code management (create, verify, list, revoke, bulk).
    - **Client credentials** — for auth-session flows (create session, poll, verify result).

    You can provide both to use all features from a single instance.

    Example::

        from qrauth import QRAuth

        # QR code management only
        qr = QRAuth(api_key="qrauth_xxx")
        code = qr.create("https://municipal-parking.com/pay", location={"lat": 40.63, "lng": 22.94})
        result = qr.verify(code["token"])

        # Auth sessions only
        qr = QRAuth(client_id="qrauth_app_xxx", client_secret="secret")
        session = qr.create_auth_session(scopes=["identity", "email"])

        # Both
        qr = QRAuth(api_key="qrauth_xxx", client_id="qrauth_app_xxx", client_secret="secret")

    The client can also be used as a context manager::

        with QRAuth(api_key="qrauth_xxx") as qr:
            code = qr.create("https://example.com")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        if not api_key and not client_id:
            raise ValueError("QRAuth: provide at least api_key or client_id")

        self.api_key = api_key
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")

        # Shared httpx client without auth headers — auth is injected per-request
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"User-Agent": _USER_AGENT},
            timeout=30.0,
        )

    # ------------------------------------------------------------------
    # QR Code -- create
    # ------------------------------------------------------------------

    def create(
        self,
        destination: str,
        *,
        label: Optional[str] = None,
        location: Optional[Dict[str, Any]] = None,
        expires_in: Optional[str] = None,
        content_type: Optional[str] = None,
        content: Optional[Dict[str, Any]] = None,
    ) -> QRCodeResponse:
        """Generate a cryptographically signed QR code.

        Args:
            destination: Target URL the QR code points to.
            label: Human-readable label.
            location: Geo-fence binding ``{"lat": ..., "lng": ..., "radiusM": ...}``.
            expires_in: Duration string (``"30s"``, ``"5m"``, ``"6h"``, ``"30d"``,
                ``"1y"``) or an ISO 8601 datetime.
            content_type: Content type (``"url"``, ``"event"``, ``"coupon"``, etc.).
            content: Structured content payload for non-URL types.

        Returns:
            QR code metadata including *token*, *verification_url*, and *signature*.
        """
        body: Dict[str, Any] = {"destinationUrl": destination}

        if label is not None:
            body["label"] = label
        if location is not None:
            body["location"] = {
                "lat": location["lat"],
                "lng": location["lng"],
                "radiusM": location.get("radiusM", 50),
            }
        if expires_in is not None:
            body["expiresAt"] = _parse_duration(expires_in)
        if content_type is not None:
            body["contentType"] = content_type
        if content is not None:
            body["content"] = content

        return self._request("POST", "/api/v1/qrcodes", json=body)

    # ------------------------------------------------------------------
    # QR Code -- verify
    # ------------------------------------------------------------------

    def verify(
        self,
        token: str,
        *,
        client_lat: Optional[float] = None,
        client_lng: Optional[float] = None,
    ) -> VerificationResult:
        """Verify a QR code token and retrieve its trust score.

        Args:
            token: The QR code token to verify.
            client_lat: Scanner latitude for geo-fence matching.
            client_lng: Scanner longitude for geo-fence matching.

        Returns:
            Verification result with *verified*, *security*, and *organization* info.
        """
        params: Dict[str, Any] = {}
        if client_lat is not None:
            params["clientLat"] = client_lat
        if client_lng is not None:
            params["clientLng"] = client_lng

        return self._request(
            "GET",
            f"/api/v1/verify/{quote(token, safe='')}",
            params=params,
            headers={"Accept": "application/json"},
        )

    # ------------------------------------------------------------------
    # QR Code -- list
    # ------------------------------------------------------------------

    def list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
    ) -> PaginatedResponse:
        """List QR codes for your organization.

        Args:
            page: Page number (1-based).
            page_size: Number of items per page.
            status: Filter by status: ``"ACTIVE"``, ``"EXPIRED"``, or ``"REVOKED"``.

        Returns:
            Paginated response with *data*, *total*, *page*, *pageSize*, *totalPages*.
        """
        params: Dict[str, Any] = {"page": page, "pageSize": page_size}
        if status is not None:
            params["status"] = status

        return self._request("GET", "/api/v1/qrcodes", params=params)

    # ------------------------------------------------------------------
    # QR Code -- get
    # ------------------------------------------------------------------

    def get(self, token: str) -> QRCodeDetail:
        """Get details of a specific QR code.

        Args:
            token: The QR code token.

        Returns:
            Full QR code detail including scan count.
        """
        return self._request("GET", f"/api/v1/qrcodes/{quote(token, safe='')}")

    # ------------------------------------------------------------------
    # QR Code -- revoke
    # ------------------------------------------------------------------

    def revoke(self, token: str) -> Dict[str, str]:
        """Revoke a QR code so it no longer verifies.

        Args:
            token: The QR code token to revoke.

        Returns:
            Confirmation message.
        """
        return self._request("DELETE", f"/api/v1/qrcodes/{quote(token, safe='')}")

    # ------------------------------------------------------------------
    # QR Code -- bulk create
    # ------------------------------------------------------------------

    def bulk(self, items: Sequence[Dict[str, Any]]) -> BulkCreateResponse:
        """Generate multiple signed QR codes in a single request (max 64).

        Args:
            items: List of dicts, each with *destination* and optionally *label*,
                *location*, and *expires_in*.

        Returns:
            Bulk creation result with per-item success/error details.
        """
        body = {
            "items": [
                {
                    "destinationUrl": item["destination"],
                    **({"label": item["label"]} if "label" in item else {}),
                    **(
                        {
                            "location": {
                                "lat": item["location"]["lat"],
                                "lng": item["location"]["lng"],
                                "radiusM": item["location"].get("radiusM", 50),
                            }
                        }
                        if "location" in item
                        else {}
                    ),
                    **(
                        {"expiresAt": _parse_duration(item["expires_in"])}
                        if "expires_in" in item
                        else {}
                    ),
                }
                for item in items
            ]
        }

        return self._request("POST", "/api/v1/qrcodes/bulk", json=body)

    # ------------------------------------------------------------------
    # Auth Sessions -- create
    # ------------------------------------------------------------------

    def create_auth_session(
        self,
        *,
        scopes: Optional[List[str]] = None,
        redirect_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> AuthSessionResponse:
        """Create an auth session for QR-based login.

        Requires ``client_id`` and ``client_secret`` to be configured.

        Args:
            scopes: Requested scopes (e.g. ``["identity", "email"]``).
            redirect_url: URL to redirect after approval (for deep-link flows).
            metadata: Arbitrary metadata attached to the session.
            code_challenge: PKCE code challenge (S256). Required for public-client flows.
            code_challenge_method: Code challenge method. Only ``"S256"`` is supported.

        Returns:
            Auth session with *session_id*, *token*, *qr_url*, *qr_data_url*,
            *status*, *scopes*, and *expires_at*.
        """
        body: Dict[str, Any] = {}
        if scopes is not None:
            body["scopes"] = scopes
        if redirect_url is not None:
            body["redirectUrl"] = redirect_url
        if metadata is not None:
            body["metadata"] = metadata
        if code_challenge is not None:
            body["codeChallenge"] = code_challenge
        if code_challenge_method is not None:
            body["codeChallengeMethod"] = code_challenge_method

        return self._client_request("POST", "/api/v1/auth-sessions", json=body)

    # ------------------------------------------------------------------
    # Auth Sessions -- get / poll status
    # ------------------------------------------------------------------

    def get_auth_session(
        self,
        session_id: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> AuthSessionStatus:
        """Get the current status of an auth session.

        For PKCE sessions, provide ``code_verifier`` to access user data once
        the session is approved.

        Args:
            session_id: The session ID returned by ``create_auth_session()``.
            code_verifier: PKCE code verifier. Required to access user data on
                PKCE sessions.

        Returns:
            Session status including *status*, *scopes*, *user*, *signature*,
            and relevant timestamps.
        """
        params: Dict[str, Any] = {}
        if code_verifier is not None:
            params["code_verifier"] = code_verifier

        return self._client_request(
            "GET",
            f"/api/v1/auth-sessions/{quote(session_id, safe='')}",
            params=params,
        )

    # ------------------------------------------------------------------
    # Auth Sessions -- verify result
    # ------------------------------------------------------------------

    def verify_auth_result(
        self,
        session_id: str,
        signature: str,
    ) -> AuthSessionVerifyResult:
        """Verify an approved auth session from your backend callback.

        Call this after your frontend receives ``onSuccess`` from the browser
        SDK. Confirms the session is genuinely approved and the signature is
        valid.

        Args:
            session_id: The session ID to verify.
            signature: The signature received from the browser SDK callback.

        Returns:
            Verification result with *valid* flag and full *session* details
            including *user*.
        """
        body: Dict[str, Any] = {"sessionId": session_id, "signature": signature}
        return self._client_request("POST", "/api/v1/auth-sessions/verify-result", json=body)

    # ------------------------------------------------------------------
    # Ephemeral Sessions -- create
    # ------------------------------------------------------------------

    def create_ephemeral_session(
        self,
        scopes: List[str],
        *,
        ttl: Optional[str] = None,
        max_uses: Optional[int] = None,
        device_binding: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EphemeralSessionResponse:
        """Create an ephemeral session for time-limited, scope-constrained access.

        No account creation required — the scanned user receives a scoped JWT.

        Requires ``client_id`` and ``client_secret`` to be configured.

        Args:
            scopes: Permission scopes granted to the session (e.g.
                ``["read:menu", "write:order"]``).
            ttl: Time-to-live as a duration string (``"30m"``, ``"4h"``,
                ``"72h"``). Default: ``"30m"``.
            max_uses: Maximum number of times the session can be claimed.
                Default: 1.
            device_binding: Lock the session to the first device that claims
                it. Default: ``False``.
            metadata: Developer-defined context attached to the session.

        Returns:
            Ephemeral session with *session_id*, *token*, *claim_url*,
            *expires_at*, *scopes*, *ttl_seconds*, and *max_uses*.
        """
        body: Dict[str, Any] = {"scopes": scopes}
        if ttl is not None:
            body["ttl"] = ttl
        if max_uses is not None:
            body["maxUses"] = max_uses
        if device_binding is not None:
            body["deviceBinding"] = device_binding
        if metadata is not None:
            body["metadata"] = metadata

        return self._client_request("POST", "/api/v1/ephemeral", json=body)

    # ------------------------------------------------------------------
    # Ephemeral Sessions -- claim
    # ------------------------------------------------------------------

    def claim_ephemeral_session(
        self,
        token: str,
        *,
        device_fingerprint: Optional[str] = None,
    ) -> EphemeralSessionClaimResult:
        """Claim an ephemeral session. Called when a user scans the QR code.

        This is a public endpoint — no client credentials are required.

        Args:
            token: The ephemeral session token embedded in the QR code.
            device_fingerprint: Device fingerprint for device-bound sessions.

        Returns:
            Claim result with *session_id*, *status*, *scopes*, *metadata*,
            and *expires_at*.
        """
        body: Dict[str, Any] = {}
        if device_fingerprint is not None:
            body["deviceFingerprint"] = device_fingerprint

        return self._request(
            "POST",
            f"/api/v1/ephemeral/{quote(token, safe='')}/claim",
            json=body,
        )

    # ------------------------------------------------------------------
    # Ephemeral Sessions -- revoke
    # ------------------------------------------------------------------

    def revoke_ephemeral_session(self, session_id: str) -> Dict[str, str]:
        """Revoke an ephemeral session immediately.

        The session can no longer be claimed after revocation.

        Requires ``client_id`` and ``client_secret`` to be configured.

        Args:
            session_id: The ephemeral session ID to revoke.

        Returns:
            Confirmation dict with *status*.
        """
        return self._client_request(
            "DELETE",
            f"/api/v1/ephemeral/{quote(session_id, safe='')}",
        )

    # ------------------------------------------------------------------
    # Ephemeral Sessions -- list
    # ------------------------------------------------------------------

    def list_ephemeral_sessions(
        self,
        *,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> PaginatedResponse:
        """List ephemeral sessions for the authenticated app.

        Requires ``client_id`` and ``client_secret`` to be configured.

        Args:
            status: Filter by status: ``"PENDING"``, ``"CLAIMED"``,
                ``"EXPIRED"``, or ``"REVOKED"``.
            page: Page number (1-based).
            page_size: Number of items per page.

        Returns:
            Paginated response with *data*, *total*, *page*, *pageSize*,
            *totalPages*.
        """
        params: Dict[str, Any] = {"page": page, "pageSize": page_size}
        if status is not None:
            params["status"] = status

        return self._client_request("GET", "/api/v1/ephemeral", params=params)

    # ------------------------------------------------------------------
    # Proximity Attestation
    # ------------------------------------------------------------------

    def get_proximity_attestation(
        self,
        token: str,
        *,
        client_lat: float,
        client_lng: float,
    ) -> "ProximityAttestationResult":
        """Get a signed JWT proving device proximity to a QR code."""
        return self._request(
            "POST",
            f"/api/v1/proximity/{quote(token, safe='')}",
            json={"clientLat": client_lat, "clientLng": client_lng},
        )

    def verify_proximity_attestation(
        self,
        jwt_token: str,
        *,
        public_key: Optional[str] = None,
    ) -> "ProximityVerifyResult":
        """Verify a proximity attestation JWT."""
        body: Dict[str, Any] = {"jwt": jwt_token}
        if public_key is not None:
            body["publicKey"] = public_key
        return self._request("POST", "/api/v1/proximity/verify", json=body)

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        if not self.api_key:
            raise ValueError("QRAuth: api_key is required for QR code management methods")

        merged_headers: Dict[str, str] = {"X-API-Key": self.api_key}
        if headers:
            merged_headers.update(headers)

        response = self._client.request(
            method,
            path,
            json=json,
            params=params,
            headers=merged_headers,
        )

        if not response.is_success:
            self._handle_error(response)

        if response.status_code == 204:
            return {"message": "Success"}

        return response.json()

    def _client_request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Issue a request authenticated with Basic auth (client_id:client_secret)."""
        if not self.client_id or not self.client_secret:
            raise ValueError(
                "QRAuth: client_id and client_secret are required for auth-session methods"
            )

        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()

        response = self._client.request(
            method,
            path,
            json=json,
            params=params,
            headers={"Authorization": f"Basic {credentials}"},
        )

        if not response.is_success:
            self._handle_error(response)

        if response.status_code == 204:
            return {"message": "Success"}

        return response.json()

    @staticmethod
    def _handle_error(response: httpx.Response) -> None:
        try:
            body = response.json()
            message = body.get("message") or body.get("error") or response.reason_phrase
        except Exception:
            message = response.reason_phrase or "Unknown error"

        status = response.status_code

        if status == 400:
            raise ValidationError(message)
        if status == 401:
            raise AuthenticationError(message)
        if status == 403:
            raise AuthorizationError(message)
        if status == 404:
            raise NotFoundError(message)
        if status == 429:
            retry_after_raw = response.headers.get("retry-after")
            retry_after = int(retry_after_raw) if retry_after_raw else None
            raise RateLimitError(message, retry_after)

        raise QRAuthError(message, status, "API_ERROR")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> QRAuth:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Duration parser
# ---------------------------------------------------------------------------


def _parse_duration(value: str) -> str:
    """Convert a human-readable duration string to an ISO 8601 datetime.

    Supports: ``30s``, ``5m``, ``6h``, ``30d``, ``1w``, ``3mo``, ``1y``,
    or a raw ISO 8601 datetime (returned as-is).
    """
    # Already an ISO datetime -- return unchanged
    if "T" in value or "-" in value:
        return value

    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError(
            f'Invalid duration: "{value}". '
            "Use formats like 30s, 5m, 6h, 30d, 1w, 3mo, 1y or an ISO datetime."
        )

    amount = int(match.group(1))
    unit = match.group(2)
    now = datetime.now(timezone.utc)

    if unit == "s":
        now += timedelta(seconds=amount)
    elif unit == "m":
        now += timedelta(minutes=amount)
    elif unit == "h":
        now += timedelta(hours=amount)
    elif unit == "d":
        now += timedelta(days=amount)
    elif unit == "w":
        now += timedelta(weeks=amount)
    elif unit == "mo":
        # Approximate: add calendar months
        month = now.month - 1 + amount
        year = now.year + month // 12
        month = month % 12 + 1
        day = min(now.day, _days_in_month(year, month))
        now = now.replace(year=year, month=month, day=day)
    elif unit == "y":
        try:
            now = now.replace(year=now.year + amount)
        except ValueError:
            # Feb 29 in a leap year -> Feb 28
            now = now.replace(year=now.year + amount, day=28)

    return now.isoformat()


def _days_in_month(year: int, month: int) -> int:
    """Return the number of days in a given month."""
    import calendar

    return calendar.monthrange(year, month)[1]
