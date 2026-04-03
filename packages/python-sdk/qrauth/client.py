"""QRAuth Python SDK client."""

from __future__ import annotations

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
    BulkCreateResponse,
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

    Example::

        from qrauth import QRAuth

        qr = QRAuth(api_key="qrauth_xxx")
        code = qr.create("https://parking.gr/pay", location={"lat": 40.63, "lng": 22.94})
        result = qr.verify(code["token"])

    The client can also be used as a context manager::

        with QRAuth(api_key="qrauth_xxx") as qr:
            code = qr.create("https://example.com")
    """

    def __init__(self, api_key: str, *, base_url: str = _DEFAULT_BASE_URL) -> None:
        if not api_key:
            raise ValueError("QRAuth: api_key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={
                "X-API-Key": api_key,
                "User-Agent": _USER_AGENT,
            },
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
        """Generate multiple signed QR codes in a single request (max 100).

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
        response = self._client.request(
            method,
            path,
            json=json,
            params=params,
            headers=headers,
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
