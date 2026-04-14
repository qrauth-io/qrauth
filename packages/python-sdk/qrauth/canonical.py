"""Canonical payload serialization (QRVA protocol v2).

Python port of ``packages/shared/src/canonical.ts``. The two
implementations MUST produce byte-identical output for every input —
the canonical string is hashed into Merkle leaves, signed, and used
to compute MACs, so any drift between SDKs silently breaks every
signature it touches.

Cross-language test vectors live in
``packages/protocol-tests/fixtures/canonical-vectors.json``. The Node
side generates them from the authoritative implementation and both
SDKs verify against the same fixtures in CI. If any value drifts the
build fails.

Field order, separator, geo hash format, and forbidden-character
rules are pinned to the QRVA v2 protocol. Changing any of them
requires bumping ``QRVA_PROTOCOL_VERSION`` and coordinating a
deploy across every SDK and the API server.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

QRVA_PROTOCOL_VERSION = "qrva-v2"
CANONICAL_FIELD_SEPARATOR = "|"

# Forbidden characters: any field that contains one of these would
# break the parse-back contract. The defensive check matches Node's
# ``assertCanonicalSafe``.
_FORBIDDEN_CHARS = ("|", "\n", "\0")


@dataclass(frozen=True)
class CanonicalQRPayload:
    """A single QR payload in canonical form.

    Mirrors the ``CanonicalQRPayload`` interface in
    ``packages/shared/src/canonical.ts``. Lat/lng/radius are all
    optional but MUST all be set together or all be ``None`` —
    partial location data raises ``ValueError``.
    """

    token: str
    tenant_id: str
    destination_url: str
    lat: Optional[float]
    lng: Optional[float]
    radius_m: Optional[int]
    expires_at: str
    nonce: str


def sha3_256_hex(value: str) -> str:
    """SHA3-256 of a UTF-8 string, hex-encoded.

    Uses Python's built-in ``hashlib.sha3_256``, which has produced
    output identical to OpenSSL's SHA3-256 since Python 3.6. Cross-
    checked against Node's ``crypto.createHash('sha3-256')`` in the
    test vector suite.
    """
    return hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def canonical_geo_hash(
    lat: Optional[float],
    lng: Optional[float],
    radius_m: Optional[int],
) -> str:
    """Compute the canonical geo hash for a (lat, lng, radius) triple.

    - All-None → literal ``"none"``.
    - Otherwise → SHA3-256 of ``f"{lat:.7f}:{lng:.7f}:{int(radius)}"``
      using fixed-precision formatting so 41.4 and 41.40 produce
      identical hashes. Cross-language SDKs MUST follow the exact
      same formatting — the seven decimal places give roughly
      one-centimeter precision and any deviation here breaks Merkle
      leaf parity.
    """
    if lat is None and lng is None and radius_m is None:
        return "none"
    if lat is None or lng is None or radius_m is None:
        raise ValueError(
            "canonical_geo_hash: lat, lng, and radius_m must all be set or all None"
        )
    formatted = f"{lat:.7f}:{lng:.7f}:{int(radius_m)}"
    return sha3_256_hex(formatted)


def assert_canonical_safe(field_name: str, value: str) -> None:
    """Reject any field value that would break the parse-back contract.

    Without this check, a payload with ``tenant_id="a|b"`` could
    canonicalize to the same string as a payload with a different
    field layout — the canonical form has no escaping. Production
    callers never produce these (tokens come from a fixed charset,
    hashes are hex, IDs are cuids), but the canonicalizer is the
    single source of truth and must enforce the contract.
    """
    if not isinstance(value, str):
        raise TypeError(
            f"canonical: field '{field_name}' must be a string, got {type(value).__name__}"
        )
    for ch in _FORBIDDEN_CHARS:
        if ch in value:
            raise ValueError(
                f"canonical: field '{field_name}' contains a forbidden character "
                f"({CANONICAL_FIELD_SEPARATOR!r}, newline, or NUL)"
            )


def canonicalize_payload(payload: CanonicalQRPayload) -> str:
    """Build the canonical payload string for a QR code.

    Fields are concatenated in fixed order, separated by ``|``.
    Destination URL and geo coordinates are hashed individually so
    the canonical form leaks neither the URL nor the precise location
    to anyone who only sees the leaf hash on the transparency log.

    The exact byte sequence this function returns is the input to
    every Merkle leaf hash and every MAC computation in the system.
    Drift between this and the Node implementation breaks every
    signature it touches.
    """
    assert_canonical_safe("token", payload.token)
    assert_canonical_safe("tenant_id", payload.tenant_id)
    assert_canonical_safe("expires_at", payload.expires_at)
    assert_canonical_safe("nonce", payload.nonce)

    dest_hash = sha3_256_hex(payload.destination_url)
    geo_hash = canonical_geo_hash(payload.lat, payload.lng, payload.radius_m)

    return CANONICAL_FIELD_SEPARATOR.join(
        [
            payload.token,
            payload.tenant_id,
            dest_hash,
            geo_hash,
            payload.expires_at,
            payload.nonce,
        ]
    )


__all__ = [
    "QRVA_PROTOCOL_VERSION",
    "CANONICAL_FIELD_SEPARATOR",
    "CanonicalQRPayload",
    "sha3_256_hex",
    "canonical_geo_hash",
    "canonicalize_payload",
    "assert_canonical_safe",
]
