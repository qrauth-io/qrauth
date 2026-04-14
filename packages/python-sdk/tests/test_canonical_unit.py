"""Unit tests for ``qrauth.canonical``.

These run without the cross-language fixtures file and cover the
contract of the Python implementation in isolation. The
``test_canonical_vectors.py`` suite covers byte-for-byte parity with
the Node reference implementation.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from qrauth.canonical import (  # noqa: E402
    CANONICAL_FIELD_SEPARATOR,
    CanonicalQRPayload,
    QRVA_PROTOCOL_VERSION,
    assert_canonical_safe,
    canonical_geo_hash,
    canonicalize_payload,
    sha3_256_hex,
)


def _make_payload(**overrides) -> CanonicalQRPayload:
    base = dict(
        token="abc123",
        tenant_id="tnt_test",
        destination_url="https://example.com/x",
        lat=None,
        lng=None,
        radius_m=None,
        expires_at="2027-01-01T00:00:00.000Z",
        nonce="deadbeef",
    )
    base.update(overrides)
    return CanonicalQRPayload(**base)


class TestProtocolPin:
    def test_protocol_version_is_qrva_v2(self) -> None:
        assert QRVA_PROTOCOL_VERSION == "qrva-v2"

    def test_field_separator_is_pipe(self) -> None:
        assert CANONICAL_FIELD_SEPARATOR == "|"


class TestSha3:
    def test_known_input(self) -> None:
        # Cross-checked against Node's `createHash('sha3-256')` and
        # OpenSSL's sha3-256 — same digest in all three.
        assert sha3_256_hex("x") == hashlib.sha3_256(b"x").hexdigest()
        assert (
            sha3_256_hex("https://acme.example/promo")
            == hashlib.sha3_256(b"https://acme.example/promo").hexdigest()
        )

    def test_output_is_64_hex_chars(self) -> None:
        out = sha3_256_hex("anything")
        assert len(out) == 64
        assert all(c in "0123456789abcdef" for c in out)


class TestCanonicalGeoHash:
    def test_all_null_returns_literal_none(self) -> None:
        assert canonical_geo_hash(None, None, None) == "none"

    def test_partial_null_raises(self) -> None:
        with pytest.raises(ValueError):
            canonical_geo_hash(40.0, None, None)
        with pytest.raises(ValueError):
            canonical_geo_hash(None, 23.0, None)
        with pytest.raises(ValueError):
            canonical_geo_hash(None, None, 50)
        with pytest.raises(ValueError):
            canonical_geo_hash(40.0, 23.0, None)
        with pytest.raises(ValueError):
            canonical_geo_hash(40.0, None, 50)
        with pytest.raises(ValueError):
            canonical_geo_hash(None, 23.0, 50)

    def test_seven_decimal_normalization(self) -> None:
        # 41.4 and 41.4000000 must produce identical hashes.
        a = canonical_geo_hash(41.4, 23.7, 50)
        b = canonical_geo_hash(41.4000000, 23.7000000, 50)
        assert a == b

    def test_distinct_at_seventh_decimal(self) -> None:
        a = canonical_geo_hash(41.4000001, 23.7, 50)
        b = canonical_geo_hash(41.4000002, 23.7, 50)
        assert a != b

    def test_radius_truncated_to_int(self) -> None:
        a = canonical_geo_hash(40.0, 23.0, 100)
        b = canonical_geo_hash(40.0, 23.0, 100.7)  # type: ignore[arg-type]
        # int() truncation (not rounding) matches `Math.trunc()` in Node.
        assert a == b


class TestCanonicalizePayload:
    def test_deterministic(self) -> None:
        a = canonicalize_payload(_make_payload())
        b = canonicalize_payload(_make_payload())
        assert a == b

    def test_six_pipe_separated_parts(self) -> None:
        out = canonicalize_payload(_make_payload())
        assert out.count("|") == 5
        assert "\n" not in out

    def test_field_independence_token(self) -> None:
        a = canonicalize_payload(_make_payload(token="abc123"))
        b = canonicalize_payload(_make_payload(token="abc124"))
        assert a != b

    def test_field_independence_destination(self) -> None:
        a = canonicalize_payload(_make_payload(destination_url="https://example.com/a"))
        b = canonicalize_payload(_make_payload(destination_url="https://example.com/b"))
        assert a != b

    def test_field_independence_nonce(self) -> None:
        a = canonicalize_payload(_make_payload(nonce="00"))
        b = canonicalize_payload(_make_payload(nonce="01"))
        assert a != b

    def test_includes_destination_hash_not_url(self) -> None:
        url = "https://example.com/secret"
        out = canonicalize_payload(_make_payload(destination_url=url))
        # The plaintext URL must NOT appear in the canonical string —
        # only its SHA3 hash. This is what makes the transparency log
        # "commitment-only" — the URL is computationally hidden.
        assert url not in out
        assert sha3_256_hex(url) in out


class TestSeparatorInjectionDefense:
    """Pin the rejection path the property fuzz suite caught on the
    Node side. Pipes, newlines, and NUL bytes in fields must throw
    instead of producing an ambiguous canonical string."""

    @pytest.mark.parametrize("forbidden", ["|", "\n", "\0"])
    def test_token_with_forbidden_char(self, forbidden: str) -> None:
        with pytest.raises(ValueError, match="forbidden character"):
            canonicalize_payload(_make_payload(token=f"abc{forbidden}def"))

    @pytest.mark.parametrize("forbidden", ["|", "\n", "\0"])
    def test_tenant_id_with_forbidden_char(self, forbidden: str) -> None:
        with pytest.raises(ValueError, match="forbidden character"):
            canonicalize_payload(_make_payload(tenant_id=f"tnt{forbidden}"))

    @pytest.mark.parametrize("forbidden", ["|", "\n", "\0"])
    def test_nonce_with_forbidden_char(self, forbidden: str) -> None:
        with pytest.raises(ValueError, match="forbidden character"):
            canonicalize_payload(_make_payload(nonce=f"deadbeef{forbidden}"))

    def test_assert_canonical_safe_accepts_safe(self) -> None:
        assert_canonical_safe("token", "abc123")
        assert_canonical_safe("token", "with-dashes_and.dots")
        assert_canonical_safe("token", "")  # empty is safe

    def test_assert_canonical_safe_rejects_non_string(self) -> None:
        with pytest.raises(TypeError):
            assert_canonical_safe("token", None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            assert_canonical_safe("token", 42)  # type: ignore[arg-type]
