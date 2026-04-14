"""Cross-language test vector consumer for the Python side.

Reads ``packages/protocol-tests/fixtures/canonical-vectors.json`` and
asserts the Python implementation reproduces every recorded value
exactly. The Node side reads the same file via
``packages/protocol-tests/src/cross-language-vectors.test.ts``. Drift
between the two languages fails one suite or the other and blocks CI.

Run with::

    cd packages/python-sdk
    python -m pytest tests/test_canonical_vectors.py -v

Or from the repo root::

    python -m pytest packages/python-sdk/tests/

No third-party dependencies required — only ``hashlib`` and the
standard library, plus pytest for the test runner.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

# Make the qrauth package importable when running from the repo root.
SDK_ROOT = Path(__file__).resolve().parent.parent
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from qrauth.canonical import (  # noqa: E402
    CanonicalQRPayload,
    canonical_geo_hash,
    canonicalize_payload,
    sha3_256_hex,
)

FIXTURES_PATH = (
    Path(__file__).resolve().parents[2]
    / "protocol-tests"
    / "fixtures"
    / "canonical-vectors.json"
)


def _load_fixtures() -> list[dict]:
    """Load the cross-language fixtures file. Skip the suite (don't
    fail) if the file is missing so a Python-only checkout still
    runs the unit tests below."""
    if not FIXTURES_PATH.exists():
        pytest.skip(
            f"fixtures file missing at {FIXTURES_PATH}; "
            "run `npx tsx packages/protocol-tests/scripts/generate-vectors.ts` to generate"
        )
    return json.loads(FIXTURES_PATH.read_text())["vectors"]


def _payload_from_dict(d: dict) -> CanonicalQRPayload:
    return CanonicalQRPayload(
        token=d["token"],
        tenant_id=d["tenantId"],
        destination_url=d["destinationUrl"],
        lat=d["lat"],
        lng=d["lng"],
        radius_m=d["radiusM"],
        expires_at=d["expiresAt"],
        nonce=d["nonce"],
    )


_FIXTURES = _load_fixtures() if FIXTURES_PATH.exists() else []
_FIXTURE_IDS = [v["name"] for v in _FIXTURES]


def test_fixtures_pin_protocol_v2() -> None:
    """The fixtures file must declare qrva-v2 — bumping the protocol
    version is a deliberate, coordinated upgrade event and we want
    this assertion to fire if anyone changes it accidentally."""
    if not FIXTURES_PATH.exists():
        pytest.skip("fixtures file missing")
    data = json.loads(FIXTURES_PATH.read_text())
    assert data["protocolVersion"] == "qrva-v2"


def test_fixtures_non_empty() -> None:
    if not FIXTURES_PATH.exists():
        pytest.skip("fixtures file missing")
    assert len(_FIXTURES) > 0


@pytest.mark.parametrize("vector", _FIXTURES, ids=_FIXTURE_IDS)
def test_destination_hash_matches(vector: dict) -> None:
    out = sha3_256_hex(vector["payload"]["destinationUrl"])
    assert out == vector["expected"]["destinationHash"]


@pytest.mark.parametrize("vector", _FIXTURES, ids=_FIXTURE_IDS)
def test_geo_hash_matches(vector: dict) -> None:
    p = vector["payload"]
    out = canonical_geo_hash(p["lat"], p["lng"], p["radiusM"])
    assert out == vector["expected"]["geoHash"]


@pytest.mark.parametrize("vector", _FIXTURES, ids=_FIXTURE_IDS)
def test_canonical_string_matches_byte_for_byte(vector: dict) -> None:
    out = canonicalize_payload(_payload_from_dict(vector["payload"]))
    assert out == vector["expected"]["canonical"]


@pytest.mark.parametrize("vector", _FIXTURES, ids=_FIXTURE_IDS)
def test_canonical_sha3_matches(vector: dict) -> None:
    canonical = canonicalize_payload(_payload_from_dict(vector["payload"]))
    sha3 = hashlib.sha3_256(canonical.encode("utf-8")).hexdigest()
    assert sha3 == vector["expected"]["canonicalSha3"]


@pytest.mark.parametrize("vector", _FIXTURES, ids=_FIXTURE_IDS)
def test_leaf_hash_matches(vector: dict) -> None:
    """Compute the Merkle leaf hash on the Python side using the same
    convention as the Node `computeLeafHash` helper:

        leaf = sha3_256( 0x00 || canonical_string )

    The 0x00 prefix is the Merkle leaf domain-separation tag — see
    `MERKLE_LEAF_PREFIX` in packages/api/src/services/merkle-signing.ts.
    """
    canonical = canonicalize_payload(_payload_from_dict(vector["payload"]))
    h = hashlib.sha3_256()
    h.update(b"\x00")
    h.update(canonical.encode("utf-8"))
    assert h.hexdigest() == vector["expected"]["leafHash"]
