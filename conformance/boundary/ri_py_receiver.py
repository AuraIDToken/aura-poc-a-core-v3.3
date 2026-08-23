"""BC-02.2 - RI-PY Receiver v1.

Independent Python receiver for the BC-02.1 Common Receipt Schema v1.

This module is a construction artifact. It observes a handoff and constructs a
receipt. It does not execute conformance, B-VAL-014, or CONF-003 section 4.5,
and it cannot express a conformance result.

Independence: the only contract shared with BC-02.3 (RI-RS) is BC-02.1 itself.
Nothing here imports, wraps, or is derived from the RI-RS implementation. The
decomposition is deliberately its own: provenance is bound once to a receiver
instance, digest derivation is private to that instance, and validation returns
a complete per-assertion report rather than failing at the first problem.

Per AGENTS.md rule 4, no validation outcome in this module relies on `assert`.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
from dataclasses import dataclass, fields
from enum import Enum
from typing import Any, Dict, List, Sequence, Tuple

SCHEMA_ID = "BC-02.1-COMMON-RECEIPT"
SCHEMA_VERSION = 1

LANGUAGE = "Python"

#: BC-02.1 section 12.8 - Base64 is the JSON transport encoding of the octet
#: sequence. It is a representation of `raw_octets`, never a digest input.
RAW_OCTET_TRANSPORT_ENCODING = "base64"

#: BC-02.1 section 14 / R-INV-04. Keys that would carry result authority.
FORBIDDEN_RECEIPT_KEYS = frozenset(
    {
        "conformance_result",
        "conformance",
        "acceptance_state",
        "expected_acceptance",
        "digest_output_state",
        "expected_digest_output",
        "result",
        "verdict",
        "outcome",
        "pass",
        "fail",
    }
)

#: BC-02.1 section 5. Values prohibited anywhere in the receipt.
FORBIDDEN_RECEIPT_VALUES = frozenset({"PASS", "FAIL", "CONFORMANT", "NON_CONFORMANT"})


class ReceiptConstructionError(Exception):
    """Raised when receipt construction is impossible. Not a conformance result."""


class HandoffStatus(Enum):
    """BC-02.1 section 5 closed engineering domain. Handoff state only."""

    TRANSFERRED = "TRANSFERRED"
    NOT_TRANSFERRED = "NOT_TRANSFERRED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class FixtureIdentity:
    """BC-02.1 section 4. Refers to the issued artifact, never to a parsed object."""

    fixture_id: str
    fixture_artifact_identity: str


@dataclass(frozen=True)
class Handoff:
    status: HandoffStatus
    method: str


@dataclass(frozen=True)
class ReceivedMaterial:
    """BC-02.1 section 6. Constructed only by `BoundaryReceiver`.

    `raw_octets` keeps octet semantics as `bytes`. Base64 appears only at the
    transport boundary in `serialize_receipt`.
    """

    octet_length: int
    raw_octets: bytes
    recomputed_sha256: str


@dataclass(frozen=True)
class ReceiverIdentity:
    receiver_id: str
    implementation_id: str
    implementation_version: str
    source_commit: str
    language: str = LANGUAGE


@dataclass(frozen=True)
class AdapterIdentity:
    """BC-02.1 section 8. Independent of the implementation; no default aliasing."""

    adapter_id: str
    adapter_version: str


@dataclass(frozen=True)
class EnvironmentIdentity:
    environment_id: str
    platform: str
    runtime: str


@dataclass(frozen=True)
class BoundaryReceipt:
    """BC-02.1 section 3 logical model.

    Evidence input. Carries no conformance-result field, by construction.
    """

    fixture: FixtureIdentity
    handoff: Handoff
    received: ReceivedMaterial
    receiver: ReceiverIdentity
    adapter: AdapterIdentity
    environment: EnvironmentIdentity
    schema_id: str = SCHEMA_ID
    schema_version: int = SCHEMA_VERSION


class BoundaryReceiver:
    """Constructs BC-02.1 receipts from octets actually handed to it.

    Receiver, implementation, adapter and environment provenance are bound once,
    at construction, so a single receipt cannot silently mix identities. The
    per-handoff surface is then only: fixture identity, transfer method, octets.

    The digest is derived internally. `receive()` exposes no digest parameter, so
    a caller cannot supply one; `digest_input_is_caller_supplied()` makes that
    property checkable rather than merely documented.
    """

    def __init__(
        self,
        receiver: ReceiverIdentity,
        adapter: AdapterIdentity,
        environment: EnvironmentIdentity,
    ) -> None:
        for label, identity in (
            ("receiver", receiver),
            ("adapter", adapter),
            ("environment", environment),
        ):
            if identity is None:
                raise ReceiptConstructionError(f"{label} identity is required")
        self._receiver = receiver
        self._adapter = adapter
        self._environment = environment

    @property
    def receiver_identity(self) -> ReceiverIdentity:
        return self._receiver

    @property
    def adapter_identity(self) -> AdapterIdentity:
        return self._adapter

    @property
    def environment_identity(self) -> EnvironmentIdentity:
        return self._environment

    def receive(
        self,
        fixture: FixtureIdentity,
        method: str,
        octets: bytes,
        status: HandoffStatus = HandoffStatus.TRANSFERRED,
    ) -> BoundaryReceipt:
        """Observe a handoff of `octets` and construct the receipt.

        `octets` must be an octet sequence. `str` is rejected: a text argument is
        how a hexadecimal or Base64 rendering would silently become digest input.
        """
        if not isinstance(fixture, FixtureIdentity):
            raise ReceiptConstructionError("fixture identity is required")
        if not isinstance(status, HandoffStatus):
            raise ReceiptConstructionError(
                "handoff status must belong to the closed BC-02.1 domain"
            )
        if not isinstance(method, str) or not method:
            raise ReceiptConstructionError("handoff method is required")
        return BoundaryReceipt(
            fixture=fixture,
            handoff=Handoff(status=status, method=method),
            received=self._observe(octets),
            receiver=self._receiver,
            adapter=self._adapter,
            environment=self._environment,
        )

    @staticmethod
    def _observe(octets: bytes) -> ReceivedMaterial:
        """Derive the received material. The single digest-input path."""
        if isinstance(octets, str):
            raise ReceiptConstructionError(
                "received material must be octets, not text; a textual rendering "
                "(hex, Base64) is not a valid digest input"
            )
        if not isinstance(octets, (bytes, bytearray, memoryview)):
            raise ReceiptConstructionError("received material must be an octet sequence")
        material = bytes(octets)
        return ReceivedMaterial(
            octet_length=len(material),
            raw_octets=material,
            recomputed_sha256=hashlib.sha256(material).hexdigest(),
        )

    @classmethod
    def digest_input_is_caller_supplied(cls) -> bool:
        """True if any `receive()` parameter could carry a digest. Always False."""
        suspect = ("sha", "digest", "hash", "expected", "checksum")
        for name in inspect.signature(cls.receive).parameters:
            lowered = name.lower()
            if any(token in lowered for token in suspect):
                return True
        return False


def _transport_mapping(receipt: BoundaryReceipt) -> Dict[str, Any]:
    """BC-02.1 section 12 transport mapping.

    Every field explicit, no implicit defaults, no `null`, octets carried as the
    declared Base64 transport encoding.
    """
    if not isinstance(receipt.handoff.status, HandoffStatus):
        raise ReceiptConstructionError(
            "handoff status must belong to the closed BC-02.1 domain to be serialized"
        )
    received = receipt.received
    raw = received.raw_octets
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise ReceiptConstructionError("raw_octets must be octets to be serialized")
    return {
        "schema_id": receipt.schema_id,
        "schema_version": receipt.schema_version,
        "fixture": {
            "fixture_id": receipt.fixture.fixture_id,
            "fixture_artifact_identity": receipt.fixture.fixture_artifact_identity,
        },
        "handoff": {
            "status": receipt.handoff.status.value,
            "method": receipt.handoff.method,
        },
        "received": {
            "octet_length": received.octet_length,
            "raw_octets": base64.b64encode(bytes(raw)).decode("ascii"),
            "recomputed_sha256": received.recomputed_sha256,
        },
        "receiver": {
            "receiver_id": receipt.receiver.receiver_id,
            "implementation_id": receipt.receiver.implementation_id,
            "language": receipt.receiver.language,
            "implementation_version": receipt.receiver.implementation_version,
            "source_commit": receipt.receiver.source_commit,
        },
        "adapter": {
            "adapter_id": receipt.adapter.adapter_id,
            "adapter_version": receipt.adapter.adapter_version,
        },
        "environment": {
            "environment_id": receipt.environment.environment_id,
            "platform": receipt.environment.platform,
            "runtime": receipt.environment.runtime,
        },
    }


def serialize_receipt(receipt: BoundaryReceipt) -> bytes:
    """Deterministic BC-02.1 section 12 receipt serialization.

    UTF-8, lexicographic member order, compact separators, no insignificant
    whitespace, Base64 transport for `raw_octets`. Repeat calls on an equal
    receipt produce identical octets.
    """
    return json.dumps(
        _transport_mapping(receipt),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def decode_transport_octets(encoded: str) -> bytes:
    """Reverse the Base64 transport encoding. Makes the representation checkable."""
    return base64.b64decode(encoded.encode("ascii"), validate=True)


@dataclass(frozen=True)
class ValidationResult:
    """One R-VAL assertion outcome. Schema validation, never conformance."""

    assertion_id: str
    scope: str
    passed: bool
    detail: str


def _walk(node: Any) -> Tuple[List[str], List[Any]]:
    keys: List[str] = []
    values: List[Any] = []
    if isinstance(node, dict):
        for key, child in node.items():
            keys.append(key)
            sub_keys, sub_values = _walk(child)
            keys.extend(sub_keys)
            values.extend(sub_values)
    elif isinstance(node, (list, tuple)):
        for child in node:
            sub_keys, sub_values = _walk(child)
            keys.extend(sub_keys)
            values.extend(sub_values)
    else:
        values.append(node)
    return keys, values


def _keys_sorted(node: Any) -> bool:
    if isinstance(node, dict):
        names = list(node.keys())
        if names != sorted(names):
            return False
        return all(_keys_sorted(child) for child in node.values())
    if isinstance(node, (list, tuple)):
        return all(_keys_sorted(child) for child in node)
    return True


def validate_receipt(receipt: BoundaryReceipt) -> List[ValidationResult]:
    """Run R-VAL-001..012 and return every outcome.

    Schema/receipt validation only. These are construction assertions; they are
    not conformance assertions and establish no protocol result. Every assertion
    is evaluated - the report is complete even when an early one fails.
    """
    results: List[ValidationResult] = []

    def record(assertion_id: str, scope: str, passed: bool, detail: str) -> None:
        results.append(ValidationResult(assertion_id, scope, bool(passed), detail))

    received = receipt.received
    raw = received.raw_octets
    raw_is_octets = isinstance(raw, (bytes, bytearray, memoryview))

    record(
        "R-VAL-001",
        "schema identity/version present",
        receipt.schema_id == SCHEMA_ID and receipt.schema_version == SCHEMA_VERSION,
        "schema_id={0!r} schema_version={1!r}".format(receipt.schema_id, receipt.schema_version),
    )

    record(
        "R-VAL-002",
        "fixture identity fields present",
        bool(receipt.fixture.fixture_id) and bool(receipt.fixture.fixture_artifact_identity),
        "fixture_id={0!r} fixture_artifact_identity={1!r}".format(
            receipt.fixture.fixture_id, receipt.fixture.fixture_artifact_identity
        ),
    )

    record(
        "R-VAL-003",
        "handoff state belongs to closed domain",
        isinstance(receipt.handoff.status, HandoffStatus)
        and receipt.handoff.status.value not in FORBIDDEN_RECEIPT_VALUES
        and bool(receipt.handoff.method),
        "status={0!r} method={1!r} domain={2}".format(
            getattr(receipt.handoff.status, "value", receipt.handoff.status),
            receipt.handoff.method,
            sorted(member.value for member in HandoffStatus),
        ),
    )

    record(
        "R-VAL-004",
        "received length is explicit",
        isinstance(received.octet_length, int)
        and not isinstance(received.octet_length, bool)
        and raw_is_octets
        and received.octet_length == len(bytes(raw)),
        "octet_length={0!r} len(raw_octets)={1}".format(
            received.octet_length, len(bytes(raw)) if raw_is_octets else "n/a"
        ),
    )

    if raw_is_octets:
        independent_digest = hashlib.sha256(bytes(raw)).hexdigest()
        digest_matches = independent_digest == received.recomputed_sha256
    else:
        independent_digest = "n/a"
        digest_matches = False
    record(
        "R-VAL-005",
        "recomputed hash is explicitly receiver-derived",
        digest_matches and not BoundaryReceiver.digest_input_is_caller_supplied(),
        "recorded={0!r} independent_recompute={1!r} receive_accepts_digest_parameter={2}".format(
            received.recomputed_sha256,
            independent_digest,
            BoundaryReceiver.digest_input_is_caller_supplied(),
        ),
    )

    record(
        "R-VAL-006",
        "receiver identity preserved",
        bool(receipt.receiver.receiver_id) and bool(receipt.receiver.language),
        "receiver_id={0!r} language={1!r}".format(
            receipt.receiver.receiver_id, receipt.receiver.language
        ),
    )

    record(
        "R-VAL-007",
        "implementation identity preserved",
        bool(receipt.receiver.implementation_id)
        and bool(receipt.receiver.implementation_version)
        and bool(receipt.receiver.source_commit)
        and receipt.receiver.implementation_id != receipt.receiver.receiver_id,
        "implementation_id={0!r} implementation_version={1!r} source_commit={2!r} "
        "distinct_from_receiver_id={3}".format(
            receipt.receiver.implementation_id,
            receipt.receiver.implementation_version,
            receipt.receiver.source_commit,
            receipt.receiver.implementation_id != receipt.receiver.receiver_id,
        ),
    )

    record(
        "R-VAL-008",
        "adapter identity preserved",
        bool(receipt.adapter.adapter_id)
        and bool(receipt.adapter.adapter_version)
        and receipt.adapter.adapter_id != receipt.receiver.implementation_id
        and receipt.adapter.adapter_id != receipt.receiver.receiver_id,
        "adapter_id={0!r} adapter_version={1!r} distinct_from_implementation_and_receiver={2}".format(
            receipt.adapter.adapter_id,
            receipt.adapter.adapter_version,
            receipt.adapter.adapter_id
            not in (receipt.receiver.implementation_id, receipt.receiver.receiver_id),
        ),
    )

    record(
        "R-VAL-009",
        "environment identity preserved",
        bool(receipt.environment.environment_id)
        and bool(receipt.environment.platform)
        and bool(receipt.environment.runtime),
        "environment_id={0!r} platform={1!r} runtime={2!r}".format(
            receipt.environment.environment_id,
            receipt.environment.platform,
            receipt.environment.runtime,
        ),
    )

    if raw_is_octets:
        try:
            round_trip = decode_transport_octets(
                base64.b64encode(bytes(raw)).decode("ascii")
            )
            reversible = round_trip == bytes(raw)
        except (ValueError, TypeError):
            reversible = False
    else:
        reversible = False
    record(
        "R-VAL-010",
        "raw material is not silently reconstructed",
        raw_is_octets and reversible,
        "raw_octets_type={0} transport_encoding={1} reversible={2}".format(
            type(raw).__name__, RAW_OCTET_TRANSPORT_ENCODING, reversible
        ),
    )

    try:
        first = serialize_receipt(receipt)
        second = serialize_receipt(receipt)
        mapping = _transport_mapping(receipt)
        _, values = _walk(mapping)
        stable = first == second
        sorted_keys = _keys_sorted(json.loads(first.decode("utf-8")))
        null_free = not any(value is None for value in values)
        compact = b", " not in first and b'": ' not in first
        serialization_ok = stable and sorted_keys and null_free and compact
        serialization_detail = (
            "stable_repeat={0} lexicographic_keys={1} null_free={2} compact={3} octets={4}".format(
                stable, sorted_keys, null_free, compact, len(first)
            )
        )
    except (ReceiptConstructionError, TypeError, ValueError) as exc:
        serialization_ok = False
        serialization_detail = "serialization failed: {0}".format(exc)
    record(
        "R-VAL-011",
        "deterministic serialization is possible",
        serialization_ok,
        serialization_detail,
    )

    schema_field_names = {field_def.name for field_def in fields(BoundaryReceipt)}
    try:
        mapping = _transport_mapping(receipt)
        keys, values = _walk(mapping)
        offending_keys = sorted(
            {key for key in keys if key.lower() in FORBIDDEN_RECEIPT_KEYS}
        )
        offending_values = sorted(
            {
                str(value)
                for value in values
                if isinstance(value, str) and value.upper() in FORBIDDEN_RECEIPT_VALUES
            }
        )
        field_set_exact = set(mapping.keys()) == schema_field_names
        authority_isolated = (
            not offending_keys and not offending_values and field_set_exact
        )
        authority_detail = (
            "forbidden_keys={0} forbidden_values={1} field_set_exact={2}".format(
                offending_keys, offending_values, field_set_exact
            )
        )
    except (ReceiptConstructionError, TypeError, ValueError) as exc:
        authority_isolated = False
        authority_detail = "authority scan failed: {0}".format(exc)
    record(
        "R-VAL-012",
        "schema contains no conformance-result authority",
        authority_isolated,
        authority_detail,
    )

    return results


def format_validation_report(results: Sequence[ValidationResult]) -> str:
    """Render each assertion on its own line. Schema validation only."""
    return "\n".join(
        "{0}  {1}  {2} - {3}".format(
            item.assertion_id,
            "PASS" if item.passed else "FAIL",
            item.scope,
            item.detail,
        )
        for item in results
    )
