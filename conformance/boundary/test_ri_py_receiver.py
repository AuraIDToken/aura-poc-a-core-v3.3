"""BC-02.2 - RI-PY Receiver v1 construction tests.

R-VAL-001..012 plus construction robustness. Synthetic material only: no
FIX-DIGEST-P01 octets, no P-01 digest, no P-01 fixture identity, and no handoff
of any issued artifact. These are construction/schema assertions and establish
no protocol conformance.
"""

from __future__ import annotations

import base64
import hashlib
import json
import unittest

from conformance.boundary import ri_py_adapter, ri_py_receiver
from conformance.boundary.ri_py_receiver import (
    FORBIDDEN_RECEIPT_KEYS,
    FORBIDDEN_RECEIPT_VALUES,
    SCHEMA_ID,
    SCHEMA_VERSION,
    AdapterIdentity,
    BoundaryReceipt,
    BoundaryReceiver,
    EnvironmentIdentity,
    FixtureIdentity,
    Handoff,
    HandoffStatus,
    ReceivedMaterial,
    ReceiptConstructionError,
    ReceiverIdentity,
    decode_transport_octets,
    serialize_receipt,
    validate_receipt,
)

# Synthetic construction material. Deliberately not valid JSON, containing a NUL
# and a non-UTF-8 octet, so it cannot be confused with any issued fixture.
SYNTHETIC_OCTETS = b"BC-02.2 synthetic construction material \x00\xfe\xff"

SYNTHETIC_FIXTURE = FixtureIdentity(
    fixture_id="FIX-SYNTHETIC-BC022",
    fixture_artifact_identity="FIX-SYNTHETIC-BC022.construction.bin",
)


def build_receiver() -> BoundaryReceiver:
    return BoundaryReceiver(
        receiver=ReceiverIdentity(
            receiver_id="RI-PY",
            implementation_id="aura-ri-py",
            implementation_version="1.0.0",
            source_commit="construction-test",
        ),
        adapter=AdapterIdentity(
            adapter_id="BC-02.2-RI-PY-BOUNDARY-ADAPTER", adapter_version="1.0.0"
        ),
        environment=EnvironmentIdentity(
            environment_id="construction-test-env",
            platform="construction-test-platform",
            runtime="construction-test-runtime",
        ),
    )


def build_receipt(octets: bytes = SYNTHETIC_OCTETS) -> BoundaryReceipt:
    return build_receiver().receive(
        fixture=SYNTHETIC_FIXTURE,
        method="in-memory-octet-transfer",
        octets=octets,
    )


def outcome(receipt: BoundaryReceipt, assertion_id: str):
    for item in validate_receipt(receipt):
        if item.assertion_id == assertion_id:
            return item
    raise AssertionError("{0} was not reported".format(assertion_id))


class RValAssertions(unittest.TestCase):
    """One test per R-VAL assertion, reported individually."""

    def test_r_val_001_schema_identity(self):
        receipt = build_receipt()
        self.assertEqual(receipt.schema_id, SCHEMA_ID)
        self.assertEqual(receipt.schema_version, SCHEMA_VERSION)
        self.assertTrue(outcome(receipt, "R-VAL-001").passed)

    def test_r_val_002_fixture_identity(self):
        receipt = build_receipt()
        self.assertEqual(receipt.fixture.fixture_id, "FIX-SYNTHETIC-BC022")
        self.assertTrue(receipt.fixture.fixture_artifact_identity)
        self.assertTrue(outcome(receipt, "R-VAL-002").passed)

    def test_r_val_003_closed_handoff_domain(self):
        receipt = build_receipt()
        self.assertIn(receipt.handoff.status, set(HandoffStatus))
        self.assertNotIn(receipt.handoff.status.value, FORBIDDEN_RECEIPT_VALUES)
        self.assertTrue(outcome(receipt, "R-VAL-003").passed)

    def test_r_val_004_length_explicit(self):
        receipt = build_receipt()
        self.assertEqual(receipt.received.octet_length, len(SYNTHETIC_OCTETS))
        self.assertTrue(outcome(receipt, "R-VAL-004").passed)

    def test_r_val_005_digest_is_receiver_derived(self):
        receipt = build_receipt()
        self.assertEqual(
            receipt.received.recomputed_sha256,
            hashlib.sha256(SYNTHETIC_OCTETS).hexdigest(),
        )
        self.assertFalse(BoundaryReceiver.digest_input_is_caller_supplied())
        self.assertTrue(outcome(receipt, "R-VAL-005").passed)

    def test_r_val_006_receiver_identity(self):
        receipt = build_receipt()
        self.assertEqual(receipt.receiver.receiver_id, "RI-PY")
        self.assertEqual(receipt.receiver.language, "Python")
        self.assertTrue(outcome(receipt, "R-VAL-006").passed)

    def test_r_val_007_implementation_identity(self):
        receipt = build_receipt()
        self.assertNotEqual(
            receipt.receiver.implementation_id, receipt.receiver.receiver_id
        )
        self.assertTrue(receipt.receiver.source_commit)
        self.assertTrue(outcome(receipt, "R-VAL-007").passed)

    def test_r_val_008_adapter_identity(self):
        receipt = build_receipt()
        self.assertNotEqual(
            receipt.adapter.adapter_id, receipt.receiver.implementation_id
        )
        self.assertNotEqual(receipt.adapter.adapter_id, receipt.receiver.receiver_id)
        self.assertTrue(outcome(receipt, "R-VAL-008").passed)

    def test_r_val_009_environment_identity(self):
        receipt = build_receipt()
        self.assertTrue(receipt.environment.environment_id)
        self.assertTrue(receipt.environment.platform)
        self.assertTrue(receipt.environment.runtime)
        self.assertTrue(outcome(receipt, "R-VAL-009").passed)

    def test_r_val_010_raw_material_preserved(self):
        receipt = build_receipt()
        self.assertIsInstance(receipt.received.raw_octets, bytes)
        self.assertEqual(receipt.received.raw_octets, SYNTHETIC_OCTETS)
        transport = json.loads(serialize_receipt(receipt).decode("utf-8"))
        self.assertEqual(
            decode_transport_octets(transport["received"]["raw_octets"]),
            SYNTHETIC_OCTETS,
        )
        self.assertTrue(outcome(receipt, "R-VAL-010").passed)

    def test_r_val_011_deterministic_serialization(self):
        first = serialize_receipt(build_receipt())
        second = serialize_receipt(build_receipt())
        self.assertEqual(first, second)
        transport = json.loads(first.decode("utf-8"))
        self.assertEqual(list(transport.keys()), sorted(transport.keys()))
        self.assertNotIn(b", ", first)
        self.assertNotIn(b'": ', first)
        self.assertTrue(outcome(build_receipt(), "R-VAL-011").passed)

    def test_r_val_012_no_conformance_authority(self):
        receipt = build_receipt()
        transport = json.loads(serialize_receipt(receipt).decode("utf-8"))
        self.assertEqual(
            set(transport.keys()),
            {
                "schema_id",
                "schema_version",
                "fixture",
                "handoff",
                "received",
                "receiver",
                "adapter",
                "environment",
            },
        )
        blob = json.dumps(transport)
        for forbidden in FORBIDDEN_RECEIPT_KEYS:
            self.assertNotIn('"{0}"'.format(forbidden), blob)
        self.assertTrue(outcome(receipt, "R-VAL-012").passed)

    def test_every_assertion_is_reported(self):
        reported = [item.assertion_id for item in validate_receipt(build_receipt())]
        self.assertEqual(
            reported, ["R-VAL-{0:03d}".format(n) for n in range(1, 13)]
        )


class OctetIntake(unittest.TestCase):
    def test_digest_matches_independent_recomputation(self):
        for material in (b"", b"\x00", SYNTHETIC_OCTETS, bytes(range(256))):
            receipt = build_receipt(material)
            self.assertEqual(
                receipt.received.recomputed_sha256,
                hashlib.sha256(material).hexdigest(),
            )
            self.assertEqual(receipt.received.octet_length, len(material))

    def test_empty_octets_are_a_valid_observation(self):
        receipt = build_receipt(b"")
        self.assertEqual(receipt.received.octet_length, 0)
        self.assertEqual(receipt.received.raw_octets, b"")
        self.assertTrue(all(item.passed for item in validate_receipt(receipt)))

    def test_bytearray_and_memoryview_are_normalized_to_bytes(self):
        for material in (bytearray(SYNTHETIC_OCTETS), memoryview(SYNTHETIC_OCTETS)):
            receipt = build_receipt(material)
            self.assertIsInstance(receipt.received.raw_octets, bytes)
            self.assertEqual(receipt.received.raw_octets, SYNTHETIC_OCTETS)

    def test_text_input_is_rejected(self):
        with self.assertRaises(ReceiptConstructionError):
            build_receipt("BC-02.2 synthetic construction material")

    def test_hex_text_is_rejected_as_digest_input(self):
        with self.assertRaises(ReceiptConstructionError):
            build_receipt(SYNTHETIC_OCTETS.hex())

    def test_base64_text_is_rejected_as_digest_input(self):
        with self.assertRaises(ReceiptConstructionError):
            build_receipt(base64.b64encode(SYNTHETIC_OCTETS).decode("ascii"))

    def test_receive_exposes_no_digest_parameter(self):
        self.assertFalse(BoundaryReceiver.digest_input_is_caller_supplied())

    def test_mutating_the_source_buffer_does_not_alter_the_receipt(self):
        buffer = bytearray(SYNTHETIC_OCTETS)
        receipt = build_receipt(buffer)
        buffer[0] = 0x00
        self.assertEqual(receipt.received.raw_octets, SYNTHETIC_OCTETS)


class ConstructionRobustness(unittest.TestCase):
    def test_invalid_handoff_status_is_rejected(self):
        receiver = build_receiver()
        for bad in ("TRANSFERRED", "PASS", "CONFORMANT", None, 1):
            with self.assertRaises(ReceiptConstructionError):
                receiver.receive(
                    fixture=SYNTHETIC_FIXTURE,
                    method="in-memory-octet-transfer",
                    octets=SYNTHETIC_OCTETS,
                    status=bad,
                )

    def test_missing_handoff_method_is_rejected(self):
        receiver = build_receiver()
        with self.assertRaises(ReceiptConstructionError):
            receiver.receive(
                fixture=SYNTHETIC_FIXTURE, method="", octets=SYNTHETIC_OCTETS
            )

    def test_missing_fixture_identity_is_rejected(self):
        receiver = build_receiver()
        with self.assertRaises(ReceiptConstructionError):
            receiver.receive(
                fixture=None, method="in-memory-octet-transfer", octets=SYNTHETIC_OCTETS
            )

    def test_missing_provenance_is_rejected(self):
        with self.assertRaises(ReceiptConstructionError):
            BoundaryReceiver(receiver=None, adapter=None, environment=None)

    def test_malformed_receipt_fails_the_matching_assertion(self):
        good = build_receipt()
        tampered = BoundaryReceipt(
            fixture=good.fixture,
            handoff=good.handoff,
            received=ReceivedMaterial(
                octet_length=999,
                raw_octets=good.received.raw_octets,
                recomputed_sha256="0" * 64,
            ),
            receiver=good.receiver,
            adapter=good.adapter,
            environment=good.environment,
        )
        self.assertFalse(outcome(tampered, "R-VAL-004").passed)
        self.assertFalse(outcome(tampered, "R-VAL-005").passed)
        self.assertTrue(outcome(tampered, "R-VAL-001").passed)

    def test_reconstructed_raw_material_fails_r_val_010(self):
        good = build_receipt()
        reconstructed = BoundaryReceipt(
            fixture=good.fixture,
            handoff=good.handoff,
            received=ReceivedMaterial(
                octet_length=good.received.octet_length,
                # A textual rendering standing in for the octets is exactly the
                # substitution R-VAL-010 exists to catch.
                raw_octets=base64.b64encode(good.received.raw_octets).decode("ascii"),
                recomputed_sha256=good.received.recomputed_sha256,
            ),
            receiver=good.receiver,
            adapter=good.adapter,
            environment=good.environment,
        )
        self.assertFalse(outcome(reconstructed, "R-VAL-010").passed)

    def test_aliased_adapter_identity_fails_r_val_008(self):
        aliased = BoundaryReceiver(
            receiver=ReceiverIdentity(
                receiver_id="RI-PY",
                implementation_id="aura-ri-py",
                implementation_version="1.0.0",
                source_commit="construction-test",
            ),
            adapter=AdapterIdentity(adapter_id="aura-ri-py", adapter_version="1.0.0"),
            environment=EnvironmentIdentity(
                environment_id="e", platform="p", runtime="r"
            ),
        ).receive(
            fixture=SYNTHETIC_FIXTURE,
            method="in-memory-octet-transfer",
            octets=SYNTHETIC_OCTETS,
        )
        self.assertFalse(outcome(aliased, "R-VAL-008").passed)

    def test_forbidden_handoff_value_fails_r_val_003(self):
        good = build_receipt()
        forbidden = BoundaryReceipt(
            fixture=good.fixture,
            handoff=Handoff(status="PASS", method="in-memory-octet-transfer"),
            received=good.received,
            receiver=good.receiver,
            adapter=good.adapter,
            environment=good.environment,
        )
        self.assertFalse(outcome(forbidden, "R-VAL-003").passed)

    def test_construction_artifacts_contain_no_p01_material(self):
        """The tokens below are a denylist, not construction material."""
        denied = (b"FIX-DIGEST-P01", b"ecf9e98e", b'{"a":1')
        for module in (ri_py_receiver, ri_py_adapter):
            with open(module.__file__, "rb") as handle:
                source = handle.read()
            for token in denied:
                self.assertNotIn(token, source, module.__name__)

    def test_construction_material_is_synthetic(self):
        # Distinct in length and encoding from any issued JSON artifact.
        self.assertNotEqual(len(SYNTHETIC_OCTETS), 15)
        with self.assertRaises(UnicodeDecodeError):
            SYNTHETIC_OCTETS.decode("utf-8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
