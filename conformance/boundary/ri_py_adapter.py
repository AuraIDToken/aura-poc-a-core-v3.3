"""BC-02.2 - RI-PY boundary adapter v1.

Engineering component that binds host and provenance identity to the RI-PY
receiver and hands it octets. Separate artifact from the receiver, with its own
identity and version, per BC-02.1 section 8.

Authority: NONE. The adapter emits receipts and schema-validation reports. It
cannot emit a conformance_result, PASS, FAIL, CONFORMANT, NON_CONFORMANT, a
CONF-003 section 4.5 result, or a B-VAL-014 result, and it never decides whether
an observation satisfies a protocol requirement.

Scope note: this adapter is a construction artifact. Executing an issued fixture
through it belongs to the later Controlled P-01 Handoff stage, not to BC-02.2.
"""

from __future__ import annotations

import argparse
import platform as platform_mod
import sys
from typing import Optional, Sequence

from conformance.boundary.ri_py_receiver import (
    AdapterIdentity,
    BoundaryReceipt,
    BoundaryReceiver,
    EnvironmentIdentity,
    FixtureIdentity,
    HandoffStatus,
    ReceiverIdentity,
    format_validation_report,
    serialize_receipt,
    validate_receipt,
)

ADAPTER_ID = "BC-02.2-RI-PY-BOUNDARY-ADAPTER"
ADAPTER_VERSION = "1.0.0"

RECEIVER_ID = "RI-PY"
IMPLEMENTATION_ID = "aura-ri-py"
IMPLEMENTATION_VERSION = "1.0.0"

DEFAULT_HANDOFF_METHOD = "local-octet-file-transfer"


def detect_environment(environment_id: Optional[str] = None) -> EnvironmentIdentity:
    """Describe the execution host. Recorded as context, never as a requirement."""
    machine = platform_mod.machine() or "unknown-machine"
    system = platform_mod.system() or "unknown-system"
    release = platform_mod.release() or "unknown-release"
    runtime = "{0} {1}".format(
        platform_mod.python_implementation(), platform_mod.python_version()
    )
    resolved_id = environment_id or "ri-py-{0}-{1}-python-{2}".format(
        system.lower(), machine, platform_mod.python_version()
    )
    return EnvironmentIdentity(
        environment_id=resolved_id,
        platform="{0}-{1}-{2}".format(system, machine, release),
        runtime=runtime,
    )


def build_receiver(
    source_commit: str,
    environment: Optional[EnvironmentIdentity] = None,
    implementation_version: str = IMPLEMENTATION_VERSION,
) -> BoundaryReceiver:
    """Bind receiver, implementation, adapter and environment identity."""
    return BoundaryReceiver(
        receiver=ReceiverIdentity(
            receiver_id=RECEIVER_ID,
            implementation_id=IMPLEMENTATION_ID,
            implementation_version=implementation_version,
            source_commit=source_commit,
        ),
        adapter=AdapterIdentity(adapter_id=ADAPTER_ID, adapter_version=ADAPTER_VERSION),
        environment=environment or detect_environment(),
    )


def receive_octets(
    receiver: BoundaryReceiver,
    fixture_id: str,
    fixture_artifact_identity: str,
    octets: bytes,
    method: str = DEFAULT_HANDOFF_METHOD,
) -> BoundaryReceipt:
    """Hand octets to the receiver. The adapter does not touch the digest path."""
    return receiver.receive(
        fixture=FixtureIdentity(
            fixture_id=fixture_id,
            fixture_artifact_identity=fixture_artifact_identity,
        ),
        method=method,
        octets=octets,
        status=HandoffStatus.TRANSFERRED,
    )


def read_artifact_octets(path: str) -> bytes:
    """Read an artifact as raw octets.

    Opened in binary mode and returned unchanged: not decoded, not parsed, not
    normalized, not re-serialized, no newline added or removed.
    """
    with open(path, "rb") as handle:
        return handle.read()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Hand an artifact's octets to the RI-PY BC-02.1 receiver and emit the "
            "receipt with its R-VAL report. Evidence only; no conformance result."
        )
    )
    parser.add_argument("artifact_path", help="path to the artifact, read as raw octets")
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--fixture-artifact-identity", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--method", default=DEFAULT_HANDOFF_METHOD)
    parser.add_argument("--environment-id", default=None)
    parser.add_argument("--receipt-out", default=None)
    args = parser.parse_args(argv)

    octets = read_artifact_octets(args.artifact_path)
    receiver = build_receiver(
        source_commit=args.source_commit,
        environment=detect_environment(args.environment_id),
    )
    receipt = receive_octets(
        receiver,
        fixture_id=args.fixture_id,
        fixture_artifact_identity=args.fixture_artifact_identity,
        octets=octets,
        method=args.method,
    )

    results = validate_receipt(receipt)
    serialized = serialize_receipt(receipt)

    print("== RI-PY intake ==")
    print("artifact_path : {0}".format(args.artifact_path))
    print("octets_read   : {0}".format(len(octets)))
    print()
    print("== R-VAL-001..012 (schema/receipt validation only) ==")
    print(format_validation_report(results))
    print()
    print("== BC-02.1 receipt (deterministic transport form) ==")
    print(serialized.decode("utf-8"))

    if args.receipt_out:
        with open(args.receipt_out, "wb") as handle:
            handle.write(serialized + b"\n")
        print()
        print("receipt written to: {0}".format(args.receipt_out))

    print()
    print("B-VAL-014 NOT EXECUTED")
    print("CONF-003 section 4.5 NO RESULT")
    print("CONFORMANCE NOT DETERMINED")

    return 0 if all(item.passed for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())
