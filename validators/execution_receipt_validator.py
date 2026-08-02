"""Schema and chain validation for RACS execution receipts v0.3.

JSON Schema validates one receipt. Replay and duplicate claims additionally
require an ordered receipt set so references, hashes and idempotency lineage can
be checked without treating an external proof as authority.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import jsonschema

from reference.python.racs_canonical import sha256_digest


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "spec"
    / "execution-receipt-v0.3.schema.json"
)
_VALIDATOR = jsonschema.Draft202012Validator(
    json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")),
    format_checker=jsonschema.FormatChecker(),
)


def validate_execution_receipt_chain(
    receipts: Iterable[dict[str, Any]],
) -> list[str]:
    """Return deterministic errors for an ordered v0.3 receipt chain."""

    errors: list[str] = []
    seen: dict[str, tuple[str, dict[str, Any]]] = {}
    previous_digest: str | None = None

    for index, receipt in enumerate(receipts):
        prefix = f"receipts[{index}]"
        for error in sorted(_VALIDATOR.iter_errors(receipt), key=str):
            path = ".".join(str(part) for part in error.absolute_path)
            location = f"{prefix}.{path}" if path else prefix
            errors.append(f"{location}: {error.message}")

        receipt_id = receipt.get("execution_receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            continue
        if receipt_id in seen:
            errors.append(f"{prefix}: duplicate execution_receipt_id {receipt_id!r}")

        current_digest = sha256_digest(receipt)
        if (
            previous_digest is not None
            and receipt.get("previous_receipt_hash") != previous_digest
        ):
            errors.append(
                f"{prefix}.previous_receipt_hash: does not bind the immediately "
                "preceding receipt"
            )

        extension = receipt.get("receipt_ext")
        if isinstance(extension, dict) and extension.get("replay_status") in {
            "REPLAY",
            "DUPLICATE",
        }:
            target_id = extension.get("duplicate_of_receipt_id")
            target_hash = extension.get("duplicate_of_receipt_hash")
            if target_id == receipt_id:
                errors.append(
                    f"{prefix}.receipt_ext.duplicate_of_receipt_id: cannot self-reference"
                )
            target = seen.get(target_id) if isinstance(target_id, str) else None
            if target is None:
                errors.append(
                    f"{prefix}.receipt_ext.duplicate_of_receipt_id: must reference "
                    "an earlier receipt in the supplied chain"
                )
            else:
                expected_hash, target_receipt = target
                if target_hash != expected_hash:
                    errors.append(
                        f"{prefix}.receipt_ext.duplicate_of_receipt_hash: does not "
                        "match the referenced receipt"
                    )
                target_extension = target_receipt.get("receipt_ext")
                target_token = (
                    target_extension.get("idempotency_token")
                    if isinstance(target_extension, dict)
                    else None
                )
                if extension.get("idempotency_token") != target_token:
                    errors.append(
                        f"{prefix}.receipt_ext.idempotency_token: does not match "
                        "the referenced execution lineage"
                    )

        seen[receipt_id] = (current_digest, receipt)
        previous_digest = current_digest

    return errors


__all__ = ["validate_execution_receipt_chain"]
