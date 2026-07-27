"""Deterministic semantic constitution reference for GOS-001A.

Preserves original expression, source spans, ambiguity, dissent and transformation
history. AI transformations are proposals only until authorized human ratification.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from hashlib import sha256
import json
from typing import Iterable, Literal


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceSpan:
    source_id: str
    start: int
    end: int
    quote: str

    def validate(self) -> None:
        if not self.source_id or self.start < 0 or self.end <= self.start or not self.quote:
            raise ValueError("INVALID_SOURCE_SPAN")


@dataclass(frozen=True)
class SemanticExpression:
    expression_id: str
    original_text: str
    language: str
    dialect: str | None = None
    source_spans: tuple[SourceSpan, ...] = ()
    ambiguities: tuple[str, ...] = ()
    dissent: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.expression_id or not self.original_text or not self.language:
            raise ValueError("MISSING_ORIGINAL_EXPRESSION")
        for span in self.source_spans:
            span.validate()

    @property
    def digest(self) -> str:
        self.validate()
        return canonical_digest(asdict(self))


@dataclass(frozen=True)
class ValueFoundation:
    foundation_id: str
    expression: SemanticExpression
    version: str

    def validate(self) -> None:
        if not self.foundation_id or not self.version:
            raise ValueError("INVALID_VALUE_FOUNDATION")
        self.expression.validate()


@dataclass(frozen=True)
class PurposeStatement:
    purpose_id: str
    foundation_id: str
    expression: SemanticExpression
    allowed_objectives: frozenset[str]
    prohibited_objectives: frozenset[str] = frozenset()
    version: str = "1"

    def validate(self) -> None:
        if not self.purpose_id or not self.foundation_id or not self.allowed_objectives:
            raise ValueError("INVALID_PURPOSE")
        if self.allowed_objectives & self.prohibited_objectives:
            raise ValueError("PURPOSE_CONTRADICTION")
        self.expression.validate()


@dataclass(frozen=True)
class TransformationRecord:
    transformation_id: str
    parent_digest: str
    output: SemanticExpression
    actor_id: str
    actor_type: Literal["human", "ai", "system"]
    method: str
    version: str
    preserves_meaning: bool
    proposed_objectives: frozenset[str]
    ambiguity_notes: tuple[str, ...] = ()

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True)
class HumanRatification:
    ratification_id: str
    transformation_digest: str
    principal_id: str
    authority_ref: str
    decision: Literal["RATIFY", "REJECT"]
    version: str

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass
class SemanticConstitutionLedger:
    records: list[TransformationRecord] = field(default_factory=list)
    ratifications: list[HumanRatification] = field(default_factory=list)

    def append_transformation(self, purpose: PurposeStatement, record: TransformationRecord) -> str:
        purpose.validate()
        record.output.validate()
        if record.parent_digest != purpose.expression.digest and not any(
            existing.digest == record.parent_digest for existing in self.records
        ):
            raise ValueError("UNKNOWN_TRANSFORMATION_PARENT")
        if not record.preserves_meaning:
            raise ValueError("SEMANTIC_INTEGRITY_FAILED")
        if not record.proposed_objectives <= purpose.allowed_objectives:
            raise ValueError("PURPOSE_WIDENING_FORBIDDEN")
        if record.proposed_objectives & purpose.prohibited_objectives:
            raise ValueError("PROHIBITED_OBJECTIVE")
        self.records.append(record)
        return record.digest

    def ratify(self, ratification: HumanRatification) -> str:
        if not ratification.principal_id or not ratification.authority_ref:
            raise ValueError("UNBOUND_HUMAN_AUTHORITY")
        if not any(r.digest == ratification.transformation_digest for r in self.records):
            raise ValueError("UNKNOWN_TRANSFORMATION")
        self.ratifications.append(ratification)
        return ratification.digest

    def authoritative_expression(self, purpose: PurposeStatement) -> SemanticExpression:
        approved = {
            r.transformation_digest
            for r in self.ratifications
            if r.decision == "RATIFY"
        }
        for record in reversed(self.records):
            if record.digest in approved:
                return record.output
        return purpose.expression

    def provenance_chain(self, purpose: PurposeStatement) -> dict[str, object]:
        return {
            "purpose_id": purpose.purpose_id,
            "original_expression": asdict(purpose.expression),
            "transformations": [asdict(r) | {"digest": r.digest} for r in self.records],
            "ratifications": [asdict(r) | {"digest": r.digest} for r in self.ratifications],
            "authoritative_expression_digest": self.authoritative_expression(purpose).digest,
        }


def validate_board_intent_semantics(
    purpose: PurposeStatement,
    requested_objectives: Iterable[str],
    expression: SemanticExpression,
    ratified_transformation_digest: str | None,
    ledger: SemanticConstitutionLedger,
) -> str:
    """Fail closed unless intent stays within purpose and transformed text is ratified."""
    purpose.validate()
    expression.validate()
    objectives = frozenset(requested_objectives)
    if not objectives or not objectives <= purpose.allowed_objectives:
        return "DENY_PURPOSE_WIDENING"
    if objectives & purpose.prohibited_objectives:
        return "DENY_PROHIBITED_OBJECTIVE"
    if expression.digest == purpose.expression.digest:
        return "ALLOW_SEMANTICALLY_BOUND"
    ratified = {
        r.transformation_digest
        for r in ledger.ratifications
        if r.decision == "RATIFY"
    }
    if ratified_transformation_digest not in ratified:
        return "STEP_UP_UNRATIFIED_TRANSFORMATION"
    record = next(
        (r for r in ledger.records if r.digest == ratified_transformation_digest),
        None,
    )
    if record is None or record.output.digest != expression.digest:
        return "DENY_PROVENANCE_MISMATCH"
    return "ALLOW_SEMANTICALLY_BOUND"
