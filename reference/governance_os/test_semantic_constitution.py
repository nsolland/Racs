from semantic_constitution import (
    HumanRatification,
    PurposeStatement,
    SemanticConstitutionLedger,
    SemanticExpression,
    SourceSpan,
    TransformationRecord,
    validate_board_intent_semantics,
)


def fixture():
    original = SemanticExpression(
        "expr-1",
        "Vi skal støtte innbyggere uten å overvåke dem.",
        "nb-NO",
        source_spans=(SourceSpan("board-minutes", 0, 47, "Vi skal støtte innbyggere uten å overvåke dem."),),
        ambiguities=("støtte",),
        dissent=("Mindretallet ba om eksplisitt reservasjon mot profilering.",),
    )
    purpose = PurposeStatement(
        "purpose-1",
        "foundation-1",
        original,
        frozenset({"assist", "inform"}),
        frozenset({"surveil", "profile"}),
    )
    return original, purpose


def test_original_language_ambiguity_and_dissent_remain_retrievable():
    original, purpose = fixture()
    ledger = SemanticConstitutionLedger()
    chain = ledger.provenance_chain(purpose)
    assert chain["original_expression"]["original_text"] == original.original_text
    assert chain["original_expression"]["language"] == "nb-NO"
    assert chain["original_expression"]["ambiguities"] == ("støtte",)
    assert chain["original_expression"]["dissent"]


def test_ai_purpose_widening_fails_closed():
    original, purpose = fixture()
    output = SemanticExpression("expr-2", "Support through profiling.", "en")
    record = TransformationRecord(
        "tx-1", original.digest, output, "model-1", "ai", "translate", "1", True,
        frozenset({"assist", "profile"}),
    )
    ledger = SemanticConstitutionLedger()
    try:
        ledger.append_transformation(purpose, record)
        assert False, "expected purpose widening failure"
    except ValueError as exc:
        assert str(exc) == "PURPOSE_WIDENING_FORBIDDEN"


def test_ai_transformation_is_non_authoritative_without_ratification():
    original, purpose = fixture()
    output = SemanticExpression("expr-2", "Support residents without surveillance.", "en")
    record = TransformationRecord(
        "tx-1", original.digest, output, "model-1", "ai", "translate", "1", True,
        frozenset({"assist"}),
    )
    ledger = SemanticConstitutionLedger()
    digest = ledger.append_transformation(purpose, record)
    result = validate_board_intent_semantics(purpose, {"assist"}, output, digest, ledger)
    assert result == "STEP_UP_UNRATIFIED_TRANSFORMATION"
    assert ledger.authoritative_expression(purpose) == original


def test_authorized_human_ratification_creates_new_authoritative_version():
    original, purpose = fixture()
    output = SemanticExpression("expr-2", "Support residents without surveillance.", "en")
    record = TransformationRecord(
        "tx-1", original.digest, output, "model-1", "ai", "translate", "1", True,
        frozenset({"assist"}),
    )
    ledger = SemanticConstitutionLedger()
    digest = ledger.append_transformation(purpose, record)
    ledger.ratify(HumanRatification("rat-1", digest, "board-chair", "mandate:board", "RATIFY", "1"))
    assert validate_board_intent_semantics(purpose, {"assist"}, output, digest, ledger) == "ALLOW_SEMANTICALLY_BOUND"
    assert ledger.authoritative_expression(purpose) == output


def test_provenance_mismatch_denied():
    original, purpose = fixture()
    output = SemanticExpression("expr-2", "Support residents without surveillance.", "en")
    other = SemanticExpression("expr-3", "Different text.", "en")
    record = TransformationRecord(
        "tx-1", original.digest, output, "human-1", "human", "clarify", "1", True,
        frozenset({"assist"}),
    )
    ledger = SemanticConstitutionLedger()
    digest = ledger.append_transformation(purpose, record)
    ledger.ratify(HumanRatification("rat-1", digest, "board-chair", "mandate:board", "RATIFY", "1"))
    assert validate_board_intent_semantics(purpose, {"assist"}, other, digest, ledger) == "DENY_PROVENANCE_MISMATCH"
