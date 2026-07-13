# RACS Implementation — Built Structure

This directory was built to fulfill the structure documented in CLAUDE.md.
Previously a documentation-only skeleton; now contains real spec files,
validators, examples, reference implementation, and compliance tests.

## What was built

| Directory / File | Purpose |
|---|---|
| `spec/*.yaml` (6 files) | YAML specification files for action envelope, authority context, evidence package, policy context, execution semantics, evidence semantics |
| `validators/envelope_validator.py` | CLI validator: `python validators/envelope_validator.py <path>` — validates action envelopes (YAML/JSON) |
| `validators/policy_validator.py` | CLI validator for policy contexts |
| `validators/evidence_validator.py` | CLI validator for evidence packages |
| `examples/*.yaml` (3 files) | Working example action envelopes: energy-grid, financial, medical |
| `reference/python-implementation/` | Reference Python dataclass types for RACS protocol objects |
| `tests/compliance/test_racs_compliance.py` | pytest suite: 32 tests covering valid/invalid envelopes, policy, evidence |
| `pyproject.toml` | Project metadata and test configuration |

## How to validate

```bash
# Validate example envelopes
python validators/envelope_validator.py examples/energy-grid.yaml
python validators/envelope_validator.py examples/financial.yaml
python validators/envelope_validator.py examples/medical.yaml

# Validate spec files
python validators/envelope_validator.py spec/action-envelope.yaml
python validators/policy_validator.py spec/policy-context.yaml
python validators/evidence_validator.py spec/evidence-package.yaml

# Run compliance test suite
pytest tests/compliance/ -v
```

## Constraints followed

- **RACS is a standard, not a runtime.** Validators check structure, not runtime behavior.
- **No hardcoded policy.** Policy lives in `policy_context` data, never in validator logic.
- **Evidence immutable.** Validators check integrity metadata structure, do not modify evidence.
- **Explicit authority.** Authority contexts require delegation chains; no implicit authority.
- **Specification-first.** Spec YAML files are the contract; validators and reference implementations conform to them.
- **Domain neutral.** No domain-specific assumptions — examples show energy, finance, AND healthcare.
- **No threshold values.** C0/α/τ thresholds not applicable here; no cryptographic parameters hardcoded.
