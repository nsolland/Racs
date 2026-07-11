# CLAUDE.md — RACS (REHT Action Control Standard)

## What this project is

**RACS** is a neutral, model-agnostic protocol specification for representing, evaluating, authorizing, executing, and evidencing AI-mediated actions. RACS is a **standard, not a runtime implementation.**

Core question answered: **"Is this action admissible to execute under the current authority, policy, evidence and system state?"**

RACS defines the contract between evidence layers (BARO, Speider) and action governance layers (VAIG, REHT, Core).

---

## Tech stack

- **Language:** YAML/JSON (protocol specification)
- **References:** Python (example implementations in `reference/`)
- **Testing:** Compliance validators (check if implementations conform to spec)
- **CI/CD:** GitHub Actions (spec validation, example tests)

---

## Directory structure

```
RACS/
├── CLAUDE.md                   # This file
├── README.md                   # Protocol overview
├── spec/
│   ├── action-envelope.yaml    # Core action message format
│   ├── authority-context.yaml  # Authority representation
│   ├── evidence-package.yaml   # Evidence data format
│   ├── policy-context.yaml     # Policy constraints
│   ├── execution-semantics.yaml # Action execution model
│   └── evidence-semantics.yaml # Evidence validation model
├── examples/
│   ├── energy-grid.yaml        # Energy grid action example
│   ├── financial.yaml          # Financial transaction example
│   └── medical.yaml            # Medical AI example
├── validators/
│   ├── envelope_validator.py   # RACS envelope validator
│   ├── policy_validator.py     # Policy compliance checker
│   └── evidence_validator.py   # Evidence package checker
├── reference/
│   ├── python-implementation/  # Reference Python implementation
│   └── typescript-implementation/ # Reference TypeScript implementation
└── tests/
    └── compliance/             # RACS compliance test suites
```

---

## Core concepts

| Term | Meaning |
|------|---------|
| **Action Envelope** | Structured message representing a single AI-mediated action (who, what, when, why, how) |
| **Authority Context** | Who is authorized to make this decision; delegation chains and policy scope |
| **Evidence Package** | Facts, conditions, and reasoning supporting the action decision |
| **Policy Context** | Constraints, rules, and acceptable risk bounds for this action class |
| **Execution Semantics** | How the action is executed, logged, and reversed if needed |
| **Evidence Semantics** | Rules for what evidence is sufficient, how it's validated, how it expires |

---

## Development commands

```bash
# Validate spec files
python validators/envelope_validator.py spec/action-envelope.yaml

# Run compliance tests
pytest tests/compliance/ -v

# Validate examples against spec
python validators/envelope_validator.py examples/energy-grid.yaml
python validators/envelope_validator.py examples/financial.yaml

# Build reference implementations
cd reference/python-implementation && python -m build
cd ../typescript-implementation && npm install && npm test
```

---

## Key files

| File | Purpose |
|------|---------|
| `spec/action-envelope.yaml` | **Start here.** Action message format (who, what, when, why, context) |
| `spec/authority-context.yaml` | Authority chains and delegation semantics |
| `spec/evidence-package.yaml` | Evidence structure and validation rules |
| `spec/policy-context.yaml` | Policy language for action constraints |
| `spec/execution-semantics.yaml` | Action execution, reversal, and auditability |
| `README.md` | Protocol overview and use cases |
| `examples/*.yaml` | Concrete action examples across domains |

---

## Architecture integration

RACS sits at the center of VALO architecture as the **bridge protocol**:

```
Data Layers          → RACS Protocol        → Action Layers
─────────────────────────────────────────────────────────────
BARO (observ.)       ↓                      → VAIG (evidence eval)
Speider (discov.)    Action Envelope       → REHT (admissibility)
External Facts       Evidence Package      → Core (execution)
                     Policy Context
                     Authority Context
```

- **Producers** (data layers): BARO, Speider, VAIG, external systems
- **Consumers** (action layers): VAIG, REHT, Core authorization engines
- **Validators:** All layers validate incoming RACS messages

---

## Important constraints for AI assistants

- **RACS is neutral.** No domain-specific assumptions; applies to energy, finance, medical, general AI equally
- **RACS is specification-first.** Implementations must conform to spec; do not invent protocol variants
- **No hardcoding policy.** Policy is data in `policy-context`; never bake policy into code
- **Evidence is immutable in transmission.** Evidence packages are signed; never modify during transmission
- **Authority chains are explicit.** Delegation must be traceable; no implicit authority
- **Specification is the source of truth.** Spec files are the contract; implementations follow them

---

## Governance

- **Development branch:** `claude/code-audit-all-repos-kvj2go`
- **PR policy:** All spec changes require review; reference implementations must pass compliance tests
- **Backwards compatibility:** Major spec changes require version bump and migration guide
- **External usage:** RACS is public; clarify which parts are stable (spec/) vs. reference (reference/)

---

## Session notes

Created in SESSION#9 (2026-07-11) as part of deep ecosystem audit. This repo was missing CLAUDE.md governance documentation. Identified as critical to VALO architecture as protocol bridge between evidence (BARO/Speider) and action layers (VAIG/REHT/Core).
