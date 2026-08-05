# VALO Agent Verification Governance — Gemini adapter

Canonical policy: `nsolland/Index/governance/agent-verification-governance.md`

- Policy: `VALO-AVG-1`
- Version: `1.1.0`
- Normative body SHA-256: `9d994600fca66b60116460789e3e137edabcbda1cdc7301666f99ad23e092f66`

This file is a tool adapter, not an independent policy or authority source. Read the repository `AGENTS.md` chain and the canonical policy before mapping, implementation, review, delivery receipts, or merge-readiness claims.

Required boundaries:

- No producing agent may independently attest its own delivery.
- Remote GitHub state controls branch, SHA, diff, PR, merge, and hosted-check claims.
- Missing external evidence is `UNVERIFIED`.
- Historical tests are not current green.
- Local environment failures are not repository failures.
- `ACTIVE_BLOCKER` requires a named, current, reproducible blocked delivery.
- Speider collects; BARO observes; VAIG evaluates; REHT clears.
- RACS expresses the deterministic decision contract and receipt schema.
- The gateway or execution boundary enforces the cleared contract and performs side effects.
- Veritas records and verifies the actual outcome.
- Runtime, evidence, evaluation, clearance, and RACS cannot create execution authority outside their defined roles.

This adapter MUST NOT override the canonical policy or repository-local `AGENTS.md` files.
