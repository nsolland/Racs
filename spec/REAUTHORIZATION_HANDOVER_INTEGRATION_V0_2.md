# Reauthorization and Handover Integration Profile (P0.2, issue #144)

Status: NORMATIVE.

Defines the integration profile for **reauthorization** (a REAUTHORIZE
continuity decision) and **handover** (a HANDOVER continuity decision), where
responsibility for a governed session or effect path moves to another
authority/operator without breaking the receipt chain.

## Reauthorization

`REAUTHORIZE` re-binds an ongoing session to a renewed authority/clearance.

Rules (RA1–RA3):

1. **RA1 — continuous binding.** Reauthorization MUST NOT reset the session;
   it extends the same `session_id` and keeps the hash chain (S2).
2. **RA2 — renewal not widening.** The renewed clearance binds the same
   tenant, purpose and policy version as the original; a widening change is a
   `MODIFY_RUNTIME_BOUNDS` and needs the narrowing proof (issue #142).
3. **RA3 — revocation checked.** Before accepting a reauthorization, the
   receiver verifies the original and renewed authorities are not in the
   revocation registry (issue #138).

## Handover

`HANDOVER` transfers the governed effect path to a successor authority.

Rules (HO1–HO4):

1. **HO1 — signed transfer.** Handover is a signed decision artifact binding
   `from_authority`, `to_authority`, `session_id` and the exact handover
   boundary (which effects may continue).
2. **HO2 — no orphaned authority.** The successor MUST NOT gain authority the
   predecessor did not hold (subset rule, N1 applies).
3. **HO3 — dual acknowledgment.** Both parties acknowledge the handover before
   the path moves; a single-sided handover is rejected.
4. **HO4 — continuity of receipts.** Receipts after handover are attributed to
   the successor but remain in the same session chain (S2), so the full effect
   path stays attributable.

## Integration surface

- `continuity-decision-v0.2.schema.json` (`REAUTHORIZE` / `HANDOVER`).
- `revocation-registry-snapshot-v0.2.schema.json` (RA3).
- `active-session cross-artifact verification` rules (S1–S5).