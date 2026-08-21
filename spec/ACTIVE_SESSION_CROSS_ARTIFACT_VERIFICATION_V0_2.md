# Active-Session Cross-Artifact Verification Rules (P0.2, issue #143)

Status: NORMATIVE.

Defines verification rules for artifacts that belong to the same active
governed execution session (`governed-execution-session-v0.2.schema.json`).
Cross-artifact verification makes a session tamper-evident: every artifact in
the session binds to the same session root, so mixed artifacts from different
sessions (or replayed from an older session) are rejected.

## Rules (S1–S5)

1. **S1 — session root binding.** Every session artifact carries
   `session_id` and a `session_digest` over the canonical session root.
   Artifacts with a different `session_id` MUST NOT be combined.
2. **S2 — chain-of-custody.** Each artifact in a session references its
   predecessor by `previous_artifact_digest` (hash-chained within the session).
   A gap or mismatch fails verification.
3. **S3 — trace length.** Heart/antenna-style synchronized channels are
   session-level: the number of transitions and the channel traces must agree
   across artifacts. Mismatched lengths fail verification.
4. **S4 — authority and clearance continuity.** Every transition in a session
   is backed by the same clearance lineage (same tenant, purpose, policy
   version). A transition whose clearance binds to another tenant/purpose is a
   cross-session splice and MUST be rejected.
5. **S5 — fail closed on ambiguity.** If any cross-artifact verification cannot
   be completed (missing predecessor, unknown session, absent digest), the
   session state is treated as indeterminate and execution does not continue.

## Verification order

1. Verify each artifact signature.
2. Verify session root binding (S1).
3. Verify chain-of-custody digests (S2).
4. Verify channel/trace synchronization (S3).
5. Verify authority/clearance continuity (S4).
6. Only then evaluate the current transition.

## Conformance

A conforming enforcement kernel MUST refuse to continue a session when any of
S1–S4 fails, and MUST record the failed verification as a runtime observation.