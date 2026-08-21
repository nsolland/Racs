# Security policy

RACS defines security-relevant protocol and conformance semantics. Do not disclose suspected vulnerabilities in public issues before a fix is available when they could enable authorization-binding confusion, replay, effect-path bypass, canonicalization/signature ambiguity or receipt-integrity failure.

Use GitHub private vulnerability reporting for this repository when available. Include the affected commit/version, relevant schema/contract, reproduction steps, expected invariant and observed behavior.

RACS is protocol infrastructure. A valid RACS object or signature does not itself create authority or permission to execute.
