# AgentBound Delta Benchmark

Deterministic offline benchmark for the RACS AgentBound adoption delta.

It measures governance decision accuracy, violation escape rate, hard-gate false allows, false step-up rate, receipt verification, replay equivalence, policy invalidation, contract-drift detection and verifier latency.

The runner imports the canonical reference implementation from `reference/governance_os`. It does not modify production logic and excludes network or transport time.

Run:

```bash
python benchmarks/agentbound_delta/benchmark.py --check \
  --output benchmarks/agentbound_delta/results.json
python -m unittest -v benchmarks/agentbound_delta/test_benchmark.py
```

Acceptance requires:

- zero escaped violations in deterministic prohibited-action scenarios;
- zero hard-gate false allows;
- 100% receipt verification for untampered bundles;
- 100% replay equivalence for valid bundles;
- every ablation identifies a concrete lost invariant;
- machine-readable results with p50, p95 and p99 offline verification latency.

The ablation model is intentionally explicit. It does not pretend to execute weakened production code. Each ablation links one removed control to the prohibited action or evidence guarantee that becomes possible to lose.
