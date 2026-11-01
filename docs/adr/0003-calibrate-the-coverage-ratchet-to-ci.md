# 3. Calibrate the coverage ratchet to CI, not to a local run

Date: 2026-08-26

## Status

Accepted

## Context

The coverage floor was first set from a local measurement of 24.83 % union. Continuous integration measured 20.18 % for the same commit, because PyMISP's live suite does not complete on a clean runner and so contributes less coverage there.

The gate consequently failed on a correct commit. Worse, an earlier run had passed while measuring nothing at all: the report was piped into `tee`, so the pipeline returned `tee`'s exit status and the ratchet was inert.

## Decision

The floor is a number the CI environment can itself reproduce, recorded alongside the local figure and the reason they differ. Both numbers are kept in the workflow, because the divergence is information, not noise.

The gate's exit status must be observable: the report is not piped, and its failure is captured explicitly rather than allowed to be swallowed.

## Consequences

The gate is meaningful, and a red build indicates a real regression rather than an environment difference.

The floor understates what the suites achieve on a fully provisioned instance. That is the correct trade: a floor CI cannot reach is a permanently red gate, which teams learn to ignore.

The divergence is itself worth watching. CI reaching *more* than local in a subsystem — `Lib/Dashboard` is higher in CI — usually means a local run had polluted state, so the two numbers together diagnose the harness.

A gate that cannot fail is worse than no gate, because it is mistaken for assurance. Any future check added here must be verified to fail before it is trusted to pass.
