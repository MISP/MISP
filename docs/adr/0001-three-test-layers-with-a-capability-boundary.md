# 1. Three test layers with a capability boundary

Date: 2026-08-26

## Status

Accepted

## Context

MISP's tests were split by accident rather than design: 19 bare-PHPUnit files with no database, and a Python suite driving a fully deployed instance over HTTP. Nothing said which kind of test a new behaviour belonged in, and the two suites' coverage could not be compared because nothing measured them against a common denominator.

Measurement showed the consequence. The Python suite covered ten times what the PHPUnit suite did, yet `Lib/Dashboard` and `Model/WorkflowModules` were at 0.00 % in *both* — each suite assumed the other covered them.

## Decision

Three layers, distinguished by *capability* rather than by taste:

- **Layer 1 (unit)** — no database, Redis, HTTP or network.
- **Layer 2 (integration)** — database and real models, but no HTTP.
- **Layer 3 (live)** — the deployed system over HTTP.

A behaviour is tested in the **highest-numbered layer that can assert it, and no higher**.

Layers 1 and 2 cannot share a process: Layer 1 supplies stub framework classes, Layer 2 loads the real CakePHP ones. They therefore have separate bootstraps and separate PHPUnit configurations.

## Consequences

The rule is decidable without judgement, so a new test's home is not a debate. It also forces an uncomfortable answer occasionally: `View/Helper` looks like Layer 1 but its collaborators are injected by the framework, so a Layer 1 test of `NavbarHelper` executed 60 of its 886 statements. The rule says move it to Layer 2 rather than keep a test that runs but proves little.

The split bootstrap is real overhead — two config files, two invocations, and a `-c` flag that is easy to forget. Forgetting it is not subtle: the suite fails immediately with `Undefined constant "APP"`.

Some duplication between layers is accepted. An export format is Layer 1, but Layer 3 still asks the API to deliver it, because "the format is correct" and "the API can deliver it" are different claims.
