# 2. Pin known defects in golden snapshots

Date: 2026-08-26

## Status

Accepted

## Context

Characterization tests protect refactoring by recording what the code does today. Applied naively to MISP, they would record behaviour that is known to be wrong: `returnFormat=text` returns no values where `json`, `csv` and `netfilter` all return them, and `workflows/checkGraph` answers malformed input with HTTP 500.

Recording those as the expected contract makes a future *fix* fail the suite, which teaches developers that a red build means "you fixed something". Excluding them instead leaves exactly the endpoints most likely to be touched unprotected during a refactor.

## Decision

Record the real current output, and annotate the snapshot `KNOWN-DEFECT` with a cross-reference to a specification test that asserts the desired behaviour and is skipped while the defect stands.

## Consequences

Refactors remain protected across defective endpoints, because the snapshot still detects unintended change.

Fixing a defect produces exactly one expected snapshot diff plus one test flipping from skipped to passing. That pairing is the signal a reviewer looks for; a snapshot diff *without* it means the fix was accidental.

The cost is that a snapshot no longer means "this is right", only "this is what happens". Anyone reading snapshots for documentation must check the annotation, which is why `KNOWN-DEFECT` is defined in the glossary rather than left as a comment convention.

The alternative — fix the defects first, then snapshot — was rejected only for sequencing: it blocks the refactoring safety net behind unrelated bug-fix work.
