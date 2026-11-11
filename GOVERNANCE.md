# MISP project governance

MISP is an open source project developed in public by its users and contributors.
This document describes how the MISP core repository is maintained, how project
decisions are made, and how contributors can take on additional responsibility.
It complements the [contribution guide](CONTRIBUTING.md), the
[GitHub workflow](GITWORKFLOW.md), the [roadmap](ROADMAP.md), and the
[funding and sustainability statement](FUNDING.md).

## Scope

This governance model applies to the MISP core repository. Other repositories in
the [MISP GitHub organisation](https://github.com/MISP) may have their own
maintainers and contribution requirements. Cross-project decisions should be
discussed in the repository most directly affected and linked from the other
affected repositories.

## Roles and responsibilities

Participation is open, and a person may move between these roles over time:

- **Users** deploy MISP, report problems, request features, and help validate
  proposed changes.
- **Contributors** improve code, tests, documentation, translations, design, or
  community support. A merged pull request is not required to participate in
  project discussions.
- **Reviewers** are trusted contributors who regularly triage issues or review
  changes in areas where they have demonstrated knowledge. They help maintainers
  assess a change but do not need repository write access.
- **Maintainers** have write or administrative access to the repository. They are
  responsible for reviews, merges, releases, security coordination, repository
  settings, and upholding the Code of Conduct. Maintainers are listed through the
  repository's current GitHub access controls; the project's lead developer is
  identified in [AUTHORS](AUTHORS).

Repository privileges are granted for project work, not as a mark of seniority.
Everyone participating in the project must follow the
[Code of Conduct](code_of_conduct.md).

## CLA-free contribution model

MISP follows the [CLA-free principles described by
OSSBase](https://ossbase.org/initiatives/cla-free/). Contributors are not asked
to sign a Contributor License Agreement (CLA) or to assign their copyright to a
project steward or private company. Each contribution remains copyrighted by
its author and is accepted under the repository's
[GNU Affero General Public License version 3](LICENSE).

Contributors therefore become co-authors of the collective MISP codebase while
retaining ownership of their own contributions. This distributed copyright
ownership, together with the AGPL-3.0 license, is a deliberate long-term
safeguard: no single private company or project participant can unilaterally
take ownership of all community code or relicense those contributions as
proprietary software. Contributions must be original work, or submitted with
the necessary rights, so that MISP and its derived works can remain open source.

Submitting a contribution indicates agreement to publish that contribution
under AGPL-3.0; it does not transfer its copyright. Project acknowledgements are
maintained in [AUTHORS](AUTHORS) and in the Git history, which is the
authoritative record of individual contributions.

## Becoming a reviewer or maintainer

There is no fixed contribution count. Existing maintainers consider a
contributor's sustained, constructive participation; sound technical judgement;
quality and consistency of reviews or contributions; ability to collaborate;
and understanding of the affected part of MISP.

A contributor may express interest in greater responsibility in a public issue,
or a maintainer may nominate them. Existing maintainers discuss the nomination,
consider feedback from the relevant contributors, and seek consensus. A
maintainer records the outcome in the issue. Access is then granted at the
minimum level needed for the role and may be expanded as responsibilities grow.

A reviewer or maintainer may step down at any time. Maintainers may revoke
inactive access as a security precaution, or revoke access after a Code of
Conduct or security breach. Except where privacy or security requires a
confidential process, the reason is communicated to the affected person and
project community. Returning contributors may ask for access to be restored.

## Decision-making

Project decisions should be made transparently and as close as possible to the
work:

1. Start an issue for a significant feature, architectural change, compatibility
   break, governance change, or roadmap proposal. Straightforward fixes may go
   directly to a pull request.
2. Explain the user need, alternatives, compatibility and security effects, and
   which MISP components are affected.
3. Invite the affected users and contributors to comment. Maintainers seek
   consensus, meaning that material objections have been addressed even when the
   final solution is not every participant's first choice.
4. A maintainer summarizes the decision and rationale in the issue or pull
   request before merging or closing it.

Routine and reversible changes may be accepted by a maintainer after the normal
review and automated checks. Maintainers may merge urgent security or release
fixes on an accelerated timeline; confidential vulnerabilities follow the
[security policy](SECURITY.md), with public rationale provided when disclosure
is safe.

When consensus cannot be reached, the lead developer makes the final decision
after considering the discussion, project mission, user impact, maintenance
cost, security, and compatibility. The decision and rationale are recorded
publicly. Participants may ask for reconsideration by providing new technical or
user-impact information in the same discussion.

Maintainers disclose relevant personal or organisational conflicts of interest
and abstain when those conflicts could reasonably affect a decision. Another
maintainer handles the review or decision in that case.

## Planning, changes, and releases

The public [roadmap](ROADMAP.md) communicates project direction and is informed
by MISP user communities. GitHub issues and milestones track concrete work.
Priorities may change in response to security issues, regressions, contributor
capacity, or community needs.

Changes are proposed and reviewed through pull requests according to the
[GitHub workflow](GITWORKFLOW.md). Maintainers evaluate correctness, tests,
security, backward compatibility, documentation, and alignment with the project
roadmap. Releases and compatibility-relevant changes are communicated through
repository releases and the changelog.

## Funding and independence

MISP is sustained through multiple complementary funding streams rather than
being dependent on a single private sponsor. These include CIRCL's national
funding, European Union project co-funding, international co-funding, and
private-sector partnerships, including [MISP Professional
Services](https://www.misp-project.org/professional-services/). The funding model
and the safeguards that keep financial support separate from ownership of the
community codebase are documented in the
[funding and sustainability statement](FUNDING.md).

## Governance changes

Changes to this document use the same public proposal process as other
significant project decisions. A proposal should explain the governance problem
being addressed and allow reasonable time for community feedback. The deciding
maintainer records the outcome and rationale in the associated issue or pull
request.

Questions about this governance model may be raised in a
[GitHub discussion](https://github.com/MISP/MISP/discussions) or issue. Report
security vulnerabilities through the private channel in the
[security policy](SECURITY.md), not through a public governance discussion.
