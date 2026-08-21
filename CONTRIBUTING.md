# Contributing to RACS

All contributions must preserve a defensible intellectual-property trail.

## Branch and push discipline

- One issue = one branch = one PR, targeting `main` (see `AGENTS.md`).
- Avoid pushing directly to `main` from a feature branch. A pre-push guard is
  provided at `scripts/pre-push-protect-main.sh` (install per-clone with
  `ln -sf ../../scripts/pre-push-protect-main.sh .git/hooks/pre-push`).

## Contributor declaration

By submitting a contribution, the contributor confirms that:

- the contribution is original or properly licensed
- they have the right to submit it
- all external sources are disclosed
- no confidential or restricted material is included
- no material is copied from the archived `nsolland/ACS` repository
- no unresolved collaboration material is presented as independently owned RACS work

## Required pull-request information

Each substantive pull request must state:

- purpose
- author
- originating requirement
- external references
- copied or adapted material, if any
- applicable licenses
- affected normative objects
- whether `docs/ip/ORIGIN_REGISTER.md` requires an update

## Contribution classification

Use one of:

- `author_owned`
- `contributor_original`
- `third_party_adapted`
- `joint_historical`
- `unresolved`

`author_owned` means material owned by the repository's documented current rights holder. It does not use `VALO` as the name of a separate legal owner.

`unresolved` material cannot enter the normative specification.

## Clean-room restrictions

Do not use the archived ACS repository as a drafting source.

When interoperability requires reference to another standard:

1. cite the standard
2. describe the compatibility requirement independently
3. avoid copying expressive text or schema structure unless the license clearly permits it
4. record the dependency in `THIRD_PARTY_NOTICES.md`

## Review requirements

Normative changes require review for:

- architecture consistency
- schema compatibility
- security impact
- provenance
- licensing
- naming conflicts

## Attribution

Do not remove author names or provenance from jointly authored or third-party material. Corrections must add clarification, not rewrite history.