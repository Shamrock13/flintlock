# Branch Strategy

This document describes the current Cashel branch policy so new work starts from the right base and stale historical branches do not create confusion.

## Active Branches

| Branch | Role |
|---|---|
| `main` | Current source-of-truth and production-ready branch. |
| `staging` | Integration and pre-release branch. It should not lag `main` long-term. |

Feature branches should branch from `main` unless a task explicitly names another base branch.

## Historical Branches

The following branches are stale historical branches:

- `codex-based`
- `codex/staging-ci-hardening`

Do not use stale historical branches for new work. They may contain useful prior context, but current product, docs, and release work should be based on `main` unless explicitly directed otherwise.

## Cleanup Policy

Stale branch deletion or archival should be manual and explicit. Do not delete local or remote branches as part of routine feature, docs, or maintenance work unless the task specifically requests it.
