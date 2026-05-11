# Branch Strategy

This document describes the current Cashel branch policy so new work starts from the right base, integration happens in the right place, and stale historical branches do not create confusion.

## Active Branches

| Branch | Role |
|---|---|
| `main` | Protected source-of-truth and release branch. It represents production-ready state. |
| `staging` | Integration branch for Codex work and pre-release validation. It should not lag `main` long-term. |

Codex work should target `staging` by default. Feature and docs branches should branch from `staging` unless a task explicitly names another base branch.

Do not push directly to `main` for normal feature, docs, test, or cleanup work. `main` should only be updated after `staging` validation or when the user explicitly instructs that a change should go directly to `main`.

## Historical Branches

The following branches are stale historical branches:

- `codex-based`
- `codex/staging-ci-hardening`

Do not use stale historical branches for new work. They may contain useful prior context, but current product, docs, and release work should be based on `staging` unless explicitly directed otherwise.

## Cleanup Policy

Stale branch deletion or archival should be manual and explicit. Do not delete local or remote branches as part of routine feature, docs, or maintenance work unless the task specifically requests it.
