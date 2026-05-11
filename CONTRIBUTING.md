# Contributing

## Branch Workflow

Normal Codex work targets `staging`. Feature, docs, test, and cleanup branches should branch from `staging` unless a task explicitly names another base branch.

Do not push directly to `main` for normal work. `main` is the protected source-of-truth and release branch, and should only be updated after `staging` validation or when the user explicitly instructs a direct update.

Stale historical branches, including `codex-based` and `codex/staging-ci-hardening`, are not for new work.
