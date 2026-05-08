# Performance and Scaling

Cashel is currently optimized for self-hosted engineering workflows and small team/MSP deployments. It is not yet designed as a horizontally scaled SaaS control plane.

## Heavy Operations

### PDF Generation

PDF generation starts Chromium through Playwright. This can be CPU and memory heavy.

Mitigations:

- Set `CASHEL_PDF_TIMEOUT_MS`.
- Limit concurrent PDF generation.
- Prefer JSON/CSV/SARIF for automation.
- Keep report retention bounded.
- Run image rebuilds regularly so Chromium dependencies stay patched.

### Bulk Audits

Bulk audits currently run in request/response flow.

Mitigations:

- Enforce max upload size.
- Limit number of files per request.
- Keep reverse proxy timeouts aligned with expected audit duration.
- Move large bulk jobs to a background queue in future work.

### Scope-Aware Shadow Analysis

Future scope-aware analysis can become expensive with nested object groups, service groups, CIDRs, zones, and NAT context.

Mitigations:

- Cache object and service expansion.
- Memoize nested group resolution.
- Avoid naive unbounded `O(n^2)` pairwise comparisons where indexed or ordered approaches are possible.
- Apply depth limits and cycle detection for nested groups.
- Emit partial-analysis warnings rather than timing out silently.

## SQLite

SQLite is acceptable for lightweight self-hosted deployments. It has write-concurrency limits.

Mitigations:

- Keep worker count low.
- Avoid long write transactions.
- Back up regularly.
- Consider future database abstraction before high-concurrency deployments.

## Scheduler

Scheduled SSH audits need explicit concurrency controls.

Risks:

- Long-running SSH commands block schedules.
- Device outages can create retry storms.
- Multi-worker deployments can duplicate scheduler runs.

Mitigations:

- Set SSH timeouts.
- Limit scheduled audit concurrency.
- Use retries with backoff.
- Run one scheduler process.
- Add leader election or locking before multi-worker scheduler deployments.

## Recommended Starting Values

| Control | Recommendation |
|---|---|
| Max upload size | 25 MB per file |
| Audit timeout | 60-120 seconds |
| PDF timeout | 30-60 seconds |
| Scheduled audit concurrency | 1-3 |
| Gunicorn workers | 1 for small hosts |
| Report retention | 30-90 days |
| SQLite backup | Daily for active installs |
| Persistent storage | Required for production |

