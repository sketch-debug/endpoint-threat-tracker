# CI runner image migration — Monday check

Reminder, not a runbook: this file exists to be deleted along with the
`ubuntu-2604-rehearsal` schedule once the pin below moves.

Tracking issue: [#8](https://github.com/sketch-debug/endpoint-threat-tracker/issues/8)
— record the Monday result there, not here; this file is the measured
baseline the issue refers back to.

## State

- `ci.yml` pins `ubuntu-24.04` on the `test` job, so the `ubuntu-latest`
  label migration (24.04 -> 26.04, rolled out Oct 19 - Nov 19 2026,
  [actions/runner-images#14748](https://github.com/actions/runner-images/issues/14748))
  cannot redden the build on its own.
- `.github/workflows/ubuntu-2604-rehearsal.yml` runs the same three gates on
  `ubuntu-26.04`, weekly (Mondays 06:00 UTC) plus manual dispatch.
- **First scheduled run: Monday 2 Nov 2026, 06:00 UTC.** It has not fired as
  of Oct 29; the only execution so far is a manual dispatch.

## What to check after Monday

```bash
gh run list --workflow=ubuntu-2604-rehearsal.yml --limit 3
```

Compare its `test` job against the `CI` run on the **same commit** — comparing
across commits mixes image drift with code drift and proves nothing.

## Baseline, commit `415ca7e` (both green)

| | 24.04 (`40863807690`) | 26.04 (`40863816822`) |
|---|---|---|
| Files / misses | 3407 / 689 | 3407 / 689 |
| Coverage | 79.78% | 79.78% |
| Tests | 303 passed, 1 skipped | 303 passed, 1 skipped |
| Suite time | 86.95s | 70.11s |

"Matching" means the three counts and the coverage figure are unchanged.
Suite time is shared-runner noisy: a few seconds either way is not a signal.

## Then

Record the outcome on issue #8, then:

- **Matches:** move `ci.yml` to `ubuntu-26.04` in its own commit, then delete
  the rehearsal workflow (its schedule becomes duplicate work).
- **Diverges:** leave the pin on 24.04, do not relax a gate to make 26.04
  pass, and record the actual delta here with the run id.
