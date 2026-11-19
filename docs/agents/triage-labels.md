# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps them to the label strings on `zeroae/countersign`.

| Canonical role    | Label in our tracker     | Meaning                                  |
| ----------------- | ------------------------ | ---------------------------------------- |
| `needs-triage`    | `triage:needs-triage`    | Maintainer needs to evaluate this issue  |
| `needs-info`      | `triage:needs-info`      | Waiting on reporter for more information |
| `ready-for-agent` | `triage:ready-for-agent` | Fully specified, ready for an AFK agent  |
| `ready-for-human` | `triage:ready-for-human` | Requires human implementation            |
| `wontfix`         | `triage:wontfix`         | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

The category is the issue type, not a label: a broken behaviour is type Bug, a new feature or improvement type Task, upkeep type Chore. An issue of type Feature is a spec and one of type Epic an epic's overview.

Countersign carries only the process labels: the `triage:` family above, `origin:` (`review`, `retro`, `site`, `alarm`), `wayfinder:` (`map`, `research`, `grilling`, `prototype`, `task`) and the bare `security`. It does not take the foresight repository's `area:`, `deploy:`, `migration:` or `flag:` labels. `docs/agents/issue-tracker.md`, "Labels", says how they reach GitHub.
