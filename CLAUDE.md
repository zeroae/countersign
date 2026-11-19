# Countersign

Desktop approval for HTTPS workloads that use an installed client certificate. The Cargo workspace (`crates/`) holds the protocol, PKI validation, Broker, Gateway and native addon. The pnpm workspace holds the Electron Companion and web widget (`packages/`) and the demo Integrator (`examples/`). `docs/develop.md` says how to build, test and release; `docs/specs/2026-11-17-countersign-design.md` is the design record.

## Agent skills

### Plugins

Work here follows the foresight process. The `foresight` plugin is installed once per machine, from the foresight repository, and is not vendored here. `superpowers` and `mattpocock-skills` stay off in this project, because foresight carries copies of their skills.

### Issue tracker

GitHub Issues and milestones (`zeroae/countersign`, via `gh`): an epic is a milestone, a spec an issue of type Feature, its tickets sub-issues. See `docs/agents/issue-tracker.md`.

### Triage labels

The five triage states, as `triage:` labels (`triage:needs-triage`, `triage:needs-info`, `triage:ready-for-agent`, `triage:ready-for-human`, `triage:wontfix`). The category is the issue type. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` at the repo root, created lazily. Decisions that bind more than one component are ADRs in `docs/adr/`; until the first one, the design record holds them. See `docs/agents/domain.md`.
