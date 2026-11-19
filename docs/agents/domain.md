# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root: the glossary.
- **The design record**, `docs/specs/2026-11-17-countersign-design.md`. It holds the trust model, the per-grant isolation contract, the qualification plan and the decisions made before the first release. The mockups beside it in `docs/specs/mockups/` are the owner-reviewed UI reference.
- **ADRs** under `docs/adr/`, once the first one is written. An `accepted` one binds you; a `proposed` one is not binding yet.
- **The handbook page for the area**: `docs/architecture.md` for the trust boundaries, `docs/operate.md` for deployment requirements, `docs/reference/` for configuration, the Broker API, the control protocol and the tested platforms.

If `GLOSSARY.md` or `docs/adr/` doesn't exist, **proceed silently**. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates them lazily when terms actually get resolved or a decision is made.

## ADRs

Write an ADR when a decision binds more than one component (Broker, Gateway, Companion, widget, protocol) or changes a contract the design record states, such as the per-grant isolation contract. Number them in order from `docs/adr/0001-<slug>.md`, one root, with front matter `status`, `date`, `supersedes`. An accepted ADR changes only by a new ADR that supersedes it. A decision that touches one component stays in its pull request.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`, and until it exists, as the design record uses it: Integrator, Workload, Broker, Gateway, Companion, grant, Context, sidecar and shared mode. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag decision conflicts

If your output contradicts an ADR or the design record, surface it explicitly rather than silently overriding:

> _Contradicts the per-grant isolation contract in the design record (workers isolated by user principal, container or equivalent OS sandbox), but worth reopening because…_
