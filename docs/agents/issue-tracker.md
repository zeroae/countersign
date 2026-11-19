# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues on `zeroae/countersign`. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --type <type> --label <triage label> --title "..." --body-file <file>`. Titles are plain sentences with no kind prefix: the type carries the kind.
- **Read an issue**: `gh issue view <number> --comments`.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Set the type**: `gh issue edit <number> --type <type>`. Types are the organisation's: Epic, Feature, Task, Bug, Chore.
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v`; `gh` does this automatically when run inside a clone.

## Labels

Countersign uses only the process labels: `triage:` (`docs/agents/triage-labels.md`), `origin:`, `wayfinder:` and `security`. Each issue carries exactly one `triage:` label once triaged. The category is the issue type, never a label.

The foresight plugin is installed per machine, not vendored here, so its `labels.json` and `labels.py` are not in this repository. That declaration also holds the foresight repository's own `area:`, `deploy:`, `migration:` and `flag:` labels, so never run `labels.py sync --apply` against `zeroae/countersign`: it would add them. Creating or changing a label is the owner's step, by hand with `gh label create` or `gh label edit`.

`origin:` goes on an issue opened from somewhere other than planning: `origin:review` for a review finding, `origin:retro` for a retro, `origin:site` for something found where Countersign is deployed (an Integrator's or operator's environment), `origin:alarm` for an alarm. Planned work carries none.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.

## Planned work: epics, specs and tickets

| What | On GitHub | Issue type | Labels |
|---|---|---|---|
| Epic | A milestone, named `E<n> <title>` | — | — |
| Wayfinder map, decision ticket | An issue in the epic's milestone | none | `wayfinder:<kind>` only |
| Spec | An issue in the epic's milestone | Feature | `triage:ready-for-agent` |
| Ticket | A sub-issue of its spec, in the same milestone | Task | `triage:ready-for-agent` (or `triage:ready-for-human`) |
| Bug, small fix, general follow-up | An issue with no milestone | Bug, Task or Chore | a `triage:` label; `origin:` when it has one |
| Follow-up about an epic, from a review | In its milestone, a sub-issue of the ticket whose review found it | Task | `origin:review`, `triage:ready-for-agent` |
| Follow-up about an epic, from a retro | In its milestone, with no parent, relating to the ticket it came from | Task | `origin:retro`, `triage:ready-for-agent` |

The design record from before this process, `docs/specs/2026-11-17-countersign-design.md`, stays a file. A new spec is an issue of type Feature.

- **Open an epic's milestone** at the effort's first artifact (the wayfinder map, or the spec). GitHub assigns the number, so open it under the plain title, read the number back and rename it `E<n> <title>`:

  ```bash
  N=$(gh api repos/zeroae/countersign/milestones -f title="<title>" \
        -f description="<one plain sentence>" --jq .number)
  [ -n "$N" ] || { echo "no milestone opened" >&2; exit 1; }
  gh api -X PATCH repos/zeroae/countersign/milestones/$N -f title="E$N <title>"
  ```

- **Create a ticket** with its type, milestone and parent in one call: `gh issue create --type Task --milestone "E<n> <title>" --parent <spec> --label triage:ready-for-agent --title "..." --body-file <file>`.
- **Blocking** is GitHub's own dependency link: `gh api --method POST repos/zeroae/countersign/issues/<blocked>/dependencies/blocked_by -F issue_id=<blocker id>`, where the id is `gh api repos/zeroae/countersign/issues/<blocker> --jq .id`, not the number. Create every ticket first, then wire the links.

## A follow-up from a retro or a review

Sort it with one test: would this have been found building any ticket of any epic?

- **No, it is about the epic**: it goes in the epic's milestone with `triage:ready-for-agent` and never under the spec.
- **Yes, it is general** (a flaky test, a product bug): no milestone, no parent, `triage:needs-triage`.
- **You cannot tell**: file it as general and say so in your report.

Open it without `--parent`, then link it to the ticket it came from with the foresight plugin's `link-follow-up.py <the new issue> <the ticket>`, run from this checkout so `gh` names this repository. A review follow-up about the epic becomes a sub-issue of that ticket; any other becomes a "relates to" link.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue labelled `wayfinder:map`, in the epic's milestone, with no issue type. Each **child ticket** is a sub-issue of the map in the same milestone, labelled `wayfinder:<research|prototype|grilling|task>`. Blocking uses the dependency link above. Claim a ticket with `gh issue edit <n> --add-assignee @me`; resolve it with a comment holding the answer, `gh issue close <n>`, and a pointer in the map's Decisions-so-far.
