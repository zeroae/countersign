# Design mockups

The owner reviewed these clickable prototypes before the matching code was written. They are kept here as the design reference, next to the [design record](../2026-11-17-countersign-design.md). The handbook build skips everything under `docs/specs/`.

| Mockup | Published prototype | Implemented in |
| --- | --- | --- |
| [Companion: whole-app Integrator theming](companion-theming/) | https://claude.ai/artifact/9j7jajgJrdWYaQUmcAHQfj | #13 |
| [Demo Integrator: Harbor Ledger site and Countersign widget](demo-integrator/) | https://claude.ai/artifact/KrQCjkZ2yBTwjTVj5b6yDc | #11 |

## Reading them

- **Running a prototype:** each one is a Claude artifact. `Main.dc.html` holds the markup, styles and logic, and `canvas.json` holds the canvas settings. Both depend on a runtime script that claude.ai provides, so opening `Main.dc.html` from disk will not run the prototype. To click through one, open its published link. The links are private; ask the owner for access.
- **Using the source:** the HTML, CSS and JavaScript are plain text. Read them for exact colours, spacing, wording and states, or diff them when a mockup changes. The Companion palette derivation (OKLCH with WCAG AA clamps) is in the companion mockup's script.

## Which parts are decided

- **Companion:** build the **Middle ground** mode. The **Strict** and **Open** modes exist only for comparison. The design record's "Companion branding and notification channels" section lists the elements that stay fixed in every theme.
- **Demo Integrator:** the layout and states are decided, but Harbor Ledger's colour changed afterwards. It is teal (`#0f6b6b` on `#eef6f4`; dark `#5cc8bd` on `#0f1f1e`), as in the Companion mockup, not the blue this mockup shows.

## Changing a mockup

Ask Claude to update the published artifact by its link. Then copy the new `Main.dc.html` and `canvas.json` here in the same pull request as the code change, so the reference and the implementation stay together.
