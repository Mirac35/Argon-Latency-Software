# Argon — Next Milestone Selection and Implementation Prompt

You are working in the Argon Latency Software repository.

Read first (all three files are in the repository root):
1. `GEMINI.md` — project-specific working rules.
2. `EXTERNAL_GITHUB_RESEARCH.md` — external repository research and candidate feature areas.
3. This prompt — the task workflow and acceptance expectations.

Do not look for or require `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, or a hidden skills directory. This task is being run with Gemini CLI and the three root-level Markdown files above are the complete instruction set.

## Objective
Select and implement the single most valuable next Argon milestone based on the current source—not on assumptions or a previously suggested roadmap.

The owner has personally observed a 3–5% FPS improvement from a selected Argon configuration on their own system. Respect that user-observed result. The task is to improve the product, not to dismiss the result or spend the entire task re-litigating it.

## Phase 1 — Inspect the actual repository
- Inspect the current working tree, README, project/solution files, build scripts, source layout, and tests.
- Map the application architecture and trace existing tweak definitions through UI, apply, state capture, verification, persistence, conflict handling, and revert.
- Inventory existing performance tools, process controls, profiles, benchmark functions, telemetry, and Windows/driver settings.
- Search for existing IDs and implementation paths before describing any feature as missing.
- State precisely what you inspected. Do not claim a full audit if it was selective.

## Phase 2 — Revalidate external research
Use the research appendix as a starting index, not as authority. Re-check the current repositories, default branches, licenses, maintenance, tests, and relevant source files:
- https://github.com/GameTechDev/PresentMon
- https://github.com/aidangilmartin/pc-opti
- https://github.com/omnibot007/win-latency-guide
- https://github.com/Amirtheshwaran/ZeroStutter
- https://github.com/psgods101/CoreCage
- https://github.com/MikeInNs/CorePin
- https://github.com/moneks1106-code/gaming-power-plan
- https://github.com/moneks1106-code/InputLab
- https://github.com/NEKR1D/PC-OPTIMIZATION
- https://github.com/ChrisTitusTech/winutil
- https://github.com/hellzerg/optimizer

Also check primary Microsoft/AMD/Intel documentation for any proposed Windows, driver, API, or registry behavior. Do not copy code from unclear/incompatible licenses.

## Phase 3 — Build a feature-gap matrix
For each plausible candidate, record:
- Candidate feature.
- Existing Argon overlap (exact IDs/classes/methods/files).
- Actual missing capability.
- User value and workflow impact.
- Evidence quality and source.
- Implementation effort.
- Risk and blast radius.
- Reversibility and failure recovery.
- Testability and measurable acceptance criteria.

At minimum evaluate:
- PresentMon-backed game frametime capture and capture-quality validation.
- Tweak provenance/evidence/read-back ledger.
- Windows 11 presentation-mode diagnosis.
- Per-game profile/process lifecycle.
- Input host-delivery diagnostics.
- Power-plan diff/export.
- MSI/interrupt diagnostics (not blanket changes).

Do not automatically choose Game Profiles + A/B Lab, PresentMon integration, or any other previously suggested feature. Choose only after the current-code gap analysis.

## Phase 4 — Select one milestone
Choose the best candidate using the matrix. Explain briefly why it outranks the next two candidates. Prefer a cohesive, user-visible improvement over a broad bundle of unrelated tweaks.

If no candidate is sufficiently justified, do not invent one. Report the blocker and propose the smallest prerequisite.

## Phase 5 — Define and implement
Before coding, define:
- User-facing behavior.
- Exact files/classes to change.
- State ownership and lifecycle.
- OS/hardware applicability.
- Failure cases.
- Rollback/recovery behavior.
- Acceptance tests and measurable success criteria.

Implementation rules:
- Extend existing architecture; do not create a parallel tweak/state framework.
- Preserve exact original state and restore semantics.
- Prefer read-only detection before mutation.
- No silent persistent changes or surprise background services.
- Do not add dependencies without explaining why.
- Do not disable security/thermal protections or use blanket debloat, timer forcing, RAM cleaners, TCP-as-UDP-ping claims, or blanket MSI/IRQ pinning.
- Treat undocumented registry/driver values as experimental and opt-in only, if justified at all.
- Separate user-observed results from controlled measurements.

## Phase 6 — Validate and report
- Build using the current documented project build path where the environment supports it.
- Run relevant tests and static checks.
- Exercise apply/read-back/failure/revert paths for any system change.
- For performance capture, validate process/swapchain identity, presentation mode, event loss, repeated runs, and stable test conditions.
- Do not claim tests passed unless they ran successfully.
- Report changed files, exact commands, results, limitations, and any untested paths.

## Final response format
1. What was inspected.
2. Feature-gap matrix.
3. Selected milestone and why.
4. Implementation summary.
5. Build/tests actually run.
6. Risks and limitations.
7. Next concrete step.

Do not pad the report with generic headings or repeat the same caveat. Be direct and specific.
