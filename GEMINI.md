# Argon Latency Software — Gemini CLI Instructions

## Project purpose
Argon is a Windows gaming/performance utility. Build it into a useful, understandable, measurable product—not a collection of registry tweaks.

The owner has reported a 3–5% FPS improvement from a selected Argon configuration on their own machine, with temperatures unchanged. Treat this as a genuine user-observed result. Do not dismiss it, but do not present it as independently reproduced or universally guaranteed.

## Project-root reference files
The following Markdown files are expected to sit beside this `GEMINI.md` in the repository root:

- `EXTERNAL_GITHUB_RESEARCH.md` — research notes on external Windows optimization, latency, measurement, and gaming-utility repositories. Read it when researching performance behavior, evaluating candidate features, or planning product improvements. Treat it as a discovery index, not as authoritative proof; re-check current repository state, licenses, and primary sources before relying on it.
- `ARGON_NEXT_MILESTONE_PROMPT.md` — the detailed workflow for inspecting the current codebase, building a feature-gap matrix, selecting one milestone, implementing it, and validating the result. Read and follow it when asked to choose or implement Argon's next milestone. Do not assume its suggested candidates are automatically the right choice.

Do not look for a separate `SKILL.md`, `.agents/skills/` directory, or `.claude/` directory. The project instructions and the two reference documents are the complete Markdown guidance set for this workflow.

## Repository discipline
- Inspect the current checkout before making claims about architecture, existing features, build steps, or runtime behavior. Historical notes are leads, not proof.
- Check the working tree before editing. Preserve unrelated user changes.
- Search the existing implementation and feature IDs before proposing or adding functionality. Extend existing systems instead of duplicating them.
- Trace relevant features end-to-end: UI → model/definition → apply path → state capture → verification → persistence/journal → revert → failure handling.
- Report which files and code paths you actually inspected. Do not imply that a complete audit occurred if inspection was selective.
- Do not perform a broad rewrite when a focused change will solve the problem.

## Argon-specific engineering rules
- Preserve the existing state snapshot, journal, conflict detection, apply/read-back verification, and rollback mechanisms. Do not bypass them or create a parallel state-management system.
- Every system modification needs an exact target, supported Windows/hardware scope, original-state capture, read-back verification, failure handling, and a reliable restore path.
- Distinguish a successful write from proof that the operating-system or driver behavior actually changed.
- Prefer read-only diagnosis before system modification. Never silently apply broad, persistent, or system-wide changes.
- Do not add dependencies, services, scheduled tasks, startup hooks, telemetry uploads, or always-on background behavior without demonstrating necessity and obtaining approval.
- Do not disable Windows security controls, thermal protections, or recovery safeguards.
- Do not add blanket service-disable/debloat presets, HPET/BCD timer forcing, RAM cleaners, blanket MSI/IRQ pinning, or generic TCP tweaks marketed as in-game UDP-ping fixes.
- Treat undocumented registry and driver values as experimental. Verify their meaning, applicability, conflicts, and reversibility before considering implementation.

## Evidence and performance measurement
Keep these categories distinct:
- **User-observed:** reported by the owner; not independently reproduced in this task.
- **Measured:** captured under documented, repeatable conditions.
- **Source-documented:** supported by authoritative documentation or inspected implementation.
- **Anecdotal:** community report or repository author's claim.
- **Hypothesis:** plausible explanation that still needs validation.

For FPS/frametime work:
- Prefer valid per-frame PresentMon-compatible captures over synthetic timer tests or a single instantaneous FPS counter.
- Confirm the correct game process and swapchain; record presentation mode and detect dropped/lost events or other capture-quality problems.
- Keep game, scene, resolution, settings, driver, and test conditions consistent. Use warm-up and repeated A/B runs where practical.
- Use 1%/0.1% lows and percentile frame times only when capture and calculation semantics are valid.
- Do not describe Raw Input host-delivery timing as device polling or click-to-photon latency.
- Never promise universal FPS or latency gains from a single-machine result or third-party claim.

## Project baseline — verify before relying on it
Historically, Argon has been a C# WinForms x64 application targeting .NET Framework 4.8, with substantial implementation in `src/ArgonLatencyStudio.cs`, a tweak-definition/variation model, and a StateVault-style reversible state system. Source layout, target framework, feature IDs, and behavior may have changed. Inspect the current project/solution files and source before relying on this historical baseline.

## Choosing and implementing work
When asked what to build next, or to implement the next milestone:
1. Read `ARGON_NEXT_MILESTONE_PROMPT.md` and follow its repository-inspection and feature-gap workflow.
2. Inspect the actual current feature inventory and trace overlapping code paths before calling anything missing.
3. Read `EXTERNAL_GITHUB_RESEARCH.md` and revalidate relevant sources; do not treat repository stars, README claims, or old notes as proof.
4. Build a feature-gap matrix covering current overlap, user value, evidence quality, implementation effort, risk, reversibility, and testability.
5. Select one cohesive milestone based on the evidence. Do not automatically choose per-game profiles, A/B benchmarking, PresentMon integration, or any previously suggested idea.
6. Define acceptance criteria, failure cases, and rollback behavior before implementation.

For unrelated small fixes, do not force a full milestone-selection exercise. Read only the reference material relevant to the task.

## Build, validation, and delivery
- Use the repository's current documented build and test path.
- Do not claim a build or test passed unless you ran it and observed the result.
- If the environment cannot build the Windows application, state that limitation and perform the strongest relevant static validation available.
- For system changes, validate baseline capture, apply, read-back, partial failure, restart behavior where relevant, and exact revert.
- Inspect the final diff for unrelated or unintended changes.
- Avoid unnecessary audit/check-command loops. Complete the requested scope thoroughly in one pass where practical.
- In the final report, state files changed, behavior added, rollback behavior, commands/tests actually run, results, and known limitations. Keep it direct and specific.
