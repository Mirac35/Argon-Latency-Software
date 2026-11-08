# Argon — External GitHub Research Notes

**Purpose:** discover engineering patterns and candidate capabilities for Argon. This is not a certification of the repositories or their performance claims.

**Research snapshot:** 2026-11-07. Repository state, licenses, branches, and maintenance can change; re-check before reuse.

## Primary references

### 1. Intel GameTechDev / PresentMon
https://github.com/GameTechDev/PresentMon

- Per-present/ETW frame capture and analysis infrastructure; includes command-line capture and related tooling.
- Argon relevance: strongest measurement foundation in this shortlist for frame-time and presentation diagnostics.
- Use: inspect current CLI/API, license, supported Windows versions, ETW permissions, metrics definitions, process/swapchain selection, and packaging requirements.
- Limitation: a measurement tool, not a source of Windows tweaks or proof that any tweak improves performance.

### 2. aidangilmartin / pc-opti
https://github.com/aidangilmartin/pc-opti

- Detailed Windows 11 gaming/latency guide. The inspected revision organized recommendations by confidence and discussed presentation paths, PresentMon/CapFrameX, power plans, input latency, DPC/ISR, bufferbloat, timer behavior, MSI, and interrupt affinity.
- Argon relevance: cross-check current tweak descriptions and expose myths/overclaims.
- Limitation: personal research, not an official Microsoft/AMD standard. Verify claims against primary documentation and code.

### 3. omnibot007 / win-latency-guide
https://github.com/omnibot007/win-latency-guide

- Windows gaming latency guide with tweak inventory, read-only audit, benchmark helpers, backup/revert scripts, and failure notes.
- Argon relevance: audit-before-apply, exact registry path/type validation, one-owner-per-setting, restore checks, and negative-result reporting.
- Limitation: inspected guide targeted a specific Intel/NVIDIA/Windows configuration; do not port its settings to AMD Ryzen systems without checking applicability. Treat its measured outcomes as machine-specific.

### 4. Amirtheshwaran / ZeroStutter
https://github.com/Amirtheshwaran/ZeroStutter

- Experimental Windows utility combining per-game process handling, reversible CPU/process changes, PresentMon capture, and CSV analysis.
- Argon relevance: process lifecycle, stop/restore semantics, capture workflow, and benchmark quality checks.
- Particularly useful lesson: the inspected project report explicitly described a comparison that did not establish an improvement because capture conditions/presentation modes and repeatability were inadequate.
- Limitation: experimental project; borrow methodology, not its performance claims.

### 5. psgods101 / CoreCage
https://github.com/psgods101/CoreCage

- .NET/WPF gaming utility with process scheduling/isolation concepts, a tweak ledger, profiles, restore behavior, and PresentMon-oriented comparison.
- Argon relevance: architecture ideas for profile lifecycle and reversible action ledgers.
- Limitation: low adoption at inspection; verify source, tests, current maintenance, and README performance claims before relying on them.

### 6. MikeInNs / CorePin
https://github.com/MikeInNs/CorePin

- Per-game scheduling/profile and background-workload feature ideas.
- Argon relevance: feature discovery and comparison of baseline/candidate behavior.
- Limitation: license metadata was reported as `NOASSERTION` at inspection. Do not copy code or assets unless a compatible license is established. Verify the current repository metadata.

### 7. moneks1106-code / gaming-power-plan
https://github.com/moneks1106-code/gaming-power-plan

- Community power-plan artifact with explicit processor and device power-setting overrides and restore guidance.
- Argon relevance: compare exact power-setting GUIDs and AC/DC values against existing Argon controls; possible named plan export/diff workflow.
- Limitation: do not import blindly or replace the active plan. Community reports about mouse delivery are not end-to-end input-latency evidence.

### 8. moneks1106-code / InputLab
https://github.com/moneks1106-code/InputLab

- Raw Input-oriented diagnostic concept for host delivery intervals, gaps/batching, USB topology, and interrupt layout.
- Argon relevance: a future input diagnostics view.
- Limitation: host Raw Input timing is not device polling, sensor scan rate, or click-to-photon latency. License/source availability was unclear at inspection; do not embed or copy without checking.

## Secondary discovery references

### 9. NEKR1D / PC-OPTIMIZATION
https://github.com/NEKR1D/PC-OPTIMIZATION

- Personal tweak batch and tool index tested on a specific Intel/Radeon/Windows setup.
- Use only as a discovery index. The inspected material included risky or hardware-specific BIOS suggestions; do not port its BIOS checklist or treat it as authoritative.

### 10. ChrisTitusTech / winutil
https://github.com/ChrisTitusTech/winutil

- Broad Windows installation/configuration/debloat utility.
- Use for settings inventory and UX ideas only. It is not evidence that its presets improve gaming FPS. Do not import blanket service-disable presets.

### 11. hellzerg / optimizer
https://github.com/hellzerg/optimizer

- The inspected repository described itself as deprecated/superseded.
- Historical feature discovery only. Check current repository status and successor before considering any reference.

## Candidate opportunities for Argon

| Priority | Candidate | Why it may matter | Gate before implementation |
|---|---|---|---|
| P0 candidate | PresentMon capture + quality gate | Valid per-frame measurements can make Argon's claims and A/B comparisons more trustworthy. | First inspect Argon's current benchmark code; validate PresentMon version/API/license/ETW permissions and reject invalid captures. |
| P1 candidate | Tweak provenance/evidence ledger | Users need to know what a tweak changes, where the claim comes from, and whether the setting actually took effect. | Check whether current tweak metadata/state journal already covers these fields; add only real gaps. |
| P1 candidate | Windows 11 presentation diagnosis | Presentation mode can affect frame pacing and latency; detection may be more useful than another registry toggle. | Use supported detection/documentation; report before changing; do not force undocumented keys. |
| P1 candidate | Per-game profile lifecycle | Could make existing controls safer and easier to use per game. | Verify current profile/process functionality first; handle launcher/game PID, child processes, multiple instances, crashes, opt-in and restore. |
| P2 candidate | Input delivery diagnostics | Could expose host-side delivery jitter/gaps and USB topology. | Name the metric accurately; do not market as click-to-photon. |
| P2 candidate | Power-plan diff/export | Makes exact power-policy changes understandable and reversible. | Compare current implementation first; exact GUID/value support and backup/restore required. |
| P3 candidate | MSI/interrupt affinity diagnostics | Useful only for a specific demonstrated device/driver bottleneck. | Read-only diagnosis first; no blanket MSI or IRQ pinning. |

## Reject / do not generalize

- Generic debloat or service-disable presets as FPS optimizations.
- Disabling security, thermal protection, or recovery safeguards.
- HPET/BCD timer forcing as a universal latency fix.
- RAM cleaners marketed as FPS improvements.
- TCP tweaks advertised as direct in-match UDP ping improvements.
- Blanket MSI/interrupt affinity or core pinning.
- BIOS checklists copied across CPU/motherboard combinations.
- Undocumented GPU-driver registry knobs presented as official controls.

## Repository evaluation rubric

Stars are not a trust score. Before adopting an idea or code, inspect:
1. Source availability and license compatibility.
2. Current maintenance, default branch, release provenance, and commit history.
3. Tests, CI, and reproducible build instructions.
4. Exact source-to-claim mapping.
5. Measurement method, repeatability, and whether negative results are published.
6. Failure handling and rollback.
7. Hardware, OS, driver, and game scope.
8. Issue/PR history and known regressions.

A small repository can still be a useful engineering example. That does not make its tweaks safe defaults or its performance claims generalizable.
