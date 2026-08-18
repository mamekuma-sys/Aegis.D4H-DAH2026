# Aegis.0xD4H Repository Instructions

## Project mission

Build two independent DAH 2026 finals Docker images: one attacker and one defender. Base strategy on the Aegis.0xD4H preliminary report, but implement only behavior supported by observable finals interfaces.

## Language

Use Korean for team-facing explanations and documentation unless the user asks otherwise. Code identifiers and commit messages use English.

## Source priority

When facts conflict, use this order:

1. Latest finals rules and same-day organizer instructions
2. Official `deploy/docs/agent-guide.md` in the external skeleton
3. Observable behavior of the official skeleton
4. Preliminary report and preliminary source
5. Team-authored notes

## Repository boundary

- Keep attacker and defender runtime code under `agents/attacker` and `agents/defender`.
- Keep interface definitions and fixtures under `contracts`.
- Keep the official skeleton outside this repository.
- Never copy `deploy/router`, `deploy/backend`, `deploy/challenges`, `deploy/litellm-gw`, or the Broker binary here.
- Keep raw competition documents and preliminary source in private team storage; track only hashes and mappings under `docs/references`.
- Never commit `.env`, credentials, tokens, flags, PDFs, PCAPs, logs, caches, or generated output.

## Design gates

- Do not add attacker runtime behavior before approving the observation-plan-execution design.
- Do not add defender runtime behavior before approving the 300ms hot-path and online-correlation design.
- Do not put remote LLM calls in the defender's per-packet synchronous verdict path.
- Do not assume report signals such as vehicle state or parameter hashes are visible unless a parser proves they are present in received packets.

## Ownership

- Attacker owner: attacker Python, tests, and `research/attack-scenarios.md`
- Defender owner: defender Python, tests, and `research/defense-mapping.md`
- Docker owner: both Dockerfiles, `integration/**`, image scripts, image CI, and Registry procedures
- Team lead Lee Gyeong-jun: `contracts/**`, shared architecture and decisions, `docs/references/**`, PR verification, and final merge

Docker changes require the affected agent owner and team lead to review. Docker owner must not change strategy code unilaterally. Agent owners must not finalize Dockerfiles or shared contracts alone.

Use a short-lived branch for one task and delete it after merge. Never create permanent person branches or push directly to `main`.

## Required checks

Run before committing repository-foundation changes:

macOS/Linux:

```bash
bash scripts/check-layout.sh
```

Windows:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

When an external skeleton is available, also run:

macOS/Linux:

```bash
bash scripts/validate-skeleton.sh <path>
```

Windows:

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <path>
```
