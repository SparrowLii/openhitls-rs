---
name: phase-docs
description: Update documentation files after completing a phase. Use when a phase implementation or refactoring is complete and docs need syncing.
argument-hint: "<phase-id> <phase-title>"
disable-model-invocation: true
---

Update all documentation files after completing Phase $ARGUMENTS.

## Files to Update

### 1. DEV_LOG.md
Append a new phase entry at the end (ascending chronological order) with:
- `## Phase $0: $1` or `## Refactoring-Phase $0: $1` (for R-prefixed phases)
- `**Date**: YYYY-MM-DD`
- `**Scope**: one-line scope description`
- `### Summary` — what was done
- `### Files Modified` — table of files and changes
- `### Build Status` — test counts, clippy, fmt results

### 2. PROMPT_LOG.md
Append a new entry with:
- `## Phase $0: $1`
- `**Prompt**: the original task description
- `**Scope**: what was targeted
- `**Work performed**: numbered list of actions
- `**Result**: test counts, build status

### 3. ARCH_LOG.md (for R-phases only)
Append a new entry with:
- `## Phase $0: $1`
- `### Date: YYYY-MM-DD`
- `### Problem` — what architectural issue was addressed
- `### Solution` — approach taken
- `### Execution` — files modified, metrics
- `### Impact` — before/after comparison table
- `### Verification` — build status

### 4. CLAUDE.md
- Update the `Status:` line to include the new phase
- Update test counts if they changed
- Update `Key milestones` section if relevant

### 5. README.md
- Update test counts in `Building & Testing` section if they changed
- Update protocol/algorithm tables if new features were added

## Conventions

- Phase headings in DEV_LOG use `## Refactoring-Phase Rxxx:` for R-phases
- Phase headings in PROMPT_LOG/ARCH_LOG use `## Phase Rxxx:`
- Dates use `### Date: YYYY-MM-DD` format in ARCH_LOG
- All phases must be in ascending numerical order within each file
- DEV_LOG has two sections: top (reverse chronological for even phases 74-92) and bottom (ascending for all others)
