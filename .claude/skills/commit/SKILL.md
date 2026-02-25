---
name: commit
description: Create a well-formatted git commit following project conventions. Use when the user asks to commit changes.
argument-hint: "[commit-message]"
disable-model-invocation: true
allowed-tools: Bash(git *)
---

Create a git commit following openHiTLS-rs project conventions.

## Behavior

### Step 1: Analyze Changes
Run in parallel:
- `git status` — see all modified/untracked files
- `git diff --stat` — see change summary
- `git log --oneline -5` — check recent commit style

### Step 2: Determine Commit Type
Based on changes, select the appropriate prefix:

| Prefix | When to Use |
|--------|-------------|
| `feat:` | New feature or capability |
| `fix:` | Bug fix |
| `refactor:` | Code refactoring without behavior change |
| `docs:` | Documentation-only changes |
| `test:` | Test-only changes |
| `chore:` | Build, CI, dependency updates |

For phase-based work, use the pattern from recent commits:
- `refactor: Phase N — <description>` for refactoring phases
- `docs: update DEV_LOG, PROMPT_LOG, ARCH_LOG, CLAUDE.md for Phase N` for doc updates

### Step 3: Stage and Commit
- Stage specific files (never use `git add -A` or `git add .`)
- Do NOT stage files containing secrets (.env, credentials, etc.)
- Create commit with message ending with:
  ```
  Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
  ```
- Use HEREDOC format for multi-line commit messages
- If `$ARGUMENTS` is provided, use it as the commit message

### Step 4: Verify
Run `git status` to confirm clean working tree.

## Conventions
- Keep commit message first line under 72 characters
- Use imperative mood ("add", "fix", "refactor", not "added", "fixed")
- Separate code changes from documentation changes into distinct commits when practical
- Never amend previous commits unless explicitly requested
- Never push unless explicitly requested
