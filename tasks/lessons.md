# Lessons

Patterns captured after corrections, so the same mistakes aren't repeated.
Reviewed at the start of each session.

## Format

### <short title>
- **Mistake:** what went wrong
- **Trigger:** the situation that surfaces it
- **Rule:** what to do instead

## Lessons

### Every change lands through a PR the owner merges
- **Mistake:** Pushed directly to `main` while setting up a repo.
- **Trigger:** Seeding a repo, replacing a starter commit, any push targeting `main`.
- **Rule:** Feature branch → push branch → open PR → stop. The owner merges manually.

### Check PR state before pushing more commits to its branch
- **Mistake:** Pushed three commits to a PR branch after the PR had already been merged, so they never reached `main`.
- **Trigger:** Adding follow-up changes to an open PR, especially after time has passed.
- **Rule:** Run `gh pr view <n> --json state` first. If it's merged, branch from the updated `main` and open a new PR.

### Finish the audit before opening the PR
- **Mistake:** Opened the Phase 1 PR while the code audit was still running. The owner merged it, so the fixes needed a second PR.
- **Trigger:** Any non-trivial PR. The owner reviews and merges quickly.
- **Rule:** Run the implementation audit and apply its fixes first, then open the PR.
