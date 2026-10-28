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

### Batch follow-up pushes to an open PR
- **Mistake:** Pushed four small commits (two of them docs-only) to an open PR within six minutes, so CI ran four times and the owner asked why.
- **Trigger:** Fixing audit findings or adding vault notes after a PR is open.
- **Rule:** Batch follow-ups into one push. CI now cancels superseded PR runs (#20), but still don't push docs-only commits one by one.

### Fix the question before choosing the method
- **Mistake:** In Phase 5 the ATT&CK hybrid was designed after seeing the zero-shot test results, and turned out β-fragile. Phase 6's planned gold-set evaluation would have been circular (labels = source feed for 298/299).
- **Trigger:** Any evaluation whose result goes in the README.
- **Rule:** Check that the labels can answer the question first, then commit a config fixing every choice before any test score (Phase 6 `cwe_config.py` is the pattern).

