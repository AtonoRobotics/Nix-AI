## Agent skills

### Issue tracker

Issues are tracked in GitHub at `AtonoRobotics/Nix-AI` through the GitHub connector. See `docs/agents/issue-tracker.md`.

### Triage labels

The repository uses the default five-role triage vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. See `docs/agents/domain.md`.

## Outcome integrity

The user's complete requested production outcome is the unit of work. Do not reduce it to a foundation, scaffold, prototype, compatibility layer, locally correct module, easier test target, or later integration task.

Intermediate plans, commits, tests, and reviews never redefine scope or completion. Incorporate discovered prerequisites into the full implementation. Evaluate every change and review against the original request and the real deployed end-to-end path.

Unused modules, placeholders, alternate state paths, fake providers, scripted integration substitutes, synthetic evidence, and wire-later changes are prohibited unless explicitly requested.
