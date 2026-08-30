# Issue tracker: GitHub

Issues and specifications live in `AtonoRobotics/Nix-AI`.

Use the authenticated GitHub connector for issue operations. Always pass
`AtonoRobotics/Nix-AI` explicitly rather than inferring it from the local
Git remote.

## Conventions

- Create work as GitHub issues.
- Read the issue body, comments, labels, and dependencies before acting.
- Use comments for durable decisions and implementation evidence.
- Apply and remove labels through the connector.
- Close an issue only after its acceptance criteria pass.
- Pull requests are not a triage request surface.

## Wayfinding

- The map is one issue labelled `wayfinder:map`.
- Decision tickets are child issues labelled by type.
- Use native sub-issues and dependencies when the connector supports them.
- Otherwise, maintain a task list in the map and `Blocked by: #...` lines
  in child issues.
- A ticket is actionable only when all blockers are closed and it is
  unassigned.
