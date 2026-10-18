# ViShare_Quick Build Plan

## Phase 1

| Build | Release | Target |
|---|---|---|
| Build 1 | `alpha_0.1` | Foundation, Python package, CLI basics, diagnostics, tests, GitHub workflows |
| Build 2 | `alpha_0.2` | Make the computer discoverable to a real Android device running Quick Share |
| Build 3 | `alpha_0.3` | Receive and save files under `ViShare Quick/download` |
| Build 4 | `alpha_0.4` | Discover a real Android device running Quick Share |
| Build 5 | `alpha_0.5` | Select and send files to a real Android Quick Share recipient |

## Phase 2

`beta_0.6` through `stable_1.0`

Detailed scope will be planned after Phase 1 device-level milestones are verified.

## Acceptance criteria for alpha_0.1

- Project has a valid Python package structure.
- CLI help and version commands work.
- `doctor` reports basic runtime and OS information without network scanning.
- Unit tests pass on Windows and Linux.
- GitHub Actions has test and tagged release workflows.
- No Quick Share discovery, sockets, or file transfer is claimed or implemented in this build.
