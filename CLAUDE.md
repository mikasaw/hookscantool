# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

Working project. Both CLI (`hookscan_cli`) and GUI (`hookscantool`) build and run.

## Build

```bash
mkdir -p build && cd build && cmake .. -G "MinGW Makefiles" && mingw32-make -j4
```

For MSVC: `cmake .. -G "Visual Studio 17 2022" -A x64` then build in VS.

Output: `build/hookscan_cli.exe` (CLI) and `build/hookscantool.exe` (GUI).

## Architecture

- **Engine** (`src/engine/`, pure C): PE parsing, process enumeration, IAT/EAT/inline hook scanning, Zydis-based chain tracing, hook restoration, WoW64 support. Static library `hookscan_engine`.
- **CLI** (`src/cli/main.c`): Command-line interface. `--list`, scan by PID, `--json`, `--restore`.
- **GUI** (`src/gui/*.cpp`): Dear ImGui + DirectX 11. Process tree, hook list, chain view, restore panel. Scans run in background thread.
- **Dependencies** (`deps/`): Zydis v4.0.0 + Zycore (local), Dear ImGui v1.91.8 (local).

## Key APIs

- `engine_scan_process(pid)` → `hook_report_t*` (always returns report, check `error_code`)
- `engine_restore_hook(pid, entry)` → bool
- `engine_report_to_json(report, path)` → int
- `engine_free_report(report)` — must call to clean up chain arrays

## Engine ↔ GUI interop

Engine headers use `extern "C"` blocks. GUI .cpp files call engine functions directly.

## Scanner signatures

- `iat_scan_module(process, pid, mod, pinfo, hooks, cap)` — needs pre-enumerated module list
- `eat_scan_module(process, mod, hooks, cap)`
- `inline_scan_module(process, mod, hooks, cap)`

## gstack

Use gstack's `/browse` skill for all web browsing. Never use `mcp__claude-in-chrome__*` tools.

Available skills:
`/office-hours` `/plan-ceo-review` `/plan-eng-review` `/plan-design-review` `/design-consultation` `/design-shotgun` `/design-html` `/review` `/ship` `/land-and-deploy` `/canary` `/benchmark` `/browse` `/connect-chrome` `/qa` `/qa-only` `/design-review` `/setup-browser-cookies` `/setup-deploy` `/setup-gbrain` `/retro` `/investigate` `/document-release` `/codex` `/cso` `/autoplan` `/plan-devex-review` `/devex-review` `/careful` `/freeze` `/guard` `/unfreeze` `/gstack-upgrade` `/learn`

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
