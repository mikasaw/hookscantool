# HookScanTool

**Windows Process Hook Scanner** — Detects IAT, EAT, and inline hooks in running Windows processes.

简体中文文档见 [README.zh-CN.md](README.zh-CN.md)。

## Overview

HookScanTool is a Windows security/malware analysis tool that scans running processes for API hooks. It detects three types of hooks:

- **IAT Hooks** — Import Address Table tampering (function pointers redirected to different modules)
- **EAT Hooks** — Export Address Table tampering (exported function RVAs modified in memory)
- **Inline Hooks** — Function prologue patching (JMP/CALL/PUSH+RET/MOV+JMP to another module)

The tool compares each function's in-memory code against the on-disk DLL, using [Zydis](https://github.com/zyantific/zydis) for instruction-level disassembly. Hook chains are traced through multiple JMP/CALL indirections to reveal the final target. The module that owns a hook's target address can be checked against a user-supplied SHA-256 signature database to mark known (e.g. security-software) hooks.

## Features

- **GUI Mode** — Dear ImGui + DirectX 11 interface with process tree, module triage panel, hook list, chain viewer, and one-click (background) restore
- **CLI Mode** — Command-line scanning with JSON/CSV/SARIF output and automated restore
- **Continuous Monitoring** — `--watch` mode polls a process and alerts on newly appearing hooks
- **Fleet Scan** — `--deep` mode scans every accessible process in parallel
- **Selective Scanning** — Recon module list with suspicion scores, scan only suspicious modules
- **Module Triage** — Suspicion scoring system (path, name, WoW64 heuristics)
- **Hook Chain Tracing** — Follows JMP/CALL/PUSH+RET/MOV+JMP chains to the final hook target
- **Hook Restoration** — Thread suspension, TOCTOU verification before writing, read-back verification after, and rollback on partial writes
- **Signature Detection** — SHA-256 known-signature database marks hook targets that belong to known modules
- **WoW64 Support** — Scan 32-bit processes from a 64-bit scanner via `NtWow64ReadVirtualMemory64`
- **API Set Awareness** — `api-ms-*` imports are resolved to their owner module and verified against its export table
- **JSON / CSV / SARIF Export** — Versioned (`schema_version`), UTF-8 safe, valid for strict parsers and code-scanning pipelines

## Building

### Requirements

- **Compiler**: MSVC 2022+ (or MinGW-w64 GCC)
- **CMake**: 3.20+
- **Dependencies**: Zydis 4.0.0 + Zycore, Dear ImGui 1.91.8 (included in `deps/`, licenses in each directory)

### Build (MSVC)

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Build (MinGW)

```bash
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
```

Or use the helper script: `./build.sh [msvc|mingw]` (set `VS_GEN="Visual Studio 18 2026"` for VS Insiders).

### Output

| Target | Path | Description |
|--------|------|-------------|
| `hookscan_cli.exe` | `build/Release/` (MSVC) or `build/` (MinGW) | Command-line tool |
| `hookscantool.exe` | same | GUI application |

## Running the tests

```bash
cmake -B build -DHOOKSCAN_BUILD_TESTS=ON   # add your generator/arch flags as above
cmake --build build --config Release
./build/Release/hookscan_test.exe          # MinGW: ./build/hookscan_test.exe
```

207 tests cover PE parsing, module scoring, inline instruction matching, CLI argument parsing, the JSON/CSV/SARIF writers, EAT alias matching, and the signature subsystem.

## Usage

### GUI

Run `hookscantool.exe` as Administrator for full process access.

1. Select a process from the process tree (left panel)
2. Click **Scan Selected** to run a full scan, or use the module triage panel to select specific modules
3. View detected hooks in the hook list (middle-right); use **Export JSON/CSV** to save a report
4. Click a hook to see its chain trace (bottom-right)
5. Use **Restore Hook** to restore original bytes (runs in the background, UI stays responsive)

### CLI

```bash
# List running processes
hookscan_cli.exe --list

# Scan a process for hooks
hookscan_cli.exe 1234

# Scan and write reports (JSON / CSV / SARIF are independent)
hookscan_cli.exe 1234 --json report.json --csv report.csv --sarif report.sarif

# List modules with suspicion scores
hookscan_cli.exe 1234 --modules

# Filter modules: s=suspicious only, a=all, m=non-microsoft
hookscan_cli.exe 1234 --modules --filter s

# Scan a specific module by index
hookscan_cli.exe 1234 --scan-module 5

# Restore a detected hook (asks for confirmation)
hookscan_cli.exe 1234 --restore 0

# Watch a process: rescan every 30s (default), alert on NEW hooks
hookscan_cli.exe 1234 --watch
hookscan_cli.exe 1234 --watch --interval 10 --json watch.json

# Scan every accessible process (parallel, 4 workers by default)
hookscan_cli.exe --deep
hookscan_cli.exe --deep --jobs 8 --filter s --json deep.json   # list only processes with hooks

# Load a known-signature database (default: signatures.txt in the current directory)
hookscan_cli.exe 1234 --sigs signatures.txt
```

**Watch exit codes**: `0` clean stop, `1` new hooks were seen (script/CI friendly), `2` target lost.

## JSON output

Reports are UTF-8 JSON with a schema version:

```json
{
  "schema_version": 1,
  "pid": 1234,
  "process_name": "target.exe",
  "hook_count": 1,
  "modules_scanned": 14,
  "scan_time_ms": 210,
  "truncated": false,
  "hooks": [
    {
      "module": "user32.dll",
      "function": "MessageBoxW",
      "type": "INLINE",
      "original_addr": "0x00007FFA12345678",
      "current_addr": "0x00007FFA98765432",
      "restorable": true,
      "signature": "",
      "chain_depth": 2,
      "original_bytes": "48894C2408",
      "hooked_bytes": "E9CD123400",
      "chain": [
        {"address": "0x00007FFA98765432", "disasm": "jmp 0x..."}
      ]
    }
  ]
}
```

`--deep` writes `{"schema_version": 1, "process_count": N, "processes": [ ... ]}` with the same report objects.

## Signature database

A signature database is a plain-text file (`signatures.txt` by default, see `signatures.example.txt`):

```
# <sha256 of the DLL file> <label>
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 our-edit-hook-dll
```

When a detected hook's target address lands inside a module whose SHA-256 matches a database entry, the hook is labelled with that entry (visible in the CLI table, the JSON `signature` field). Hash a module with `certutil -hashfile some.dll SHA256`.

## Suspicion scoring

| Criterion | Points |
|-----------|--------|
| Module not in Windows/Program Files | +30 |
| Suspicious name (hook, inject, patch, etc.) | +40 |
| WoW64 DLL in 64-bit process | +20 |

Score 0-30: Low risk | 31-60: Suspicious | 61-80: High | 81-100: Critical

## Known limitations

- **Inline detection depth** — only the first 5 instructions of each function are compared against disk. Hooks placed after the prologue window are not detected.
- **EAT hooks vs inline** — EAT scan only compares export RVAs; a hook that patches a function body without changing the RVA is caught by the inline scan instead.
- **Address-based API-set verification** — an api-ms import hijacked to *another legitimate export of the same owner module* cannot be distinguished from a normal forward by address alone.
- **Truncation** — if the report hook buffer fills, the scan sets `"truncated": true` and results may be incomplete.

## Administrator rights & antivirus

- Without elevation, most processes outside your own session return `ENGINE_ACCESS_DENIED`. Run the CLI/GUI **as Administrator** for full coverage.
- A tool that reads other processes' memory and writes to them will attract antivirus heuristics. If your AV quarantines HookScanTool, verify the published SHA-256 checksums against the release and add an exclusion.

## Error codes

| Code | Meaning |
|------|---------|
| `ENGINE_OK` (0) | Success |
| `ENGINE_ACCESS_DENIED` (-1) | Cannot open process (run as Admin) |
| `ENGINE_PROCESS_NOT_FOUND` (-2) | Process or modules not found |
| `ENGINE_NO_MEMORY` (-6) | Out of memory |
| `ENGINE_SCAN_FAILED` (-7) | General scan failure |

`ENGINE_READ_ERROR`/`ENGINE_WRITE_ERROR`/`ENGINE_PACKED_DLL` are reserved (see `src/engine/types.h`): scanner-level read failures surface as "no hook", and packed images are signalled per-hook via `restorable: false`.

## Architecture

```
src/
├── engine/          # Core scanner engine (pure C)
│   ├── engine.h/.c        # Public API: scan, recon, restore, JSON/CSV/SARIF export
│   ├── types.h            # Shared type definitions + error codes
│   ├── pe_parser.h/.c     # PE header parsing (in-memory + on-disk)
│   ├── process_enum.h/.c  # Process/module enumeration
│   ├── iat_scanner.h/.c   # IAT hook detection
│   ├── eat_scanner.h/.c   # EAT hook detection
│   ├── inline_scanner.h/.c# Inline hook detection
│   ├── chain_tracer.h/.c  # Hook chain tracing
│   ├── restore.h/.c       # Hook restoration
│   ├── wow64.h/.c         # WoW64 support
│   ├── sigcheck.h/.c      # Known-signature database (SHA-256, BCrypt)
│   └── module_scorer.h/.c # Suspicion scoring
├── cli/
│   ├── main.c       # CLI entry point
│   └── args.c/.h    # Argument parsing (unit tested)
└── gui/
    ├── main.cpp             # GUI entry point + main loop
    ├── ui_process_tree.cpp  # Process tree panel
    ├── ui_module_list.cpp   # Module triage panel
    ├── ui_hook_list.cpp     # Hook list panel + report export
    ├── ui_chain_view.cpp    # Chain viewer panel
    └── ui_restore.cpp       # Restore panel (background thread)
```

### Scan pipeline

1. **Recon** — Enumerate process modules, score each for suspicion
2. **IAT Scan** — For each import, verify the function pointer points within the expected DLL's address range (follows export forwarders; api-ms imports are verified against the resolved owner module's export table)
3. **EAT Scan** — Compare in-memory export RVAs against on-disk export RVAs (export-name aliases handled)
4. **Inline Scan** — Disassemble first instructions of each exported function, compare against on-disk using Zydis
5. **Chain Tracing** — Follow JMP/CALL/PUSH+RET/MOV+JMP indirections to the final hook target
6. **Signature Annotation** — Hash the module owning each hook target and label known modules from the database

## License

MIT — see [LICENSE](LICENSE). Third-party dependencies (Zydis, Zycore, Dear ImGui) are vendored under their own MIT licenses in `deps/`.
