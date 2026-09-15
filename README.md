# HookScanTool

**Windows Process Hook Scanner** — Detects IAT, EAT, and inline hooks in running Windows processes.

## Overview

HookScanTool is a Windows security/malware analysis tool that scans running processes for API hooks. It detects three types of hooks:

- **IAT Hooks** — Import Address Table tampering (function pointers redirected to different modules)
- **EAT Hooks** — Export Address Table tampering (exported function RVAs modified in memory)
- **Inline Hooks** — Function prologue patching (JMP/CALL/PUSH+RET/MOV+JMP to another module)

The tool compares each function's in-memory code against the on-disk DLL, using Zydis for instruction-level disassembly. Hook chains are traced through multiple JMP/CALL indirections to reveal the final target.

## Features

- **GUI Mode** — Dear ImGui + DirectX 11 interface with process tree, module triage panel, hook list, chain viewer, and one-click restore
- **CLI Mode** — Command-line scanning with JSON output and automated restore
- **Continuous Monitoring** — `--watch` mode polls a process and alerts on newly appearing hooks
- **Fleet Scan** — `--deep` mode scans every accessible process in one run
- **Selective Scanning** — Recon module list with suspicion scores, scan only suspicious modules
- **Module Triage** — Suspicion scoring system (path, name, WoW64 heuristics)
- **Hook Chain Tracing** — Follows JMP/CALL/PUSH+RET/MOV+JMP chains to final hook target
- **Hook Restoration** — Thread suspension, TOCTOU verification before writing, read-back verification after, and rollback on partial writes
- **WoW64 Support** — Scan 32-bit processes from a 64-bit scanner via `NtWow64ReadVirtualMemory64`
- **JSON Export** — Versioned (`schema_version`), UTF-8 safe, valid for strict parsers

## Building

### Requirements

- **Compiler**: MSVC 2022+ (or MinGW-w64 GCC)
- **CMake**: 3.20+
- **Dependencies**: Zydis 4.0.0 + Zycore, Dear ImGui 1.91.8 (included in `deps/`)

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

136 tests cover PE parsing, module scoring, inline instruction matching, CLI argument parsing, and the JSON writer.

## Usage

### GUI

Run `hookscantool.exe` as Administrator for full process access.

1. Select a process from the process tree (left panel)
2. Click **Scan Selected** to run a full scan, or use the module triage panel to select specific modules
3. View detected hooks in the hook list (middle-right)
4. Click a hook to see its chain trace (bottom-right)
5. Use **Restore Hook** to restore original bytes

### CLI

```bash
# List running processes
hookscan_cli.exe --list

# Scan a process for hooks
hookscan_cli.exe 1234

# Scan and write JSON report
hookscan_cli.exe 1234 --json report.json

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

# Scan every accessible process
hookscan_cli.exe --deep
hookscan_cli.exe --deep --filter s --json deep.json    # list only processes with hooks
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

## Suspicion scoring

| Criterion | Points |
|-----------|--------|
| Module not in Windows/Program Files | +30 |
| Suspicious name (hook, inject, patch, etc.) | +40 |
| WoW64 DLL in 64-bit process | +20 |

Score 0-30: Low risk | 31-60: Suspicious | 61-80: High | 81-100: Critical

## Known limitations

- **Inline detection depth** — only the first 5 instructions of each function are compared against disk. Hooks placed after the prologue window are not detected.
- **WoW64 false positives** — legitimate OS-level Nt\* redirects in 32-bit `ntdll.dll` are reported as hooks. Treat WoW64 ntdll findings as expected noise unless corroborated.
- **api-ms-\* imports** — API Set virtual DLLs are not resolvable to a module range, so their IAT entries are not checked.
- **EAT hooks vs inline** — EAT scan only compares export RVAs; a hook that patches a function body without changing the RVA is caught by the inline scan instead.
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
│   ├── engine.h/.c        # Public API: scan, recon, restore, JSON export
│   ├── types.h            # Shared type definitions + error codes
│   ├── pe_parser.h/.c     # PE header parsing (in-memory + on-disk)
│   ├── process_enum.h/.c  # Process/module enumeration
│   ├── iat_scanner.h/.c   # IAT hook detection
│   ├── eat_scanner.h/.c   # EAT hook detection
│   ├── inline_scanner.h/.c# Inline hook detection
│   ├── chain_tracer.h/.c  # Hook chain tracing
│   ├── restore.h/.c       # Hook restoration
│   ├── wow64.h/.c         # WoW64 support
│   └── module_scorer.h/.c # Suspicion scoring
├── cli/
│   ├── main.c       # CLI entry point
│   └── args.c/.h    # Argument parsing (unit tested)
└── gui/
    ├── main.cpp             # GUI entry point + main loop
    ├── ui_process_tree.cpp  # Process tree panel
    ├── ui_module_list.cpp   # Module triage panel
    ├── ui_hook_list.cpp     # Hook list panel
    ├── ui_chain_view.cpp    # Chain viewer panel
    └── ui_restore.cpp       # Restore panel
```

### Scan pipeline

1. **Recon** — Enumerate process modules, score each for suspicion
2. **IAT Scan** — For each import, verify the function pointer points within the expected DLL's address range
3. **EAT Scan** — Compare in-memory export RVAs against on-disk export RVAs
4. **Inline Scan** — Disassemble first instructions of each exported function, compare against on-disk using Zydis
5. **Chain Tracing** — Follow JMP/CALL/PUSH+RET/MOV+JMP indirections to the final hook target

## License

MIT — see [LICENSE](LICENSE).
