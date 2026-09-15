# HookScanTool

**Windows Process Hook Scanner** — Detects IAT, EAT, and inline hooks in running Windows processes.

![GUI Screenshot](docs/screenshot.png)

## Overview

HookScanTool is a Windows security/malware analysis tool that scans running processes for API hooks. It detects three types of hooks:

- **IAT Hooks** — Import Address Table tampering (function pointers redirected to different modules)
- **EAT Hooks** — Export Address Table tampering (exported function RVAs modified in memory)
- **Inline Hooks** — Function prologue patching (JMP/CALL/PUSH+RET/MOV+JMP to another module)

The tool compares each function's in-memory code against the on-disk DLL, using Zydis for instruction-level disassembly. Hook chains are traced through multiple JMP/CALL indirections to reveal the final target.

## Features

- **GUI Mode** — Dear ImGui + DirectX 11 interface with process tree, module triage panel, hook list, chain viewer, and one-click restore
- **CLI Mode** — Command-line scanning with JSON output and automated restore
- **Selective Scanning** — Recon module list with suspicion scores, scan only suspicious modules
- **Module Triage** — Suspicion scoring system (path, name, WoW64 heuristics)
- **Hook Chain Tracing** — Follows JMP/CALL/PUSH+RET/MOV+JMP chains to final hook target
- **Hook Restoration** — Thread-safe restore with thread suspension and TOCTOU verification
- **WoW64 Support** — Scan 32-bit processes from a 64-bit scanner via `NtWow64ReadVirtualMemory64`
- **JSON Export** — Full scan report in JSON format for scripted analysis

## Building

### Requirements

- **Compiler**: MinGW-w64 (GCC) or MSVC 2022
- **CMake**: 3.20+
- **Dependencies**: Zydis 4.0.0 + Zycore, Dear ImGui 1.91.8 (included in `deps/`)

### Build (MinGW)

```bash
mkdir -p build && cd build
cmake .. -G "MinGW Makefiles"
mingw32-make -j4
```

### Build (MSVC)

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
# Open the .sln in Visual Studio or run:
cmake --build . --config Release
```

### Output

| Target | Path | Description |
|--------|------|-------------|
| `hookscan_cli.exe` | `build/hookscan_cli.exe` | Command-line tool |
| `hookscantool.exe` | `build/hookscantool.exe` | GUI application |

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
hookscan_cli.exe 1234 --modules           # find the module index
hookscan_cli.exe 1234 --scan-module 5      # scan module index 5

# Restore a detected hook
hookscan_cli.exe 1234 --restore 0          # restore hook #0
```

## Architecture

```
src/
├── engine/          # Core scanner engine (pure C)
│   ├── engine.h/.c  # Public API: scan, recon, restore
│   ├── types.h      # Shared type definitions
│   ├── pe_parser.h/.c     # PE header parsing (in-memory + on-disk)
│   ├── process.h/.c       # Process/module enumeration
│   ├── iat_scanner.h/.c   # IAT hook detection
│   ├── eat_scanner.h/.c   # EAT hook detection
│   ├── inline_scanner.h/.c # Inline hook detection
│   ├── chain_tracer.h/.c  # Hook chain tracing
│   ├── restore.h/.c       # Hook restoration
│   ├── wow64.h/.c         # WoW64 support
│   └── module_scorer.h/.c # Suspicion scoring
├── cli/
│   └── main.c       # CLI entry point
└── gui/
    ├── main.cpp             # GUI entry point + main loop
    ├── ui_process_tree.cpp  # Process tree panel
    ├── ui_module_list.cpp   # Module triage panel
    ├── ui_hook_list.cpp     # Hook list panel
    ├── ui_chain_view.cpp    # Chain viewer panel
    └── ui_restore.cpp       # Restore panel
```

### Scan Pipeline

1. **Recon** — Enumerate process modules, score each for suspicion
2. **IAT Scan** — For each import, verify the function pointer points within the expected DLL's address range
3. **EAT Scan** — Compare in-memory export RVAs against on-disk export RVAs
4. **Inline Scan** — Disassemble first instructions of each exported function, compare against on-disk using Zydis
5. **Chain Tracing** — Follow JMP/CALL/PUSH+RET/MOV+JMP indirections to the final hook target

### Suspicion Scoring

| Criterion | Points |
|-----------|--------|
| Module not in Windows/Program Files | +30 |
| Suspicious name (hook, inject, patch, etc.) | +40 |
| WoW64 DLL in 64-bit process | +20 |

Score 0-30: Low risk | 31-60: Suspicious | 61-80: High | 81-100: Critical

## Error Codes

| Code | Meaning |
|------|---------|
| `ENGINE_OK` (0) | Success |
| `ENGINE_ACCESS_DENIED` (-1) | Cannot open process (run as Admin) |
| `ENGINE_PROCESS_NOT_FOUND` (-2) | Process or modules not found |
| `ENGINE_READ_ERROR` (-3) | Memory read failure |
| `ENGINE_WRITE_ERROR` (-4) | Memory write failure |
| `ENGINE_PACKED_DLL` (-5) | DLL is packed/crunched |
| `ENGINE_NO_MEMORY` (-6) | Out of memory |
| `ENGINE_SCAN_FAILED` (-7) | General scan failure |

## License

MIT
