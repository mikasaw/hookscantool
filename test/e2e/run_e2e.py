#!/usr/bin/env python3
"""End-to-end test driver for HookScanTool.

Builds nothing itself — point it at a built CLI and the e2e fixture dir:

    python test/e2e/run_e2e.py --cli build-msvc/Release/hookscan_cli.exe \
                               --fixture build-msvc/Release

Fixture binaries (e2e_target.exe + e2e_hook.dll) are produced with
-DHOOKSCAN_BUILD_E2E=ON. The script:

  1. starts e2e_target (it loads e2e_hook.dll, which installs an EAT,
     IAT and inline hook inside its own process),
  2. scans it with the CLI and validates all three hooks are detected,
  3. restores the inline hook (MulDiv) and verifies it is gone,
  4. checks the target survived the whole round trip.
"""
import argparse
import json
import subprocess
import sys
import time
import ctypes
from pathlib import Path

kernel32 = ctypes.windll.kernel32


def fail(msg):
    print(f"E2E FAIL: {msg}")
    sys.exit(1)


def process_alive(pid):
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    code = ctypes.c_ulong()
    ok = kernel32.GetExitCodeProcess(h, ctypes.byref(code))
    kernel32.CloseHandle(h)
    return bool(ok) and code.value == STILL_ACTIVE


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", required=True, help="path to hookscan_cli.exe")
    ap.add_argument("--fixture", required=True, help="dir with e2e_target.exe + e2e_hook.dll")
    args = ap.parse_args()

    cli = Path(args.cli).resolve()
    fixture = Path(args.fixture).resolve()
    if not cli.exists():
        fail(f"CLI not found: {cli}")
    if not (fixture / "e2e_target.exe").exists():
        fail(f"e2e_target.exe not found in {fixture}")

    tmp_json = Path(tempfile_path())
    proc = subprocess.Popen(
        [str(fixture / "e2e_target.exe")],
        cwd=str(fixture), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    try:
        # wait for READY line
        pid = None
        deadline = time.time() + 10
        while time.time() < deadline and pid is None:
            line = proc.stdout.readline()
            if line.startswith("READY"):
                pid = int(line.split("pid=")[1].split()[0])
            elif line.strip():
                print("[target]", line.strip())
        if pid is None:
            fail("target never became READY")

        print(f"[e2e] target pid={pid}")

        # 1) scan
        r = subprocess.run(
            [str(cli), str(pid), "--json", str(tmp_json)],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            fail(f"scan failed:\n{r.stdout}\n{r.stderr}")
        report = json.loads(tmp_json.read_text(encoding="utf-8"))
        hooks = report.get("hooks", [])
        print(f"[e2e] scan found {len(hooks)} hooks")

        def find(pred, what):
            for i, h in enumerate(hooks):
                if pred(h):
                    print(f"[e2e] detected {what}: #{i} {h['module']}!{h['function']} ({h['type']})")
                    return i
            fail(f"{what} NOT detected")

        eat_idx = find(
            lambda h: h["type"] == "EAT" and "hook_dll" in h["module"].lower()
            and "marker" in h["function"].lower(),
            "EAT hook (e2e_marker_export)")
        iat_idx = find(
            lambda h: h["type"] == "IAT" and h["function"].lower() == "lstrlenw",
            "IAT hook (lstrlenW)")
        inline_idx = find(
            lambda h: h["type"] == "INLINE" and h["function"].lower() == "muldiv",
            "inline hook (MulDiv)")
        del eat_idx, iat_idx

        apiset_idx = find(
            lambda h: h["type"] == "IAT" and h["module"].lower().startswith("api-ms-")
            and h["function"].lower() == "_initterm",
            "api-set hijack (_initterm)")
        del apiset_idx

        if not hooks[inline_idx].get("restorable", False):
            fail("inline hook is not marked restorable")

        # 2) restore the inline hook
        r = subprocess.run(
            [str(cli), str(pid), "--restore", str(inline_idx)],
            input="y\n", capture_output=True, text=True, timeout=120,
        )
        if "restored successfully" not in r.stdout:
            fail(f"restore failed:\n{r.stdout}\n{r.stderr}")
        print("[e2e] inline hook restored")

        # 3) rescan: MulDiv hook must be gone, others must remain
        tmp_json2 = Path(tempfile_path())
        r = subprocess.run(
            [str(cli), str(pid), "--json", str(tmp_json2)],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            fail(f"rescan failed:\n{r.stdout}\n{r.stderr}")
        hooks2 = json.loads(tmp_json2.read_text(encoding="utf-8")).get("hooks", [])
        still = [h for h in hooks2
                 if h["type"] == "INLINE" and h["function"].lower() == "muldiv"]
        if still:
            fail("inline MulDiv hook still present after restore")
        if not any(h["type"] == "IAT" and h["function"].lower() == "lstrlenw" for h in hooks2):
            fail("IAT hook disappeared unexpectedly")
        print(f"[e2e] rescan clean: {len(hooks2)} hooks remain, MulDiv gone")

        # 4) target still alive?
        if not process_alive(pid):
            fail("target process died during the round trip")
        print("[e2e] target survived — PASS")
    finally:
        proc.kill()
        tmp_json.unlink(missing_ok=True)
        Path(tempfile_path(second=True)).unlink(missing_ok=True)


def tempfile_path(second=False):
    import tempfile
    return Path(tempfile.gettempdir()) / f"hookscan_e2e_{'b' if second else 'a'}.json"


if __name__ == "__main__":
    main()
