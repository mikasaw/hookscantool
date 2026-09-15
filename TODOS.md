# TODOS

## DONE: CLI module listing and selective scanning
- `--modules` flag — prints module list with suspicion scores (supports `--filter s|a|m`)
- `--scan-module <n>` flag — scan specific module by index
- `--version` flag — version info
- `--help` updated with all new flags

## Future
- Add `--watch` mode: poll processes at interval, flag new hooks
- Add `--deep` scan: scan all processes, not just specified PID
- Add export to CSV/SARIF for CI pipeline integration
- Add signature-based detection: known hook DLL hashes