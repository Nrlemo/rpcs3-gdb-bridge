# rpcs3-gdb-bridge (English summary)

Tools to debug a PS3 game in **RPCS3** through its (very limited) GDB server, and to analyze PS3 (PPC64) executables. Pure Python (standard library only). Documentation is in Spanish (`docs/`).

- **`proxy.py`** — persistent RSP proxy: keeps the single connection to RPCS3's GDB server alive (closing the client otherwise freezes the emulator), makes detach a no-op, serves clients one at a time, logs JSONL.
- **`bp_probe.py`** — `Z0` breakpoint probe: who writes/reads a field, with value, object and verified call chain; includes a watchdog for *silent stops* (a thread parks on a breakpoint and the server never says so).
- **`bp_preflight.py`** — preflight: does RPCS3 *really* stop on a `Z0`? An accepted `Z0` proves nothing (the server always answers `OK`; with the LLVM decoder it never stops). Puts a `Z0` on the thread's current PC, resumes and requires a genuine stop at that PC (plus a no-breakpoint control that must not stop). PASS / FAIL / INCONCLUSIVE (exit 0/1/3); a bare timeout is never FAIL. `bp_probe.py` runs it first and refuses to probe without PASS (`--ignore-preflight` overrides loudly). See `docs/bp_preflight.md`; tests are simulated, not run against a real RPCS3.
- **`opd_scan.py`** — finds indirect callers through function descriptors (OPD), vtables and constructed addresses.
- **`validate_server.py`, `check_decoder_z0.py`** — validation batteries against the real server. **`ghidra/FuncOf.java`** — containing function of an address (read-only).
- **`docs/servidor_gdb_rpcs3.md`** — what RPCS3's GDB server really supports (with evidence): only `Z0`; no `D`; default thread is the first PPU thread; with the LLVM decoder breakpoints are accepted but never hit.
- **`tools/check_no_game_data.py`** — leak scanner (working tree and full history) for game data.

Tested only with RPCS3 0.0.43 (build 20394), Ghidra 12.2 and Python 3.14.4. Run the tests with `python3 -I tests/run_all.py` (109 tests, none may be skipped). License: GPL-3.0; no RPCS3 code is copied.

Note: this repo was extracted from a game-translation project's history; old revisions contain address/offset constants of that binary, but no game data (checked across the full history).
