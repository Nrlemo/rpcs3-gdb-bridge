# Cambios

## Sin publicar
- `bp_preflight.py`: verificación previa de breakpoints (PASS / FAIL / INCONCLUSIVE) con reintento acotado en otra dirección de retorno validada contra el ELF (sin `s`, sin cambiar de hilo; un reintento solo da PASS o INCONCLUSIVE) y registro por intento. `bp_probe.py` no sondea sin PASS (`--preflight-timeout`, `--preflight-attempts`, `--ignore-preflight`) y copia los intentos al evento `inicio`. `mock_rsp.py`: opciones de prueba opcionales (apagadas por defecto). 53 tests simulados; informe de corridas reales en `docs/evidencia/preflight_rpcs3_0.0.43/` (muestra chica; el reintento actual sin probar contra RPCS3 real).

## v0.1.0 (2026-10-27)
- Proxy RSP persistente y servidor simulado (`proxy.py`, `mock_rsp.py`).
- Cliente RSP (`gdbrsp.py`) y sesión persistente (`dbg_session.py`).
- Sondeo con `Z0` (`bp_probe.py`): sitios `stb`/`lbz`/`ld`, filtro opcional por vtable, vigía contra paradas silenciosas (por defecto 5 s), volcados, etiquetas de ruta.
- Escáner de descriptores de función (`opd_scan.py`) con varias bases de TOC.
- Baterías de validación (`validate_server.py`, `check_decoder_z0.py`) y `attach_idle.py`.
- `ghidra/FuncOf.java`, `tools/check_no_game_data.py`, documentación y 77 tests.
- Generalización respecto del proyecto de origen: sin constantes de un juego en el código (se pasan por `--object-vtable`, `--field-offset`, `--thread-name`, `--elf`/`--code`/`--toc`).
