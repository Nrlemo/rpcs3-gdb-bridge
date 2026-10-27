# rpcs3-gdb-bridge

Herramientas para depurar un juego de PS3 en **RPCS3** a través de su servidor GDB (muy limitado) y para analizar ejecutables PS3 (PPC64): un **proxy RSP persistente**, un **sondeo con breakpoints** de accesos a un campo de un objeto, un **escáner de descriptores de función (OPD)** y un script de Ghidra.
Python puro (solo biblioteca estándar). English summary: [README.en.md](README.en.md).

> Estado: uso interno, en desarrollo; sin versión publicada. Probado únicamente con **RPCS3 0.0.43** (build 20394, commit `6110dbb2`, Linux), **Ghidra 12.2** y **Python 3.14.4**; otras versiones no se probaron.

## Qué hay
| Archivo | Para qué | Documentación |
|---|---|---|
| `gdbrsp.py` | cliente mínimo del protocolo GDB remoto (lectura de memoria, registros, `Z0`, pasos) | `docs/servidor_gdb_rpcs3.md` |
| `proxy.py`, `mock_rsp.py` | proxy que mantiene viva la única conexión al servidor (`D` = no-op, clientes en serie, registro JSONL) y servidor simulado para las pruebas | `docs/proxy.md` |
| `bp_probe.py` | sondeo con `Z0`: quién escribe/lee un campo, con valor, objeto y llamadores; vigía contra paradas silenciosas | `docs/bp_probe.md` |
| `validate_server.py`, `check_decoder_z0.py`, `attach_idle.py` | baterías de validación y controles contra el servidor real | `docs/proxy.md`, `docs/servidor_gdb_rpcs3.md` |
| `opd_scan.py` | llamadores indirectos por OPD / vtable / direcciones construidas | `docs/opd_scan.md` |
| `dbg_session.py` | sesión de depuración persistente por archivos (`in/`, `out/`, `done/`) | docstring |
| `ghidra/FuncOf.java` | función contenedora de una dirección, en modo solo lectura | `ghidra/README.md` |
| `tools/check_no_game_data.py` | escáner de fugas de datos de un juego (árbol e historial) | docstring |
| `docs/servidor_gdb_rpcs3.md` | **qué soporta realmente el servidor GDB de RPCS3** (con evidencia) | — |
| `docs/ghidra_trace_rmi.md`, `docs/metodo.md` | viabilidad de integrarlo con el depurador de Ghidra; lecciones de método | — |

## Inicio rápido
1. Ejecute RPCS3 con el servidor GDB activo (`GDB Server: 127.0.0.1:2345` en `config.yml`) y **`PPU Decoder: Interpreter (static)`** (con LLVM los `Z0` se aceptan pero no paran).
2. Con el programa ya en la pantalla que interesa: `python3 -I proxy.py` (conectar pausa el emulador).
3. Compruebe el servidor: `python3 -I validate_server.py salida.json --thread <id_hex> --elf programa.elf`.
4. Sondee unos sitios: `python3 -I bp_probe.py --elf programa.elf --sites examples/sitios.ejemplo.txt --out salida.jsonl --log RPCS3.log` (ver `docs/bp_probe.md`).

## Pruebas
```
python3 -I tests/run_all.py --min-tests 60
```
Corre cada suite en su proceso y **falla si algún test se omite**: ninguna depende de un programa real (hay un ELF sintético en `tests/fixtures/`). Estado actual: 77 tests (proxy 18, bp_probe 24, opd_scan 11, herramientas 9, escáner de fugas 15).

## Aviso sobre el historial
Este repo se extrajo del historial de un proyecto de traducción de un juego de PS3 (se conservaron los commits de estos archivos y se reescribieron sus mensajes). **Las versiones antiguas del código contienen constantes de ese binario** (direcciones y offsets de funciones y estructuras), no datos del juego: no hay ejecutables, volcados, capturas ni texto del juego en ninguna revisión (comprobado con `tools/check_no_game_data.py`: árbol y todos los blobs del historial). El estado actual no contiene esas constantes. El autor de los commits figura con su nombre y correo.

## Usar como submódulo
Los scripts insertan su propio directorio en `sys.path` (necesario con `python3 -I`), por lo que se puede montar en cualquier carpeta (por ejemplo `tools/rpcs3_bridge/`) y invocar con la ruta del script.

## Licencia
GPL-3.0 (ver `LICENSE`). Se describe el protocolo y el comportamiento observado de RPCS3 y se citan sus archivos y líneas, pero **no se copia código de RPCS3**. No soy abogado: confirme la compatibilidad de licencias antes de publicar o redistribuir.
