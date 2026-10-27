# Integración con el depurador de Ghidra: viabilidad

Informe de viabilidad (solo lectura de la instalación; **no se abrió Ghidra con interfaz ni se conectó nada**). Ghidra 12.2 PUBLIC (build 2026-10-16), Python 3.14.4, RPCS3 0.0.43.

## Veredicto
| Opción | Viabilidad | Esfuerzo (estimación) | Recomendación |
|---|---|---|---|
| **A. Importar la RAM a un programa de Ghidra por script** | Alta (la API existe) | pequeño: 1 script + un manifiesto | hacer primero |
| **B. Agente Trace RMI propio (Python + `ghidratrace`)** | Media, **sin probar** | grande (2-3 sesiones) y solo probable con la interfaz gráfica | postergar |
| **C. Agente oficial `ghidragdb` vía gdb** | Baja | pequeño en código, grande en incertidumbre | descartar por ahora |

## Lo verificado
- Ghidra 12.2 trae el módulo `Debugger-rmi-trace` con el paquete Python `ghidratrace` (cliente del protocolo) y sus dependencias como wheels (`ghidratrace-12.2`, `protobuf-6.31.0`). **Importa sin instalar nada** con el Python del sistema (añadiendo las wheels a `sys.path`): expone `Client`, `Trace`, `RegVal`, `Address`, `AddressRange` (solo importa; no se abrió ninguna conexión).
- API de cliente relevante: `Client.create_trace(path, language, compiler)`, `Trace.put_bytes`, `put_registers`, `set_memory_state`, `snapshot`, `create_root_object` y un `MethodRegistry` para exponer métodos que Ghidra invoca. Del lado de Ghidra, `ListenTraceRmiScript.java` / `ConnectTraceRmiScript.java` abren el aceptador; el contrato de métodos se ve en el agente de gdb (`resume`, `interrupt`, `step_into`, `read_mem`, breakpoints...; `read_mem` se invoca **bajo demanda**).
- **El agente oficial de gdb (opción C) no sirve hoy:** `gdb`/`gdb-multiarch` no estaban instalados; RPCS3 no ofrece `target.xml` (gdb adivina el diseño de registros) y el asignador de lenguaje del agente traduce `powerpc:common64` a `PowerPC:BE:64:64-32addr`/`default`, que **no coincide** con el lenguaje con el que se suele importar un binario de PS3 (`PowerPC:BE:64:A2ALT-32addr`) → desajuste con el programa estático.
- Lenguaje `A2ALT-32addr`: registros `pc`, `MSR`, `cr0..cr7` (1 byte) y `crall`, partes de `xer`; RPCS3 entrega CR como un `u32` y MSR/XER/FPSCR como «no disponible» (habría que partir CR y omitir esos tres).
- API de memoria de Ghidra 12.2 (`javap` sobre `ghidra.program.model.mem.Memory`): `createInitializedBlock(String, Address, InputStream, long, TaskMonitor, boolean)`, `createUninitializedBlock(...)`, `convertToInitialized(MemoryBlock, byte)` y `setBytes(Address, byte[])`.

## Opción A: diseño propuesto (no implementado)
Un script de Ghidra que lee un manifiesto `[{"base": "0x...", "file": "..."}]` y, por tramo: si cae sobre un bloque sin inicializar (p. ej. el `.bss`) → `convertToInitialized` + `setBytes`; si no hay bloque (heap) → `createInitializedBlock`. **Verificación previa obligatoria:** comparar el tramo que solapa código o datos de solo lectura con los bytes del programa y abortar si difieren (comprueba que el volcado es del mismo programa). Trabajar sobre una **copia** del proyecto. Con los resultados de `opd_scan.py --raw` se pueden crear referencias desde cada puntero hallado hasta la función. Riesgos: tamaño (volcar solo lo relevante), ruido, y que el volcado exige el emulador detenido.

## Opción B: qué implicaría y cuándo reconsiderarla
Hablar RSP con el proxy y `ghidratrace` hacia Ghidra en el mismo proceso; crear la traza con el lenguaje del programa; esquema de objetos mínimo (sesión → proceso → hilos/registros/memoria, partiendo del `schema.xml` del agente de gdb); métodos `resume`, `interrupt`, `step_into`, `read_mem`, alta/baja de `Z0`; un hilo que espere las paradas del servidor; respetar las reglas del servidor (memoria solo con el emulador detenido; `Z0` solo con el intérprete; paradas silenciosas, ver `servidor_gdb_rpcs3.md`).
**No probado:** ninguna conexión real con Ghidra (sin pantalla en el entorno de la prueba y sin modo headless equivalente para el aceptador); que el mapeo estático↔dinámico sea trivial (hipótesis: si el ejecutable se carga en su `p_vaddr` debería ser un mapeo idéntico); la estabilidad del protocolo entre versiones.
**Criterio:** reconsiderarla cuando (1) `validate_server.py` confirme que `Z0` para y reanuda, (2) `bp_probe.py` dé paradas fiables y (3) haga falta inspeccionar estados repetidamente en vez de volcar una vez.
