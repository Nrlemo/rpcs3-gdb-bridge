# El servidor GDB de RPCS3: qué soporta realmente

Versión estudiada: **RPCS3 0.0.43, build 20394, commit `6110dbb2`** (Linux, AppImage). Las referencias `archivo:línea` son del repo de RPCS3 en ese commit
(`rpcs3/Emu/GDB.cpp` salvo que se diga otra cosa). Los archivos relevantes eran idénticos en el `master` del 2026-10-27 (diff vacío).
**Nivel de evidencia:** *[F]* leído en el código fuente; *[R]* observado en ejecuciones reales de esa versión; *[H]* hipótesis. Con otras versiones no se probó.

## Paquetes (RSP)
| Paquete | Estado | Evidencia |
|---|---|---|
| `qSupported` | responde solo `PacketSize=1200` (hexadecimal); no anuncia `qXfer`, `swbreak`, etc. | [F] 565-568 |
| `qXfer` / `target.xml` | **no existe** | [F] 1031-1048 |
| `vCont?` / `vCont` | anuncia `vCont;c;s;C;S`, pero solo implementa `c` y `s` sin señal | [F] 839-909 |
| `c`, `s` planos, `D`, `T`, `vKill` | **no existen** (respuesta vacía); no se probó el `c` plano contra el servidor real | [F] 1031-1054 |
| `g` / `G`, `p` / `P` | sí (ver «Registros») | [F] 595-655, 734-797; [R] longitud 1112 |
| `m` | sí; no respeta `PacketSize`; corta en la primera dirección inválida; **solo con el emulador detenido** | [F] 657-689 |
| `M` | sí; exige página escribible | [F] 691-732 |
| `Z0` / `z0` | aceptado; sin condiciones | [F] 913-969 |
| `Z1`, `Z2`, `Z3`, `Z4` | **no**: respuesta vacía (no hay watchpoints) | [F] 940-941 |
| `k` | apaga el emulador (`GracefulShutdown`) y no responde | [F] 832-837 |
| `H` | sí; el hilo por defecto es **el primer hilo PPU**, normalmente no el del programa | [F] 420-435, 799-824; [R] 33 hilos en una corrida |

## Reglas que importan en la práctica
1. **Conectar pausa el emulador** [F 1011-1015, R]. Solo `vCont;c|s` lo reanuda [F 887-890]; lo único que reanuda es ese paquete.
2. **Cerrar el socket congela el emulador**: `D` no existe, y cuando `recv` devuelve 0 `read_char()` lanza una excepción sin captura (`GDB.cpp:237-241`; no hay `try/catch` en `operator()` ni en el hilo) [F]. Se observó «Emulation has been frozen!» [R]. El mecanismo exacto entre la excepción y ese mensaje es [H]. Solución: `proxy.py`.
3. **Un `Z0` aceptado no garantiza nada**: `cmd_set_breakpoint` ignora el valor de retorno de `ppu_breakpoint` y contesta `OK` siempre [F 937-938]. `ppu_breakpoint` devuelve `false` sin hacer nada si la dirección no está alineada, no es ejecutable, el opcode no coincide o **el decoder PPU es LLVM** [F `Emu/Cell/PPUThread.cpp` 1234-1237]. [R] Con LLVM los `Z0` nunca pararon (muestra pequeña, n=2 direcciones × 20 s) y con el intérprete sí, en las mismas direcciones.
4. **Continuar sin quitar el `Z0` vuelve a parar en la misma instrucción** [R, 0,08 s]. El patrón válido es: parada → leer → quitar `Z0` → un paso → reponer `Z0` → continuar (5 de 5 ciclos en dos direcciones). Es lo que hace el depurador Qt de RPCS3.
5. **Paradas silenciosas** [R]: un hilo puede alcanzar un `Z0`, quedar parado y **el servidor no comunica la parada** (el cliente espera para siempre; el emulador consume CPU y el programa se queda quieto). Se vio en un sitio concreto (4 de 4 comprobaciones), y otras paradas sí se comunicaron. No se sabe por qué. Pista no verificada: `pause_from` sale sin avisar si `paused` ya vale `true` (`GDB.cpp:1062-1071`) [H]. Mitigación: interrumpir (`0x03`) tras N segundos sin parada y mirar el PC del hilo (`bp_probe.py --watchdog`).
6. **Un paso (`s`) sobre un hilo bloqueado no termina** [R, 20 s]: poner siempre un tiempo máximo.
7. **El hilo que cuenta hay que elegirlo**: `Hg<id>` / `Hc<id>` tras `qfThreadInfo`. El id del hilo principal cambia entre arranques (en el log: `PPU[0x…] Thread (GameThread)`).

## Registros (`g`)
71 registros concatenados en hexadecimal [F 744-753, 437-466]: `r0-r31` (8 B) · `f0-f31` (8 B) · `pc` · `msr` (**siempre `xx…`**) · `cr` (4 B) · `lr` · `ctr` · `xer` (**`xx`**, 4 B) · `fpscr` (**`xx`**, 4 B). Total **1112 caracteres** (556 B) [R]. `pc`, `lr` y `r2` se verificaron por su efecto (el PC avanza +4 por paso; `lr` = dirección de retorno). `cr` y `ctr` no se verificaron. Compatibilidad con la tabla de `powerpc:common64` de gdb: **no verificada** (no hay `target.xml`).

## Rendimiento medido [R]
Coste fijo por paquete ≈ 41 ms medido (el cliente activa `TCP_NODELAY` por el retardo de Nagle); lectura con `m`: 4 KiB ≈ 0,1 MiB/s, 64-256 KiB ≈ 28 MiB/s, 1 MiB ≈ 17 MiB/s, 4 MiB ≈ 6,6 MiB/s (óptimo 256 KiB). Cada impacto de un sondeo con `Z0` cuesta ~0,5 s (varios viajes: registros, memoria, quitar, paso, reponer; n=4); un sitio que se ejecuta por fotograma frena el programa a menos de 2 impactos por segundo: `Z0` es para sitios raros.

## Depurador integrado (Qt) y watchpoints
- Existe un «break on memory read/write» **solo si RPCS3 se compila con `-DHAS_MEMORY_BREAKPOINTS=ON`** (`CMakeLists.txt:61`, por defecto **OFF**) y solo en el intérprete PPU [F]. Con la opción apagada el diálogo de breakpoints solo ofrece «Execution» (`rpcs3qt/debugger_add_bp_window.cpp:37-47`) [F].
- El AppImage 0.0.43 **no lo trae**: faltan en el binario las cadenas que dependen de la opción (`Memory Read`, `Memory Write`, `Enable BPM`, `breakpoint reading/writing`), mientras que las que no dependen (`BPMRW: 0x%1`, `PacketSize`, `vCont;c;s;C;S`) sí están [R, inferencia por ausencia de cadenas; confirmarlo mirando la interfaz].
- «Cheat Search» / «Memory Viewer» **no tienen** ningún hook de acceso: la búsqueda de valores es por sondeo (`rpcs3qt/cheat_manager.cpp:307-373`) [F].
- Añadir `Z2/Z3/Z4` al servidor exigiría compilar un RPCS3 propio con la opción activada, mapear los tipos a `bp_read`/`bp_write`, activar el interruptor «break on BPM» (`PPUInterpreter.cpp:30-33`), expandir la longitud (la coincidencia es por dirección exacta, `breakpoint_handler.cpp:15-23`) y reportar la dirección en la parada. Estimación [H]: decenas de líneas, pero grande en logística. No se implementó.
