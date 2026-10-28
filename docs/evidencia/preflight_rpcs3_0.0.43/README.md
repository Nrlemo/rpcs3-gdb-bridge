# Evidencia: `bp_preflight.py` contra RPCS3 0.0.43 (intérprete frente a LLVM)

Informe de las corridas reales del 2026-10-27/28. **Muestra chica y sin base estadística: no estima tasas de falsos positivos ni negativos.** Nada se probó en hardware.

**Sobre las direcciones:** los PC concretos son del ejecutable de un juego y este repo público no los contiene (ver `README.md`, «Aviso sobre el historial», y `tools/check_no_game_data.py`).
Aquí se usan las etiquetas `PC-A`…`PC-H`. Los originales (salidas del preflight, registros JSONL del proxy, los cuatro `RPCS3.log` finales comprimidos y sus hashes) están en el
repo del proyecto que consume el bridge (`docs/evidencia/preflight_bp/`), no aquí. Para reproducirlo con otro juego, los comandos están en `docs/bp_preflight.md`.

## Configuración
- RPCS3 0.0.43 (build 20394, commit `6110dbb2`, AppImage, Linux), headless (Weston + Xwayland, Vulkan), SPU Decoder LLVM, servidor GDB `127.0.0.1:2345`, `proxy.py` en `:2346`.
- Variable estudiada: **PPU Decoder** = `Interpreter (static)` o `Recompiler (LLVM)`. Un arranque por tanda, hilo `GameThread`, un solo momento del juego (~1 min tras el arranque; pantalla no identificada).
- `bp_preflight.py --log … --timeout 8` (más `--attempts 3` en las tandas 3 y 4), una corrida tras otra; control sin breakpoint de 1 s. Python 3.14.4.

## Tandas y código del bridge
| Tanda | Decoder | Corridas | Código del bridge |
|---|---|---|---|
| 1 | LLVM | 3 | `34c1584` (sin reintento) |
| 2 | Intérprete | 3 | `34c1584` (sin reintento) |
| 3 | Intérprete | 6 | `11df8a9` (reintento avanzando con `s`; **retirado**) |
| 4 | LLVM | 6 | `11df8a9` (ídem) |

Las tandas 3 y 4 usaron un reintento que avanzaba el hilo con `s`. Esa lógica se sustituyó por la de `docs/bp_preflight.md` (otra dirección de retorno validada, sin `s`). El primer intento
de todas las tandas es el mismo; **el reintento actual no corrió en ninguna**.

## Resultados por corrida
| Tanda | # | PC | Veredicto | Evidencia en la salida |
|---|---|---|---|---|
| 1 LLVM | 1 | PC-A | **FAIL** | el hilo ejecutó esa instrucción con `Z0` puesto y siguió sin parar (PC distinto al interrumpir) |
| 1 LLVM | 2 | PC-B | **FAIL** | ídem |
| 1 LLVM | 3 | PC-A | INCONCLUSIVE | 8 s sin parada y el hilo seguía en el mismo PC |
| 2 Interp. | 1 | PC-C | INCONCLUSIVE | 8 s sin parada, PC sin cambios |
| 2 Interp. | 2 | **PC-A** | **PASS** | `Z0` aceptado, parada con señal 05 en el mismo PC, control sin parada |
| 2 Interp. | 3 | PC-D | INCONCLUSIVE | 8 s sin parada, PC sin cambios |
| 3 Interp. | 1–6 | PC-E, PC-A ×4, PC-F | 6 × **PASS** | igual que la corrida 2 de la tanda 2; 0 reintentos |
| 4 LLVM | 1, 3, 4, 5 | PC-D, PC-B, PC-D, PC-A | 4 × **FAIL** | el hilo avanzó sin parar |
| 4 LLVM | 2 | PC-B → PC-E | **FAIL** | intento 1 INCONCLUSIVE; paso con `s` (retirado); intento 2 FAIL |
| 4 LLVM | 6 | PC-G → PC-H | **FAIL** | ídem |

## Comparación
| | LLVM (tandas 1 y 4) | Intérprete (tandas 2 y 3) |
|---|---|---|
| Corridas | 9 | 9 |
| PASS | 0 | 7 |
| FAIL | 8 (2 de ellos tras el reintento con `s`, retirado) | 0 |
| INCONCLUSIVE | 1 | 2 |

- **El mismo PC (PC-A) dio resultados opuestos según el decoder:** con LLVM, FAIL (tanda 1, corrida 1) e INCONCLUSIVE (tanda 1, corrida 3); con el intérprete, PASS (tanda 2, corrida 2 y cuatro veces en la tanda 3).
- Es el patrón que predice el código de RPCS3 (`ppu_breakpoint` rechaza LLVM; `servidor_gdb_rpcs3.md`, regla 3), pero **no lo demuestra** con esta muestra.
- Ningún PASS con LLVM y ningún FAIL con el intérprete en estas 18 corridas. Eso no establece una tasa de falsos positivos.

## Evidencia de protocolo (del registro del proxy)
| Tanda | `Z0` | `z0` | `vCont;c` | `vCont;s` |
|---|---|---|---|---|
| 1 | 3 | 3 | 6 | 0 |
| 2 | 3 | 3 | 7 | 0 |
| 3 | 6 | 6 | 18 | 0 |
| 4 | 8 | 8 | 14 | 2 |

Cada `Z0` tiene su `z0`; el número de `vCont;c` es coherente con el ciclo de cada corrida (prueba, control si hubo parada, reanudación final). **No disponible:** el paquete de parada de cada PASS
de las tandas 1–2 (el código de entonces no lo imprimía; consta en el JSONL del proxy sin atribución por corrida) ni el PC tras la parada. No se registraron los PC de los demás hilos.
Los cuatro `RPCS3.log` finales se revisaron solo con `grep`: 0 `Access violation` y 0 `frozen` en cada uno; no se leyeron enteros y no están en este repo.

## Confirmado / hipótesis / pendiente
- **Confirmado (n chico):** el veredicto de cada corrida, la coherencia de los paquetes `Z0`/`z0`/`vCont`, y que un PASS exigió parada con señal 05 en el PC más control sin parada.
- **Hipótesis:** los INCONCLUSIVE del intérprete son paradas silenciosas o un hilo bloqueado (el protocolo no los distingue); el resultado del intérprete depende del momento de ejecución (1/3 PASS en la
  tanda 2, 6/6 en la 3).
- **Pendiente:** correr contra RPCS3 real el reintento actual (`bp_probe.make_alternates`); otros hilos y pantallas; más corridas.
