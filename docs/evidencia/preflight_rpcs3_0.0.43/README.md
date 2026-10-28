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
| 5 | Intérprete | 6 | `d5d5b92` (reintento actual; `--elf`) |
| 6 | LLVM | 6 | `d5d5b92` (ídem) |

Las tandas 3 y 4 usaron un reintento que avanzaba el hilo con `s`. Esa lógica se sustituyó por la de `docs/bp_preflight.md` (otra dirección de retorno validada, sin `s`). El primer intento
de todas las tandas es el mismo; el reintento actual (tandas 5 y 6) se ejecutó con `--elf` (el ELF original descifrado).

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
| 5 Interp. | 1–6 | PC-A ×6 | 6 × **PASS** | 0 reintentos |
| 6 LLVM | 1, 2, 4, 5, 6 | PC-K, PC-A, PC-A, PC-A, PC-F | 5 × **FAIL** | el hilo avanzó sin parar |
| 6 LLVM | 3 | PC-D → PC-I (LR) → PC-J (retorno 1) | INCONCLUSIVE | **3 intentos** sin parada en 8 s; limpieza correcta en cada uno; límite de intentos alcanzado; sin `s` ni cambio de hilo |

## Comparación
| | LLVM (tandas 1 y 4) | Intérprete (tandas 2 y 3) |
|---|---|---|
| Corridas (tandas 1–6) | 15 | 15 |
| PASS | 0 | 13 |
| FAIL | 13 (2 de ellos tras el reintento con `s`, retirado) | 0 |
| INCONCLUSIVE | 2 | 2 |

- **El mismo PC (PC-A) dio resultados opuestos según el decoder:** con LLVM, FAIL (tanda 1, corrida 1) e INCONCLUSIVE (tanda 1, corrida 3); con el intérprete, PASS (tanda 2, corrida 2; cuatro veces en la tanda 3; seis en la tanda 5). Con LLVM, la tanda 6 repitió FAIL en PC-A (3 de 3).
- Es el patrón que predice el código de RPCS3 (`ppu_breakpoint` rechaza LLVM; `servidor_gdb_rpcs3.md`, regla 3), pero **no lo demuestra** con esta muestra.
- Ningún PASS con LLVM y ningún FAIL con el intérprete en estas 30 corridas. Eso no establece una tasa de falsos positivos.

## Evidencia de protocolo (del registro del proxy)
| Tanda | `Z0` | `z0` | `vCont;c` | `vCont;s` |
|---|---|---|---|---|
| 1 | 3 | 3 | 6 | 0 |
| 2 | 3 | 3 | 7 | 0 |
| 3 | 6 | 6 | 18 | 0 |
| 4 | 8 | 8 | 14 | 2 |
| 5 | 6 | 6 | 18 | 0 |
| 6 | 8 | 8 | 14 | 0 |

Cada `Z0` tiene su `z0`; el número de `vCont;c` es coherente con el ciclo de cada corrida (prueba, control si hubo parada, reanudación final). **No disponible:** el paquete de parada de cada PASS
de las tandas 1–2 (el código de entonces no lo imprimía; consta en el JSONL del proxy sin atribución por corrida) ni el PC tras la parada. No se registraron los PC de los demás hilos.
Los seis `RPCS3.log` (cuatro finales del proceso y dos copias tomadas al terminar las corridas de las tandas 5 y 6) se revisaron solo con `grep`: 0 `Access violation` y 0 `frozen` en cada uno; no se leyeron enteros y no están en este repo.

## Confirmado / hipótesis / pendiente
- **Confirmado (n chico):** el veredicto de cada corrida, la coherencia de los paquetes `Z0`/`z0`/`vCont`, y que un PASS exigió parada con señal 05 en el PC más control sin parada.
- **Hipótesis:** los INCONCLUSIVE del intérprete son paradas silenciosas o un hilo bloqueado (el protocolo no los distingue); el resultado del intérprete depende del momento de ejecución (1/3 PASS en la
  tanda 2, 6/6 en la 3).
- **Confirmado (tandas 5–6, n=12):** el reintento actual se ejecutó una vez en RPCS3 real (LLVM): 3 intentos, todos INCONCLUSIVE, limpieza correcta, sin `s`.
- **Pendiente:** un reintento real que termine en PASS (no reproducible hasta ahora; ver la tanda 7); otros hilos y pantallas; más corridas; registrar la instrucción del PC en cada intento para poder correlacionar con `sc`.

## Tanda 7 (2026-10-28): muestreo amplio del intérprete y experimento de memoria
**Objetivo:** comprobar si la ruta «INCONCLUSIVE por PC sin cambios → reintento → PASS» aparece de forma natural, sin tocar RPCS3 ni relajar criterios.
**Método:** un arranque con el intérprete, `bp_preflight.py --elf <ELF original> --timeout 8 --attempts 3 --json`, **101 corridas** seguidas entre `t+18 s` y `t+495 s` desde que apareció `GameThread`. Código: `add003a` más `--json`
y el arreglo de Ctrl-C (este último aplicado mientras corría; no altera el camino normal). Contexto: arranque en frío; a ~60 s el vídeo de logos y a ~400 s una escena con cuadro de diálogo (no se sabe si es modo demostración).

| Resultado | Corridas |
|---|---|
| PASS en el primer intento | 97 (25 PC distintos) |
| INCONCLUSIVE: PC fuera del código del ELF (sin `Z0` puesto, no reintentable) | 4 |
| INCONCLUSIVE por PC sin cambios | **0** |

**La ruta INCONCLUSIVE → reintento → PASS no se ha demostrado en RPCS3 real.** Prerrequisito que falta: un primer intento reproducible que termine en «timeout con el PC sin cambios». Con el intérprete ocurrió 2 veces en 116
primeros intentos (ambas en la tanda 2) y 0 veces en las 113 corridas posteriores (tandas 3, 5 y 7). Provocarlo exigiría manipular el escenario o RPCS3, o forzar un resultado que el criterio no concede; no se hizo.
La única ejecución real del reintento es la de la tanda 6 (LLVM, 3 intentos, todos INCONCLUSIVE, sin PASS).

### Tipo de instrucción en el PC probado
Se decodificó (del ELF original, fuera de este repo) la instrucción en cada PC probado. Primer intento, todas las tandas; el reintento con `s` (retirado) se cuenta aparte.

| Decoder | Instrucción en el PC | PASS | FAIL | INCONCLUSIVE |
|---|---|---|---|---|
| Intérprete | llamada al sistema (`sc`) | 84 | 0 | 2 (por PC sin cambios; ambos en `sc`) |
| Intérprete | otra | 26 | 0 | 0 |
| Intérprete | fuera del ELF | — | — | 4 (sin `Z0`) |
| LLVM | `sc` | 0 | 10 | 1 |
| LLVM | otra | 0 | 1 | 0 |
| LLVM, tras el paso con `s` (retirado) | otra | 0 | 2 | 0 |

- Hay 7 PC probados con **ambos** decoders (4 de tipo `sc`, 3 de otro tipo). En los 3 de otro tipo: intérprete PASS (4 veces en total), LLVM FAIL (1 de primer intento y 2 tras el paso retirado).

### Experimento de caja negra: ¿el `Z0` cambia la memoria?
Con el intérprete, 8 rondas: se lee con `m` la memoria alrededor del PC antes del `Z0`, después y tras el `z0`. **En 8 de 8 rondas es idéntica**, el `Z0` y el `z0` contestan `OK` y el PC no cambia. **Este método no puede distinguir
«rechazado» de «instalado y ignorado»** y tampoco permitiría detectar un breakpoint del depurador Qt comparando contra el ELF. No se repitió con LLVM porque no aportaría información.

### Qué se sabe y qué no del contraste intérprete / LLVM
- **Confirmado (n chico, un hilo, un contexto):** con LLVM el servidor contestó `OK` al `Z0` en las 15 corridas y en 13 corridas decisivas el hilo siguió más allá del PC sin parar; con el intérprete los mismos PC paran (110 PASS).
  En cada FAIL el hilo avanzó: **una parada silenciosa no explica esos FAIL**. Hay FAIL de LLVM en instrucciones que no son `sc` y PC no-`sc` con PASS (intérprete) y FAIL (LLVM).
- **Hipótesis, sin descartar:** (a) `ppu_breakpoint` rechaza el `Z0` con LLVM (lectura de código de una sesión previa, `servidor_gdb_rpcs3.md` regla 3; no releída en esta tarea); (b) el código LLVM ya compilado no consulta la
  tabla de breakpoints; (c) con LLVM el PC de una parada podría no ser «la próxima instrucción a ejecutar», sobre todo en un `sc` (10 de 11 FAIL de primer intento caen en un `sc`); (d) efecto del momento o del estado del juego.
  (c) no explica el FAIL de primer intento fuera de `sc` (n=1) ni los 2 posteriores al paso retirado, pero esas muestras son demasiado pequeñas para descartarla.
- **Desconocido:** la causa; si algún ajuste de RPCS3 hace que LLVM respete los breakpoints; qué ocurre con otros hilos, pantallas o versiones. **No se afirma que LLVM carezca de breakpoints en general.**
- Los 2 INCONCLUSIVE del intérprete por PC sin cambios caen en `sc`: compatible con un hilo bloqueado dentro de la llamada (hipótesis, no demostrado).

## Tanda 8 (2026-10-28): contexto de instrucción en cada intento
**Código:** `f81dcf1` (campos `instruccion`, `desenlace`, `decoder_ppu` en cada intento; solo observacionales, ver `docs/bp_preflight.md`). **Método:** un arranque por decoder, `bp_preflight.py --elf <ELF original> --log … --timeout 8 --attempts 3 --json`,
corridas seguidas entre `t+17 s` y `t+166 s` desde que apareció `GameThread`; sin forzar reintentos ni manipular el juego. El bridge tomó `decoder_ppu` de la línea `PPU Decoder:` del log (fuente registrada en el JSON).
**Contexto:** la película de apertura en ambas muestras, pero **no el mismo fotograma** (escenas distintas, capturas cada ~10 s sin sincronizar con las corridas).

| Muestra | Corridas | Resultado |
|---|---|---|
| Intérprete (`Interpreter (static)`) | 33 | 28 PASS; 5 INCONCLUSIVE por PC fuera del código del ELF (sin `Z0`); 0 reintentos; limpieza correcta |
| LLVM (`Recompiler (LLVM)`) | 13 | 13 FAIL (`desenlace: avanzo`); 0 reintentos; limpieza correcta |

En el intérprete, 23 de los 28 PASS fueron en un `sc` y 5 en otras instrucciones; en LLVM, 9 de los 13 FAIL fueron en un `sc` y 4 en otras (`li`, `b`). Hubo PC que no son `sc` probados con ambos decoders (PASS con el intérprete, FAIL con LLVM).

### Asociación con `sc` (todas las tandas, primer intento)
| Decoder | Instrucción en el PC | PASS | FAIL | INCONCLUSIVE por PC sin cambios |
|---|---|---|---|---|
| Intérprete | `sc` | 107 | 0 | 2 |
| Intérprete | otra (31 con mnemónico o palabra no reconocida) | 31 | 0 | 0 |
| LLVM | `sc` | 0 | 19 | 2 |
| LLVM | otra | 0 | 5 | 0 |

Aparte, en el intérprete, 9 corridas con el PC fuera del código del ELF (INCONCLUSIVE, sin `Z0`). Se excluyen los 2 FAIL de LLVM obtenidos tras el paso con `s` (reintento retirado). Las tandas 1–7 se decodificaron **a posteriori**
con un script fuera del bridge; la tanda 8 usa los campos nuevos de `bp_preflight.py`. Todos los INCONCLUSIVE por PC sin cambios (4 de 4) caen en `sc`; en los PC que no son `sc` hubo 0 de 36. Las corridas repiten pocos PC distintos y no son independientes: son
**conteos descriptivos, no una prueba de asociación**.

- **FAIL con LLVM no depende de `sc`:** 5 de 5 primeros intentos fuera de `sc` dieron FAIL, igual que 19 de 19 decisivos en `sc`; con el intérprete los mismos tipos de instrucción dan PASS. La hipótesis (c) por sí sola no explica los FAIL de LLVM.
- **«PC sin cambios» coincide con `sc`** (4 de 4; 0 de 36 fuera de `sc`): compatible con un hilo bloqueado dentro de la llamada o con una parada silenciosa, no distinguibles aquí. Correlación en una muestra mínima.
- **No se estableció la causa.** Siguen abiertas: rechazo del `Z0` con LLVM, un código LLVM que no consulta la tabla de breakpoints, el estado del juego y el significado exacto del PC en LLVM.
- **Límites:** un hilo, un contexto (la apertura), un arranque por decoder, escenas no alineadas, palabra de instrucción tomada del ELF, mnemónicos solo para unas pocas codificaciones. Evidencia con direcciones: repo del proyecto que consume el bridge.
