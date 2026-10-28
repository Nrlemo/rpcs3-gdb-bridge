# `bp_preflight.py`: ¿RPCS3 realmente para en un `Z0`?

Un `Z0` aceptado **no prueba nada**: `cmd_set_breakpoint` contesta `OK` siempre y descarta el resultado de `ppu_breakpoint`, que no hace nada si la dirección no es ejecutable/alineada o si el decoder PPU es LLVM (`servidor_gdb_rpcs3.md`, regla 3). Sin esta verificación, un sondeo con `bp_probe.py` bajo LLVM corre minutos sin ningún impacto y parece «el campo no se toca». `bp_probe.py` la ejecuta solo antes de poner ningún `Z0` y no sigue salvo con PASS.

## Uso
```
# con el proxy en marcha y el juego en la pantalla que interesa (conectar pausa el emulador)
python3 -I bp_preflight.py (--thread <id_hex> | --log RPCS3.log [--thread-name GameThread]) [--elf programa.elf | --code lo-hi]
    [--timeout 5] [--no-control] [--no-resume] [--port 2346]
```
Código de salida: **0 PASS · 1 FAIL · 3 INCONCLUSIVE** · 2 uso incorrecto. Por defecto reanuda el objetivo al terminar con limpieza correcta (`--no-resume` lo deja detenido). Debe correr con el objetivo **detenido** (estado al conectar o al conectar el proxy): si está en marcha devuelve INCONCLUSIVE sin tocar nada.
Como módulo: `bp_preflight.check_breakpoints(g, tid, timeout, avoid=(), is_code=None, control=True, resume=False)` devuelve un `Result` (`verdict`, `reason`, `address`, `cleanup_ok`, `allows_probe`).

## Qué hace
1. Selecciona el hilo (`Hg`/`Hc`), descarta paquetes pendientes (`drain`: una parada vieja sería un falso positivo), comprueba `?` y lee el **PC** del hilo: la próxima instrucción que ejecutará (dirección ejecutable por construcción, alineada; con `--elf`/`--code` además se exige que caiga en el código del programa). No se inventa ninguna dirección.
2. Si esa dirección ya tiene un breakpoint conocido por el llamador (`avoid`; `bp_probe` pasa sus sitios), no la usa.
3. `Z0` en el PC → `c` → espera una parada hasta `--timeout`.
4. Con la parada: exige señal `05` y que el PC del hilo siga siendo el del breakpoint. **Control:** quita el `Z0`, continúa de nuevo ~1 s y exige que **no** pare; así la parada se atribuye al `Z0` y no a un servidor que para siempre.
5. Sin parada: interrumpe (`0x03`) y mira el PC. Si el hilo **avanzó** (ejecutó la instrucción con el `Z0` puesto sin parar) es FAIL; si sigue en el mismo PC no hay evidencia suficiente.
6. Siempre intenta quitar el `Z0` (parando antes el objetivo si hace falta) y confirma el `z0`. Si no pudo, `cleanup_ok = False`: el resultado nunca autoriza un sondeo.

## Resultados
| Resultado | Significa | Qué hacer |
|---|---|---|
| **PASS** | `Z0` aceptado, parada comunicada (señal 05) en el mismo PC, y continuar sin `Z0` no para. Los breakpoints de ejecución funcionan **en este hilo y ahora**. | Seguir con `bp_probe.py`. |
| **FAIL** | El servidor rechazó el `Z0` (vacío o `E..`), o el hilo ejecutó la instrucción protegida y siguió sin parar. | Con LLVM es lo esperado: cambiar a `PPU Decoder: Interpreter (static)` y repetir. |
| **INCONCLUSIVE** | No se pudo determinar con seguridad: objetivo en marcha, PC inválido/ya sondeado/fuera del código, respuestas inesperadas, error de conexión, plazo vencido con el hilo sin moverse, parada ajena o parada también sin breakpoint. **No prueba que falten breakpoints.** | Leer el motivo; si fue una parada silenciosa o un hilo inactivo, repetir en otro punto del juego o con otro `--thread`. |

## Decoders PPU
- **Interpreter (static)** (el probado): se espera PASS.
- **Recompiler (LLVM)**: se espera FAIL (el hilo avanza sin parar) o, si el hilo está bloqueado, INCONCLUSIVE; nunca PASS, salvo que RPCS3 cambie. Un INCONCLUSIVE bajo LLVM **no** autoriza a concluir nada: el plazo vencido por sí solo no es evidencia.
- Otros decoders o versiones de RPCS3: sin probar. Cualquier cosa distinta de PASS se trata como «no apto» para `bp_probe.py`.

## Límites (no resolubles sin cambiar RPCS3 o el protocolo)
- **Simulado, no real:** los tests usan `mock_rsp.py`, que imita las reglas leídas en el código de RPCS3. Que el PASS/FAIL coincida con RPCS3 real **no está verificado** hasta correr `bp_preflight.py` contra el emulador (intérprete y LLVM). La premisa «con un `Z0` en el PC actual, `c` vuelve a parar al instante» se apoya en la medición de la regla 4 (0,08 s, 5 de 5 ciclos, dos direcciones), no en una garantía.
- **Breakpoints ajenos:** el servidor no permite listar breakpoints. Si el hilo está parado justo en un breakpoint puesto desde el depurador Qt de RPCS3, el `z0` de limpieza lo quitaría. Correr la verificación antes de poner breakpoints propios o del depurador.
- **Un solo hilo:** valida el hilo elegido. Una parada que llega de otro hilo se informa como INCONCLUSIVE.
- **Paradas silenciosas** (regla 5): un hilo que queda en el `Z0` sin aviso se ve como «sin parada y PC sin cambios» → INCONCLUSIVE, nunca PASS. `bp_probe.py` las trata con su vigía; la verificación no.
- **Interrupción tardía:** si la parada real llega justo al vencer el plazo, la interrupción puede encontrar ya detenido el objetivo; el resultado más probable es INCONCLUSIVE, no uno falso.
- Solo prueba breakpoints de ejecución (`Z0`); `Z1`–`Z4` no existen en el servidor.
- Ninguna verificación previa garantiza que el estado del juego no cambie después.

## `bp_probe.py`
Ejecuta esta verificación antes de abrir la salida o poner un `Z0`, con `avoid` = sus sitios y `is_code` = el código del ELF. Sin PASS (y limpieza correcta) imprime el informe, **no crea el archivo de salida**, deja el juego en marcha y termina con código 3. `--preflight-timeout N` ajusta el plazo. `--ignore-preflight` es el único modo de seguir sin PASS: imprime un aviso, anota el veredicto y `"ignorado": true` en el evento `inicio` del JSONL, y **no cubre** una limpieza fallida (con un `Z0` posiblemente puesto, se niega siempre).
