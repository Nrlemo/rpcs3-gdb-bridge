# `bp_preflight.py`: ¿RPCS3 realmente para en un `Z0`?

Un `Z0` aceptado **no prueba nada**: `cmd_set_breakpoint` contesta `OK` siempre y descarta el resultado de `ppu_breakpoint`, que no hace nada si la dirección no es ejecutable/alineada o si el decoder PPU es LLVM (`servidor_gdb_rpcs3.md`, regla 3). Sin esta verificación, un sondeo con `bp_probe.py` bajo LLVM corre minutos sin ningún impacto y parece «el campo no se toca». `bp_probe.py` la ejecuta antes de poner ningún `Z0` y no sigue salvo con PASS.

## Uso
```
# con el proxy en marcha y el juego en la pantalla que interesa (conectar pausa el emulador)
python3 -I bp_preflight.py (--thread <id_hex> | --log RPCS3.log [--thread-name GameThread]) [--elf programa.elf | --code lo-hi]
    [--timeout 5] [--attempts 3] [--no-control] [--no-resume] [--json salida.json] [--port 2346]
```
`--json` guarda el resultado completo (un registro por intento, hilo, código de salida); el archivo no debe existir.
Código de salida: **0 PASS · 1 FAIL · 3 INCONCLUSIVE** · 2 uso incorrecto. Por defecto reanuda el objetivo al terminar con limpieza correcta (`--no-resume` lo deja detenido). Debe correr con el objetivo **detenido** (estado al conectar el proxy): si está en marcha devuelve INCONCLUSIVE sin tocar nada.
`--timeout` es **por intento**; cota total aproximada: `attempts × (timeout + 1 s de control + limpieza)`.
Como módulo: `bp_preflight.check_breakpoints(g, tid, timeout, avoid=(), is_code=None, control=True, resume=False, attempts=3, alternates=None)` devuelve un `Result` (`verdict`, `reason`, `address`, `cleanup_ok`, `allows_probe`, `notes`, `attempts`, `to_dict()`).

## Qué hace (intento 1)
1. Selecciona el hilo (`Hg`/`Hc`), descarta paquetes pendientes (`drain`: una parada vieja sería un falso positivo), comprueba `?` y lee el **PC** del hilo: la próxima instrucción que ejecutará (dirección ejecutable por construcción, alineada; con `--elf`/`--code` además se exige que caiga en el código del programa). No se inventa ninguna dirección.
2. Si esa dirección ya tiene un breakpoint conocido por el llamador (`avoid`; `bp_probe` pasa sus sitios), no la usa.
3. `Z0` en el PC → `c` → espera una parada hasta `--timeout`.
4. Con la parada: exige señal `05` y que el PC del hilo siga siendo el del breakpoint. **Control:** quita el `Z0`, continúa de nuevo ~1 s y exige que **no** pare; así la parada se atribuye al `Z0` y no a un servidor que para siempre.
5. Sin parada: interrumpe (`0x03`) y mira el PC. Si el hilo **avanzó** (ejecutó la instrucción con el `Z0` puesto sin parar) es FAIL; si sigue en el mismo PC no hay evidencia suficiente (INCONCLUSIVE).
6. Siempre intenta quitar el `Z0` (parando antes el objetivo si hace falta) y confirma el `z0`, también ante Ctrl-C u otra excepción (limpia y la propaga). Si no pudo, `cleanup_ok = False`: el resultado nunca autoriza un sondeo.

## Reintentos (otra dirección, validada; sin pasos ni cambio de hilo)
Solo el caso «plazo vencido y el hilo sigue en el mismo PC» (parada silenciosa o hilo bloqueado: el protocolo no los distingue) permite otro intento, y solo si la limpieza del anterior salió bien y quedan intentos (`--attempts`, 3 por defecto en total; `1` los desactiva).
- **Dirección alternativa:** la pasa quien llama (`alternates(regs, read)`). `bp_probe.make_alternates(img)` devuelve el **LR** y los **retornos de la cadena de retroceso** del propio hilo; cada uno se acepta solo si cae en el código del ELF y la instrucción anterior es una llamada (`bl/bla/bctrl/blrl`; la misma comprobación que usa `walk_chain`). Además deben estar alineadas, no repetirse, no estar en `avoid` y pasar `is_code`. Sin `--elf` (o sin ninguna válida) **no hay reintento** y queda INCONCLUSIVE con la nota que lo explica. No se suma al PC ni se prueban direcciones arbitrarias.
- **Ciclo completo por intento:** `Z0`, parada con señal 05 en esa dirección, control sin breakpoint y limpieza confirmada. Cada intento se evalúa solo, sin arrastrar nada del anterior.
- **Semántica:** un intento alternativo solo puede dar **PASS** o **INCONCLUSIVE**. Que el hilo no pare, o que se mueva, no prueba que ejecutara esa dirección, así que **un reintento nunca produce FAIL**. Un FAIL del intento 1 (rechazo del `Z0` o avance del hilo) es definitivo y no se reintenta. Un INCONCLUSIVE nunca se convierte en PASS por haber reintentado: el PASS sale de una parada genuina más su control, y vale solo para esa dirección y ese hilo (el informe lo anota).
- **Se detiene** ante: error de conexión, respuesta inesperada, rechazo del `Z0` en la alternativa, parada ajena, interrupción fallida o limpieza fallida.
- **No hace:** pasos con `s`, cambios de hilo, ni reanudar entre intentos más allá de los propios `c` de cada intento (cada uno bajo su `--timeout`).
- **Registro por intento** (`Result.attempts`; `bp_probe` lo copia al evento `inicio` del JSONL): `n`, `origen` (`pc_actual`, `lr`, `retorno_N`), `hilo`, `pc`, `pc_hilo`, `timeout_s`, `respuesta_z0`, `parada` / `sin_parada_en_s`, `pc_tras_parada` / `pc_tras_interrupcion`, `control`, `veredicto`, `motivo`, `limpieza_ok`, `segundos`.

## Resultados
| Resultado | Significa | Qué hacer |
|---|---|---|
| **PASS** | `Z0` aceptado, parada comunicada (señal 05) en el mismo PC, y continuar sin `Z0` no para. Los breakpoints de ejecución funcionan **en este hilo y ahora**. | Seguir con `bp_probe.py`. |
| **FAIL** | El servidor rechazó el `Z0` (vacío o `E..`), o el hilo ejecutó la instrucción protegida y siguió sin parar. | Con LLVM es lo esperado: cambiar a `PPU Decoder: Interpreter (static)` y repetir. |
| **INCONCLUSIVE** | No se pudo determinar con seguridad: objetivo en marcha, PC inválido/ya sondeado/fuera del código, respuestas inesperadas, error de conexión, plazo vencido con el hilo sin moverse, parada ajena, parada también sin breakpoint, sin dirección alternativa segura. **No prueba que falten breakpoints.** | Leer el motivo y los intentos; repetir en otro punto del juego. |

## Decoders PPU
- **Interpreter (static)** (el probado): se espera PASS, aunque hubo INCONCLUSIVE (ver el informe de evidencia).
- **Recompiler (LLVM)**: se espera FAIL (el hilo avanza sin parar) o, si el hilo no se mueve, INCONCLUSIVE; nunca PASS, salvo que RPCS3 cambie. Un INCONCLUSIVE bajo LLVM **no** autoriza a concluir nada: el plazo vencido por sí solo no es evidencia.
- Otros decoders o versiones de RPCS3: sin probar. Cualquier cosa distinta de PASS se trata como «no apto» para `bp_probe.py`.

## Validación
- **Simulada:** `tests/test_bp_preflight.py` (55 tests) usa `mock_rsp.py` (Gdb real → `proxy.py` real → servidor simulado que imita las reglas leídas en el código de RPCS3) y dobles sin red. Demuestran la lógica de decisión, **no** el comportamiento de RPCS3.
- **Real:** corridas puntuales con RPCS3 0.0.43 (intérprete y LLVM), con muestra chica y sin estadística: `docs/evidencia/preflight_rpcs3_0.0.43/README.md`. El reintento actual (direcciones de retorno) se ejecutó **una sola vez** contra RPCS3 real (LLVM, 3 intentos, todos INCONCLUSIVE); **ningún reintento real ha terminado en PASS**, y en 101 corridas amplias del intérprete (tanda 7) no hizo falta ninguno. No se mezclan resultados simulados y reales en una misma tasa.

## Límites (no resolubles sin cambiar RPCS3 o el protocolo)
- **FAIL en un `sc`:** el FAIL supone que el hilo no había ejecutado aún la instrucción del PC. Con el intérprete eso se sostiene (84 PASS en `sc`), pero con LLVM no está comprobado: un hilo parado en un `sc` podría ir ya dentro de la llamada. Casi todos los FAIL de LLVM observados caen en un `sc` (hay uno fuera de `sc`, n=1). Hipótesis abierta; ver el informe de evidencia.
- La premisa «con un `Z0` en el PC actual, `c` vuelve a parar al instante» se apoya en la medición de la regla 4 (0,08 s, 5 de 5 ciclos, dos direcciones) y en las corridas del informe, no en una garantía.
- **Breakpoints ajenos:** el servidor no permite listar breakpoints, y se midió que el `Z0` no deja huella en la memoria visible con `m`, así que tampoco se detectan comparando con el ELF. Si el hilo está parado justo en un breakpoint puesto desde el depurador Qt de RPCS3, el `z0` de limpieza lo quitaría. Correr la verificación antes de poner breakpoints propios o del depurador.
- **Un solo hilo:** valida el hilo elegido. Una parada que llega de otro hilo se informa como INCONCLUSIVE.
- **Parada silenciosa frente a hilo bloqueado:** indistinguibles con este protocolo; ambos dan INCONCLUSIVE, nunca PASS. `bp_probe.py` trata las silenciosas con su vigía; la verificación no.
- **Direcciones de retorno:** que una dirección de retorno sea código válido no garantiza que el hilo vuelva a pasar por ella pronto; un hilo ocioso puede agotar los intentos.
- **Interrupción tardía:** si la parada real llega justo al vencer el plazo, la interrupción puede encontrar ya detenido el objetivo; el resultado más probable es INCONCLUSIVE, no uno falso.
- Solo prueba breakpoints de ejecución (`Z0`); `Z1`–`Z4` no existen en el servidor.
- Ninguna verificación previa garantiza que el estado del juego no cambie después.

## `bp_probe.py`
Ejecuta esta verificación antes de abrir la salida o poner un `Z0`, con `avoid` = sus sitios, `is_code` = el código del ELF y `alternates` = `make_alternates(img)`. Sin PASS (y limpieza correcta) imprime el informe, **no crea el archivo de salida**, deja el juego en marcha y termina con código 3. `--preflight-timeout N` (por intento) y `--preflight-attempts N` ajustan el plazo y el máximo de intentos. `--ignore-preflight` es el único modo de seguir sin PASS: imprime un aviso, anota el veredicto, los intentos y `"ignorado": true` en el evento `inicio` del JSONL, y **no cubre** una limpieza fallida (con un `Z0` posiblemente puesto, se niega siempre).
