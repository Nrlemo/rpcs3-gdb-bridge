# `proxy.py`: proxy RSP persistente

Resuelve las dos limitaciones del servidor GDB de RPCS3 que más estorban (ver `servidor_gdb_rpcs3.md`): una sola conexión por arranque y el congelamiento al cerrar el cliente.
El proxy abre **una** conexión al servidor y **no la cierra nunca**; los clientes se conectan al proxy, de uno en uno, y pueden irse y volver.

## Uso
```
python3 -I proxy.py [--upstream 127.0.0.1:2345] [--listen 127.0.0.1:2346] [--log ./rpcs3_bridge_logs/<fecha>.jsonl] [--allow-kill] [--no-translate]
```
Arrancarlo con el programa ya en la pantalla que interesa: **conectar pausa el emulador**. Los clientes (`gdbrsp.py`, `bp_probe.py`, `validate_server.py`, `attach_idle.py`) apuntan al puerto `--listen`.
Un Ctrl-C solo avisa (salir cierra la conexión y congela RPCS3); el segundo en 5 s sale. Si el servidor cierra la conexión, el proxy termina con código 2.

## Qué hace con cada paquete del cliente
| Paquete | Acción |
|---|---|
| `D` | responde `OK` él mismo; el servidor no se entera (no-op) |
| `k` | se bloquea (apagaría RPCS3); con `--allow-kill` se reenvía |
| `c` / `s` | se traducen a `vCont;c` / `vCont;s` (el servidor no tiene `c`/`s` planos); `--no-translate` lo desactiva |
| `0x03` | se reenvía si el objetivo corre |
| otro, con el objetivo corriendo | se rechaza con `E01` (el servidor se tragaría esos bytes) |
| otro | se reenvía tal cual y se devuelve la respuesta |

Al conectarse un cliente nuevo con el objetivo corriendo, el proxy lo interrumpe y descarta esa parada: todo cliente empieza con el objetivo detenido. Si un cliente se va con el objetivo corriendo, su parada futura se descarta (no se la come el siguiente).
Solo se atiende un cliente a la vez (el segundo se rechaza).

## Registro (JSONL)
Una línea por evento: `open`, `client_connect`, `client_disconnect`, `pkt` (`dir`: `c2p`, `p2u`, `u2p`, `p2c`), `local` (respuesta propia), `translate`, `int`, `interrupt_on_attach`, `orphan_reply`, `kill_blocked`, `bad_checksum`, `unsolicited`, `upstream_closed`, `exit`. Cuerpos truncados a 200 caracteres. No se sobrescribe un registro existente.

## Validación
- **Contra un servidor simulado** (`mock_rsp.py`, que imita las reglas leídas en el código de RPCS3): 18 tests (`tests/test_proxy.py`), incluida la mutación deliberada del proxy (reenviar `D`, cerrar el servidor al irse un cliente) que hace fallar los tests.
- **Contra RPCS3 real** (0.0.43, intérprete): 8 conexiones de cliente, 41 interrupciones, 3 «interrumpir al conectar», 3 respuestas huérfanas descartadas, 0 paquetes no solicitados o con checksum malo, `D` respondido localmente y **ningún congelamiento** (0 apariciones de `Emulation has been frozen` en los registros de RPCS3).
- **No probado:** el `c` plano contra el servidor real (siempre se tradujo); más de un cliente concurrente más allá del rechazo del segundo.
