#!/usr/bin/env python3
"""Verificación previa: ¿RPCS3 realmente PARA en un `Z0`? (un `Z0` aceptado no prueba nada: docs/servidor_gdb_rpcs3.md, regla 3)

Método: con el objetivo detenido, se toma el PC del hilo elegido (la próxima instrucción que ejecutará, una dirección de código
válida por construcción), se pone `Z0` ahí y se continúa. Con breakpoints que funcionan (intérprete) el hilo para de inmediato en
ese mismo PC (docs/servidor_gdb_rpcs3.md, regla 4). Resultados:
  PASS           el servidor aceptó el `Z0`, comunicó una parada (señal 05) y el PC del hilo es el del breakpoint; además, un
                 control sin breakpoint (continuar de nuevo) NO produce parada, así que la parada se debe al `Z0`.
  FAIL           el servidor rechazó el `Z0` (respuesta vacía o `E..`), o venció el plazo y al interrumpir el hilo había AVANZADO más
                 allá del PC con el `Z0` puesto: ejecutó la instrucción sin parar (p. ej. decoder LLVM).
  INCONCLUSIVE   todo lo demás: objetivo no detenido, PC no válido/no alineado/fuera del código/ya sondeado, respuestas inesperadas,
                 errores de conexión, plazo vencido con el PC sin cambios (parada silenciosa o hilo bloqueado), parada ajena o parada
                 también sin breakpoint. Un plazo vencido por sí solo nunca es FAIL.
Siempre intenta dejar el estado limpio: quita el `Z0` y deja el objetivo detenido (o lo reanuda con `resume=True`).
Límite: el protocolo no permite listar breakpoints existentes; si el hilo está parado justo en un breakpoint del depurador Qt de
RPCS3, el `z0` de limpieza lo quitaría. Correr la verificación antes de poner breakpoints propios.

Uso: python3 -I bp_preflight.py (--thread <id_hex> | --log RPCS3.log [--thread-name GameThread]) [--elf programa.elf | --code lo-hi]
         [--timeout 5] [--no-control] [--no-resume] [--port 2346]
Código de salida: 0 PASS, 1 FAIL, 3 INCONCLUSIVE, 2 uso incorrecto.
"""
import argparse
import re
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gdbrsp import Gdb, GdbError  # noqa: E402
from validate_server import parse_g  # noqa: E402

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
EXIT_CODES = {PASS: 0, FAIL: 1, INCONCLUSIVE: 3}
STOP_RE = re.compile(r"^[ST]([0-9a-fA-F]{2})")
CONTROL_TIMEOUT = 1.0           # s sin parada que se exigen al control sin breakpoint
CLEANUP_TIMEOUT = 20.0          # s para que el servidor conteste a una interrupción


class Result:
    def __init__(self, verdict, reason, address=None, cleanup_ok=True):
        self.verdict, self.reason, self.address, self.cleanup_ok = verdict, reason, address, cleanup_ok
        self.notes = []

    @property
    def allows_probe(self):
        """Solo PASS con la limpieza completa autoriza un sondeo basado en breakpoints."""
        return self.verdict == PASS and self.cleanup_ok

    def report(self):
        lines = ["preflight de breakpoints: %s%s" % (self.verdict, " (PC 0x%x)" % self.address if self.address is not None else ""),
                 "  " + self.reason]
        lines += ["  nota: " + n for n in self.notes]
        if not self.cleanup_ok:
            lines.append("  ATENCIÓN: la limpieza no se completó; puede quedar un Z0 puesto o el objetivo en marcha")
        if self.verdict == INCONCLUSIVE:
            lines.append("  Un resultado inconcluso NO prueba que falten breakpoints; ver README (límites).")
        return "\n".join(lines)


def _stop_signal(pkt):
    m = STOP_RE.match(pkt or "")
    return int(m.group(1), 16) if m else None


def _regs(g):
    r = parse_g(g.cmd("g"))
    return r if "pc" in r else None


def check_breakpoints(g, tid, timeout=5.0, avoid=(), is_code=None, control=True, resume=False):
    """Ejecuta la verificación sobre una conexión `Gdb` (o el proxy). Nunca lanza por errores de protocolo/conexión.

    `tid`: hilo (hex de 16 cifras) cuyo PC actual se usa; `avoid`: direcciones con breakpoints ya conocidos por el llamador;
    `is_code(addr)`: opcional, ¿la dirección está en el código del programa?; `control`: exige que continuar sin breakpoint no pare;
    `resume`: al terminar con limpieza correcta, reanuda el objetivo (si no, queda detenido como estaba al entrar)."""
    state = {"installed": False, "addr": None}
    try:
        res = _run(g, tid, timeout, set(avoid), is_code, control, state)
    except (GdbError, OSError, ValueError) as e:       # TimeoutError es OSError
        res = Result(INCONCLUSIVE, "error de conexión o de protocolo: %s: %s" % (type(e).__name__, e), state["addr"])
    cleanup_ok = _cleanup(g, state, res)
    res.cleanup_ok = cleanup_ok
    if resume and cleanup_ok and not g.running:
        try:
            g.cont()
        except (GdbError, OSError) as e:
            res.notes.append("no se pudo reanudar: %s" % e)
    return res


def _run(g, tid, timeout, avoid, is_code, control, state):
    if g.running:
        return Result(INCONCLUSIVE, "el objetivo está en marcha: se necesita detenido (sin tocarlo, para no perturbar otra sesión)")
    for pk in ("Hg" + tid, "Hc" + tid):
        if g.cmd(pk) != "OK":
            return Result(INCONCLUSIVE, "el servidor no aceptó %s" % pk[:2])
    g.drain()          # parada pendiente de antes: contaría como falso positivo
    if _stop_signal(g.cmd("?")) is None:
        return Result(INCONCLUSIVE, "'?' no describe un objetivo detenido")
    r = _regs(g)
    if r is None:
        return Result(INCONCLUSIVE, "respuesta 'g' inesperada: no se pudo leer el PC")
    pc = state["addr"] = r["pc"]
    if pc == 0 or pc % 4:
        return Result(INCONCLUSIVE, "PC 0x%x no válido o no alineado para un breakpoint" % pc, pc)
    if pc in avoid:
        return Result(INCONCLUSIVE, "ya hay un breakpoint conocido en 0x%x: no se pisa" % pc, pc)
    if is_code is not None and not is_code(pc):
        return Result(INCONCLUSIVE, "PC 0x%x fuera del código del programa (¿otro módulo o rutina del sistema?)" % pc, pc)

    reply = g.cmd("Z0,%x,4" % pc)
    if reply != "OK":
        if reply == "" or reply.startswith("E"):
            return Result(FAIL, "el servidor rechazó Z0 en 0x%x (respuesta %r)" % (pc, reply), pc)
        return Result(INCONCLUSIVE, "respuesta inesperada a Z0: %r" % reply, pc)
    state["installed"] = True

    g.cont()
    try:
        stop = g.wait_stop(timeout)
    except TimeoutError:
        return _after_timeout(g, tid, pc, timeout)
    sig = _stop_signal(stop)
    if sig != 5:
        return Result(INCONCLUSIVE, "paquete de parada inesperado %r (no es señal 05)" % stop, pc)
    r2 = _regs(g)
    if r2 is None:
        return Result(INCONCLUSIVE, "tras la parada, 'g' dio una respuesta inesperada", pc)
    if r2["pc"] != pc:
        return Result(INCONCLUSIVE, "paró con PC 0x%x != 0x%x: parada ajena al breakpoint de la prueba (otro breakpoint u otro hilo)" % (r2["pc"], pc), pc)
    if not control:
        res = Result(PASS, "Z0 aceptado y parada con señal 05 en el mismo PC; control sin breakpoint omitido (--no-control)", pc)
        return res
    return _control(g, state, pc)


def _after_timeout(g, tid, pc, timeout):
    """Venció el plazo tras `c`: interrumpir y mirar si el hilo avanzó. Solo avanzar sin parar prueba que el Z0 se ignoró."""
    try:
        g.interrupt(timeout=CLEANUP_TIMEOUT)
    except (GdbError, OSError) as e:
        return Result(INCONCLUSIVE, "sin parada en %gs y la interrupción falló (%s: %s): el objetivo puede seguir en marcha" % (timeout, type(e).__name__, e), pc)
    r2 = _regs(g)
    if r2 is None:
        return Result(INCONCLUSIVE, "sin parada en %gs; tras interrumpir, 'g' dio una respuesta inesperada" % timeout, pc)
    if r2["pc"] == pc:
        return Result(INCONCLUSIVE, "sin parada comunicada en %gs y el hilo sigue en 0x%x: parada silenciosa (el Z0 pudo funcionar sin avisar) "
                                    "o hilo sin ejecutar; el plazo por sí solo no prueba nada" % (timeout, pc), pc)
    return Result(FAIL, "el hilo ejecutó la instrucción de 0x%x con Z0 puesto y siguió hasta 0x%x sin parar: los breakpoints no se respetan "
                        "(típico del decoder LLVM; con 'Interpreter (static)' debería parar)" % (pc, r2["pc"]), pc)


def _control(g, state, pc):
    """Con el Z0 ya quitado, continuar de nuevo no debe parar: si para, la parada anterior no era atribuible al breakpoint."""
    if not _remove(g, pc):
        state["installed"] = True
        return Result(INCONCLUSIVE, "no se pudo quitar el Z0 para el control", pc)
    state["installed"] = False
    g.cont()
    try:
        stop = g.wait_stop(CONTROL_TIMEOUT)
    except TimeoutError:
        g.interrupt(timeout=CLEANUP_TIMEOUT)
        return Result(PASS, "Z0 aceptado, parada con señal 05 en el mismo PC y sin parada al repetir sin breakpoint", pc)
    return Result(INCONCLUSIVE, "el objetivo también paró SIN breakpoint (%r): la parada no es atribuible al Z0" % stop, pc)


def _remove(g, pc):
    return g.cmd("z0,%x,4" % pc) == "OK"


def _cleanup(g, state, res):
    """Quitar el Z0 si sigue puesto; con el objetivo en marcha hay que pararlo antes (el proxy rechaza z0 en marcha)."""
    if not state["installed"]:
        return True
    try:
        if g.running:
            g.interrupt(timeout=CLEANUP_TIMEOUT)
        if _remove(g, state["addr"]):
            state["installed"] = False
            return True
        res.notes.append("el servidor no confirmó z0 en 0x%x" % state["addr"])
    except (GdbError, OSError) as e:
        res.notes.append("limpieza fallida: %s: %s" % (type(e).__name__, e))
    return False


def build_parser():
    ap = argparse.ArgumentParser(description="Verifica que RPCS3 realmente pare en un Z0 (PASS/FAIL/INCONCLUSIVE)")
    ap.add_argument("--thread", help="id del hilo (hex)")
    ap.add_argument("--log", help="RPCS3.log (para hallar el hilo por nombre)")
    ap.add_argument("--thread-name", default="GameThread")
    ap.add_argument("--elf", help="ELF: el PC debe caer en un segmento ejecutable")
    ap.add_argument("--code", help="rango de código lo-hi en hex (alternativa a --elf)")
    ap.add_argument("--timeout", type=float, default=5.0, help="s a esperar la parada (def. %(default)s)")
    ap.add_argument("--no-control", action="store_true", help="omitir el control sin breakpoint")
    ap.add_argument("--no-resume", action="store_true", help="dejar el objetivo detenido al terminar")
    ap.add_argument("--port", type=int, default=2346)
    return ap


def main(argv):
    ap = build_parser()
    a = ap.parse_args(argv[1:])
    if not a.thread and not a.log:
        ap.error("hace falta --thread o --log")
    from bp_probe import find_game_thread
    import validate_server
    tid = a.thread.zfill(16) if a.thread else find_game_thread(a.log, a.thread_name)
    ranges = validate_server.set_code_ranges(a.elf, a.code)
    g = Gdb("127.0.0.1", a.port, timeout=30.0)
    res = check_breakpoints(g, tid, a.timeout, is_code=validate_server.in_code if ranges else None,
                            control=not a.no_control, resume=not a.no_resume)
    print(res.report())
    return EXIT_CODES[res.verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
