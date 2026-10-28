#!/usr/bin/env python3
"""Verificación previa: ¿RPCS3 realmente PARA en un `Z0`? (un `Z0` aceptado no prueba nada: docs/servidor_gdb_rpcs3.md, regla 3)

Método: con el objetivo detenido, se toma el PC del hilo elegido (la próxima instrucción que ejecutará, una dirección de código
válida por construcción), se pone `Z0` ahí y se continúa. Con breakpoints que funcionan (intérprete) el hilo para de inmediato en
ese mismo PC (docs/servidor_gdb_rpcs3.md, regla 4). Resultados:
  PASS           el servidor aceptó el `Z0`, comunicó una parada (señal 05) y el PC del hilo es el del breakpoint; además, un
                 control sin breakpoint (continuar de nuevo) NO produce parada, así que la parada se debe al `Z0`.
  FAIL           el servidor rechazó el `Z0` (respuesta vacía o `E..`), o venció el plazo y al interrumpir el hilo había AVANZADO más
                 allá del PC con el `Z0` puesto: ejecutó la instrucción sin parar (p. ej. decoder LLVM). Solo el PRIMER intento
                 (PC actual) puede dar FAIL.
  INCONCLUSIVE   todo lo demás: objetivo no detenido, PC no válido/no alineado/fuera del código/ya sondeado, respuestas inesperadas,
                 errores de conexión, plazo vencido con el PC sin cambios (parada silenciosa o hilo bloqueado), parada ajena o parada
                 también sin breakpoint. Un plazo vencido por sí solo nunca es FAIL.
Siempre intenta dejar el estado limpio: quita el `Z0` y deja el objetivo detenido (o lo reanuda con `resume=True`).
Límite: el protocolo no permite listar breakpoints existentes; si el hilo está parado justo en un breakpoint del depurador Qt de
RPCS3, el `z0` de limpieza lo quitaría. Correr la verificación antes de poner breakpoints propios.

Reintentos (`attempts` en total, 3 por defecto; 1 los desactiva). Solo tras «plazo vencido con el PC sin cambios» y con la limpieza
correcta se prueba OTRA dirección, que debe haber sido validada como código por quien llama (`alternates`; bp_probe.make_alternates usa
las direcciones de retorno del propio hilo: LR y cadena de retroceso, cada una comprobada contra el ELF: la instrucción anterior es una
llamada). Sin `alternates` (p. ej. sin --elf) o sin ninguna dirección válida se queda en INCONCLUSIVE. Cada intento repite el ciclo
completo (Z0, parada con señal 05 en esa dirección, control sin breakpoint, limpieza) y se registra aparte (`Result.attempts`). Un
intento alternativo SOLO puede dar PASS o INCONCLUSIVE: que el hilo no pare o se mueva no prueba que ejecutara esa dirección, así que
no hay FAIL por reintento. No avanza el hilo con `s`, no cambia de hilo y no suma al PC.

Contexto de instrucción (solo observacional; no cambia el veredicto, el timeout ni los reintentos): cada registro de intento incluye
`instruccion` (PC, si cae en el código del ELF, palabra del ELF, mnemónico de una tabla mínima propia, `es_sc`, estado y método),
`desenlace` (paró en el PC / avanzó / siguió en el mismo PC / sin dato) y `decoder_ppu` (de --ppu-decoder o de la línea «PPU Decoder:» del
log). La palabra sale SOLO del ELF (no se lee memoria del juego): no detecta código parcheado en ejecución. Sin ELF, fuera del código o con
una palabra ilegible se registra el estado y `es_sc: null`; nunca se supone «no sc».

Uso: python3 -I bp_preflight.py (--thread <id_hex> | --log RPCS3.log [--thread-name GameThread]) [--elf programa.elf | --code lo-hi]
         [--timeout 5] [--attempts 3] [--no-control] [--no-resume] [--json salida.json] [--ppu-decoder TEXTO] [--port 2346]
`--json` guarda el resultado completo (un registro por intento; el archivo no debe existir). `--timeout` es por intento; cota total ≈ attempts × (timeout + CONTROL_TIMEOUT + limpieza). Los reintentos con direcciones de retorno
exigen --elf. Código de salida: 0 PASS, 1 FAIL, 3 INCONCLUSIVE, 2 uso incorrecto.
"""
import argparse
import json
import re
import sys
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gdbrsp import Gdb, GdbError  # noqa: E402
from validate_server import parse_g  # noqa: E402

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
EXIT_CODES = {PASS: 0, FAIL: 1, INCONCLUSIVE: 3}
STOP_RE = re.compile(r"^[ST]([0-9a-fA-F]{2})")
CONTROL_TIMEOUT = 1.0           # s sin parada que se exigen al control sin breakpoint
CLEANUP_TIMEOUT = 20.0          # s para que el servidor conteste a una interrupción
DEFAULT_ATTEMPTS = 3


class Result:
    def __init__(self, verdict, reason, address=None, cleanup_ok=True, retryable=False):
        self.verdict, self.reason, self.address, self.cleanup_ok = verdict, reason, address, cleanup_ok
        self.retryable = retryable      # INCONCLUSIVE por «sin parada y PC sin cambios»: otra dirección válida puede dar evidencia
        self.notes = []
        self.attempts = []              # un dict por intento (ver _attempt)
        self.ppu_decoder = None         # {"valor", "fuente"} indicado por el operador o leído del log; None si no se indicó

    @property
    def allows_probe(self):
        """Solo PASS con la limpieza completa autoriza un sondeo basado en breakpoints."""
        return self.verdict == PASS and self.cleanup_ok

    def to_dict(self):
        """Resumen serializable (JSON) para dejar constancia, p. ej. en el evento `inicio` de bp_probe."""
        return {"veredicto": self.verdict, "motivo": self.reason, "pc": hex(self.address) if self.address is not None else None,
                "limpieza_ok": self.cleanup_ok, "notas": list(self.notes), "decoder_ppu": self.ppu_decoder,
                "intentos": [dict(a) for a in self.attempts]}

    def report(self):
        lines = ["preflight de breakpoints: %s%s" % (self.verdict, " (PC 0x%x)" % self.address if self.address is not None else ""),
                 "  " + self.reason]
        if len(self.attempts) > 1:
            for a in self.attempts:
                lines.append("  intento %d [%s, %s, %.1fs]: %s en %s, limpieza %s: %s" % (
                    a["n"], a["origen"], a["hilo"][-4:], a["segundos"], a["veredicto"], a["pc"], "ok" if a["limpieza_ok"] else "FALLÓ", a["motivo"]))
        lines += ["  nota: " + n for n in self.notes]
        if not self.cleanup_ok:
            lines.append("  ATENCIÓN: la limpieza no se completó; puede quedar un Z0 puesto o el objetivo en marcha")
        if self.verdict == INCONCLUSIVE:
            lines.append("  Un resultado inconcluso NO prueba que falten breakpoints; ver README (límites).")
        return "\n".join(lines)


METODO_INSTRUCCION = "palabra del ELF (opd_scan.Image.u32) + tabla mínima propia de codificaciones exactas (sc, nop, b/bl/ba/bla, blr/blrl/bctr/bctrl, li)"
_EXACTAS = {0x44000002: "sc", 0x60000000: "nop", 0x4E800020: "blr", 0x4E800021: "blrl", 0x4E800420: "bctr", 0x4E800421: "bctrl"}


def decode_word(w):
    """(mnemónico | None, es_sc | None, estado) de una palabra de instrucción PPC. Solo reconoce lo que está en la tabla mínima:
    el resto da mnemónico None. `es_sc` es True solo para la palabra exacta de `sc` (LEV 0), None para otras palabras del código de
    operación 17 (formas no estándar: no se decide) y False para cualquier otra, de la que se sabe con certeza que no es `sc`."""
    if w in _EXACTAS:
        return _EXACTAS[w], w == 0x44000002, "ok"
    op = w >> 26
    if op == 17:
        return None, None, "opcode_17_no_estandar"
    if op == 18:
        return ("b", "bl", "ba", "bla")[w & 3], False, "ok"
    if op == 14 and ((w >> 16) & 31) == 0:
        return "li", False, "ok"
    return None, False, "mnemonico_no_reconocido"


def instruction_context(img, addr):
    """Qué instrucción hay en `addr` según el ELF `img` (None si no hay ELF). Nunca adivina y nunca lee memoria del juego."""
    ctx = {"pc": hex(addr), "en_codigo": None, "palabra": None, "mnemonico": None, "es_sc": None, "estado": "sin_elf",
           "metodo": METODO_INSTRUCCION}
    if img is None:
        return ctx
    if not img.in_code(addr):
        ctx.update(en_codigo=False, estado="fuera_del_codigo")
        return ctx
    ctx["en_codigo"] = True
    w = img.u32(addr)
    if w is None:
        ctx["estado"] = "palabra_ilegible"
        return ctx
    mn, es_sc, estado = decode_word(w)
    ctx.update(palabra="%08x" % w, mnemonico=mn, es_sc=es_sc, estado=estado)
    return ctx


def make_instr_info(img):
    """`instr_info` para check_breakpoints a partir de un opd_scan.Image (o None: «sin_elf»)."""
    return lambda addr: instruction_context(img, addr)


def ppu_decoder_from_log(path):
    """Valor de la línea «PPU Decoder:» del log de RPCS3 (la primera), o None. Es lo que decía la configuración, no una medición."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = re.match(r"^\s*PPU Decoder:\s*(.+?)\s*$", ln)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def _desenlace(rec, addr):
    """Qué se observó del hilo en este intento: paró en el PC, paró en otro, avanzó, siguió en el mismo PC o sin dato."""
    if rec.get("pc_tras_parada") is not None:
        return "paro_en_pc" if rec["pc_tras_parada"] == hex(addr) else "paro_en_otro_pc"
    if rec.get("pc_tras_interrupcion") is not None:
        return "mismo_pc" if rec["pc_tras_interrupcion"] == hex(addr) else "avanzo"
    return "sin_dato"


def _stop_signal(pkt):
    m = STOP_RE.match(pkt or "")
    return int(m.group(1), 16) if m else None


def _regs(g):
    r = parse_g(g.cmd("g"))
    return r if "pc" in r else None


def _valid_target(addr, avoid, is_code):
    """Motivo por el que `addr` no sirve para un breakpoint de prueba, o None si sirve."""
    if addr == 0 or addr % 4:
        return "0x%x no válido o no alineado para un breakpoint" % addr
    if addr in avoid:
        return "ya hay un breakpoint conocido en 0x%x: no se pisa" % addr
    if is_code is not None and not is_code(addr):
        return "0x%x fuera del código del programa (¿otro módulo o rutina del sistema?)" % addr
    return None


def check_breakpoints(g, tid, timeout=5.0, avoid=(), is_code=None, control=True, resume=False, attempts=DEFAULT_ATTEMPTS, alternates=None,
                      instr_info=None, ppu_decoder=None):
    """Ejecuta la verificación sobre una conexión `Gdb` (o el proxy). Nunca lanza por errores de protocolo/conexión.

    `tid`: hilo (hex de 16 cifras) cuyo PC actual se usa; `avoid`: direcciones con breakpoints ya conocidos por el llamador;
    `is_code(addr)`: opcional, ¿la dirección está en el código del programa?; `control`: exige que continuar sin breakpoint no pare;
    `resume`: al terminar con limpieza correcta, reanuda el objetivo (si no, queda detenido como estaba al entrar);
    `attempts`: intentos en total (ver el docstring del módulo); `alternates(regs, read)`: devuelve [(dirección, etiqueta)] de
    direcciones que el llamador pudo validar como código; se consulta una sola vez y solo tras «plazo vencido con el PC sin cambios».
    `instr_info(addr)` (p. ej. make_instr_info) y `ppu_decoder` ({"valor", "fuente"}) solo enriquecen los registros: no influyen en nada más."""
    avoid = set(avoid)
    attempts = max(1, attempts)
    records, tried = [], set()
    ctx = (instr_info, ppu_decoder)
    res = _attempt(g, tid, timeout, avoid, is_code, control, None, "pc_actual", 1, records, ctx)
    if res.address is not None:
        tried.add(res.address)
    candidates = None
    while res.retryable and res.cleanup_ok and len(records) < attempts:
        if candidates is None:
            candidates, why = _candidates(g, alternates)
            if why:
                res.notes.append("sin reintento: " + why)
                break
        cand = next(((a, lb) for a, lb in candidates if a not in tried and _valid_target(a, avoid, is_code) is None), None)
        if cand is None:
            res.notes.append("sin reintento: no hay otra dirección alternativa válida (retornos del hilo fuera del ELF, repetidos o con breakpoint conocido)")
            break
        tried.add(cand[0])
        res = _attempt(g, tid, timeout, avoid, is_code, control, cand[0], cand[1], len(records) + 1, records, ctx)
    if res.retryable and res.cleanup_ok and len(records) >= attempts > 1:
        res.notes.append("límite de %d intentos alcanzado" % attempts)
    res.attempts = records
    res.ppu_decoder = ppu_decoder
    if len(records) > 1 and res.verdict == PASS:
        res.notes.append("PASS en el intento %d tras intentos previos sin evidencia; solo vale para esa dirección y ese hilo" % len(records))
    if g.running:                   # p. ej. una interrupción fallida
        res.cleanup_ok = False
    if resume and res.cleanup_ok:
        try:
            g.cont()
        except (GdbError, OSError) as e:
            res.notes.append("no se pudo reanudar: %s" % e)
    return res


def _candidates(g, alternates):
    """Lista de direcciones alternativas, o ([], motivo). Se consulta con el objetivo detenido y ya limpio."""
    if alternates is None:
        return [], "no hay forma segura de validar otra dirección como código (se necesita --elf)"
    try:
        r = _regs(g)
        if r is None:
            return [], "respuesta 'g' inesperada al buscar direcciones alternativas"
        return list(alternates(r, g.read)), None
    except (GdbError, OSError, ValueError) as e:
        return [], "error al buscar direcciones alternativas: %s: %s" % (type(e).__name__, e)


def _attempt(g, tid, timeout, avoid, is_code, control, target, origen, n, records, ctx=(None, None)):
    """Un intento completo (con limpieza) y su registro. `target` None = PC actual del hilo."""
    t0 = time.time()
    state = {"installed": False, "addr": None, "rec": {}}
    try:
        res = _run(g, tid, timeout, avoid, is_code, control, state, target)
    except (GdbError, OSError, ValueError) as e:       # TimeoutError es OSError
        res = Result(INCONCLUSIVE, "error de conexión o de protocolo: %s: %s" % (type(e).__name__, e), state["addr"])
    except BaseException:                              # p. ej. Ctrl-C con el Z0 puesto y el objetivo en marcha: limpiar y propagar
        _cleanup(g, state, Result(INCONCLUSIVE, "interrumpido"))
        raise
    res.cleanup_ok = _cleanup(g, state, res)
    rec = {"n": n, "origen": origen, "hilo": tid, "pc": hex(res.address) if res.address is not None else None, "timeout_s": timeout,
           "veredicto": res.verdict, "motivo": res.reason, "limpieza_ok": res.cleanup_ok, "reintentable": res.retryable,
           "segundos": round(time.time() - t0, 2)}
    rec.update(state["rec"])
    instr_info, ppu_decoder = ctx
    if res.address is not None:                        # solo observacional: un fallo aquí no puede afectar al resultado
        try:
            rec["instruccion"] = (instr_info or (lambda a: instruction_context(None, a)))(res.address)
        except Exception as e:      # noqa: BLE001
            rec["instruccion"] = {"pc": hex(res.address), "estado": "error_de_decodificacion", "es_sc": None, "detalle": "%s: %s" % (type(e).__name__, e)}
        rec["desenlace"] = _desenlace(rec, res.address)
    rec["decoder_ppu"] = ppu_decoder
    records.append(rec)
    return res


def _run(g, tid, timeout, avoid, is_code, control, state, target):
    rec = state["rec"]
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
    rec["pc_hilo"] = hex(r["pc"])
    addr = state["addr"] = r["pc"] if target is None else target
    bad = _valid_target(addr, avoid, is_code)
    if bad:
        return Result(INCONCLUSIVE, bad, addr)

    reply = rec["respuesta_z0"] = g.cmd("Z0,%x,4" % addr)
    if reply != "OK":
        if reply == "" or reply.startswith("E"):
            # En un reintento no es concluyente: el primer Z0 sí se aceptó y esta dirección pudo no ser apta.
            return Result(FAIL if target is None else INCONCLUSIVE, "el servidor rechazó Z0 en 0x%x (respuesta %r)" % (addr, reply), addr)
        return Result(INCONCLUSIVE, "respuesta inesperada a Z0: %r" % reply, addr)
    state["installed"] = True

    g.cont()
    try:
        stop = rec["parada"] = g.wait_stop(timeout)
    except TimeoutError:
        rec["sin_parada_en_s"] = timeout
        return _after_timeout(g, addr, timeout, target is None, rec)
    sig = _stop_signal(stop)
    if sig != 5:
        return Result(INCONCLUSIVE, "paquete de parada inesperado %r (no es señal 05)" % stop, addr)
    r2 = _regs(g)
    if r2 is None:
        return Result(INCONCLUSIVE, "tras la parada, 'g' dio una respuesta inesperada", addr)
    rec["pc_tras_parada"] = hex(r2["pc"])
    if r2["pc"] != addr:
        return Result(INCONCLUSIVE, "paró con PC 0x%x != 0x%x: parada ajena al breakpoint de la prueba (otro breakpoint u otro hilo)" % (r2["pc"], addr), addr)
    if not control:
        return Result(PASS, "Z0 aceptado y parada con señal 05 en el mismo PC; control sin breakpoint omitido (--no-control)", addr)
    return _control(g, state, addr, rec)


def _after_timeout(g, addr, timeout, current, rec):
    """Venció el plazo tras `c`: interrumpir y mirar el PC. Con el PC actual, avanzar sin parar prueba que el Z0 se ignoró; con una
    dirección alternativa nada de lo observado lo prueba (no hay certeza de que el hilo pasara por ella)."""
    try:
        g.interrupt(timeout=CLEANUP_TIMEOUT)
    except (GdbError, OSError) as e:
        return Result(INCONCLUSIVE, "sin parada en %gs y la interrupción falló (%s: %s): el objetivo puede seguir en marcha" % (timeout, type(e).__name__, e), addr)
    r2 = _regs(g)
    if r2 is None:
        return Result(INCONCLUSIVE, "sin parada en %gs; tras interrumpir, 'g' dio una respuesta inesperada" % timeout, addr)
    rec["pc_tras_interrupcion"] = hex(r2["pc"])
    if not current:
        return Result(INCONCLUSIVE, "dirección alternativa 0x%x sin parada en %gs (el hilo está en 0x%x): no prueba que el hilo pasara por ella" % (addr, timeout, r2["pc"]),
                      addr, retryable=True)
    if r2["pc"] == addr:
        return Result(INCONCLUSIVE, "sin parada comunicada en %gs y el hilo sigue en 0x%x: parada silenciosa (el Z0 pudo funcionar sin avisar) "
                                    "o hilo sin ejecutar; el plazo por sí solo no prueba nada" % (timeout, addr), addr, retryable=True)
    return Result(FAIL, "el hilo ejecutó la instrucción de 0x%x con Z0 puesto y siguió hasta 0x%x sin parar: los breakpoints no se respetan "
                        "(típico del decoder LLVM; con 'Interpreter (static)' debería parar)" % (addr, r2["pc"]), addr)


def _control(g, state, pc, rec):
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
        rec["control"] = "sin parada en %gs" % CONTROL_TIMEOUT
        return Result(PASS, "Z0 aceptado, parada con señal 05 en el mismo PC y sin parada al repetir sin breakpoint", pc)
    rec["control"] = "paró: %s" % stop
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
    ap.add_argument("--elf", help="ELF: el PC debe caer en un segmento ejecutable; habilita los reintentos con direcciones de retorno")
    ap.add_argument("--code", help="rango de código lo-hi en hex (alternativa a --elf; sin reintentos)")
    ap.add_argument("--timeout", type=float, default=5.0, help="s a esperar la parada, por intento (def. %(default)s)")
    ap.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS, help="intentos en total; los reintentos usan otra dirección de retorno del hilo validada contra el ELF (def. %(default)s; 1 = sin reintentos)")
    ap.add_argument("--no-control", action="store_true", help="omitir el control sin breakpoint")
    ap.add_argument("--no-resume", action="store_true", help="dejar el objetivo detenido al terminar")
    ap.add_argument("--ppu-decoder", help="decoder PPU en uso, tal como lo indica el operador (si no, se toma del log con --log); solo se registra")
    ap.add_argument("--json", help="guardar el resultado completo, con un registro por intento (no debe existir)")
    ap.add_argument("--port", type=int, default=2346)
    return ap


def main(argv):
    ap = build_parser()
    a = ap.parse_args(argv[1:])
    if not a.thread and not a.log:
        ap.error("hace falta --thread o --log")
    from bp_probe import find_game_thread, make_alternates
    import opd_scan
    import validate_server
    if a.json and os.path.exists(a.json):
        print("error: %s ya existe" % a.json, file=sys.stderr)
        return 2
    tid = a.thread.zfill(16) if a.thread else find_game_thread(a.log, a.thread_name)
    ranges = validate_server.set_code_ranges(a.elf, a.code)
    img = opd_scan.Image.from_elf(a.elf) if a.elf else None
    alternates = make_alternates(img) if img else None
    if a.ppu_decoder:
        dec = {"valor": a.ppu_decoder, "fuente": "operador"}
    else:
        v = ppu_decoder_from_log(a.log) if a.log else None
        dec = {"valor": v, "fuente": "RPCS3.log (primera línea «PPU Decoder:»)"} if v else None
    g = Gdb("127.0.0.1", a.port, timeout=30.0)
    res = check_breakpoints(g, tid, a.timeout, is_code=validate_server.in_code if ranges else None,
                            control=not a.no_control, resume=not a.no_resume, attempts=a.attempts, alternates=alternates,
                            instr_info=make_instr_info(img), ppu_decoder=dec)
    print(res.report())
    if a.json:
        with open(a.json, "x", encoding="utf-8") as f:
            json.dump(dict(res.to_dict(), hilo=tid, codigo_salida=EXIT_CODES[res.verdict], t_fin=time.time()), f, ensure_ascii=False, indent=1)
    return EXIT_CODES[res.verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
