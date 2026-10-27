#!/usr/bin/env python3
"""Fase 2 del puente (#20): sondeo con `Z0` de quién escribe/lee `obj+0xd4` (byte de VWF del objeto de fuente).

Pone `Z0` en una lista de instrucciones `stb rS,0xd4(rA)` / `lbz rD,0xd4(rA)` / `ld rD,DS(rA)` del EBOOT, y en cada parada registra (JSONL):
PC, LR, el valor que se guarda (`stb`: byte de rS, decodificado de la palabra de instrucción del ELF) o el byte actual (`lbz`, leído
por `m`), el objeto (rA), si es un objeto de fuente real (`*(u32*)rA == 0xCFB7E8`, la vtable de docs/vwf_estado.md §2e; no depende de
direcciones fijas), r3..r10, los 3 primeros marcos de la cadena de retroceso (cada `ret` comprobado contra el ELF: la instrucción
anterior debe ser un `bl`/`bctrl`/`blrl`) y la etiqueta del paso de la ruta. Luego reanuda: quita el `Z0`, un paso, lo repone, continúa
(patrón validado en la Fase 0; continuar sin quitar el `Z0` vuelve a parar en el mismo PC).
Solo funciona con `PPU Decoder: Interpreter (static)`: con LLVM el servidor acepta `Z0` y no para nunca (docs/puente_rpcs3.md, Fase 0).
Control del costo: tope de registros por clave (sitio, LR, valor, es_fuente) y tope de impactos por sitio (luego se retira el `Z0`).
Al final, resumen con impactos/s y latencia por ciclo (para decidir entre `Z0` y la cueva de `patch_trace.py`).

Uso (con el proxy en marcha y el juego corriendo; ver docs/puente_rpcs3.md):
  python3 -I tools/rpcs3_bridge/bp_probe.py --elf work/eboot/EBOOT.elf --sites sitios.txt --out salida.jsonl
      --log <RPCS3.log> [--thread <id_hex>] [--route tests/rutas/R2.json --route-log <salida>/route.log]
      [--label-file etiqueta.txt] [--keep-after-route] [--watchdog 20] [--dump ra:0:0x80]... [--all-regs] [--duration 600] [--max-bps 8] [--cap-key 10] [--cap-site 500] [--port 2346]
`sitios.txt`: una línea por sitio, `0xVA [nombre]`; `#` comenta. La salida no debe existir. Si un sitio no es `stb`/`lbz` con
desplazamiento 0xd4, aborta. No cierra la conexión del proxy; al terminar quita sus `Z0` y deja el juego corriendo.
"""
import argparse
import json
import os
import re
import signal
import struct
import sys
import time
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "rpcs3_bridge"))
from gdbrsp import Gdb  # noqa: E402
from fase0 import parse_g  # noqa: E402
import opd_scan  # noqa: E402

FONT_VTABLE = 0xCFB7E8
BL_LIKE = (0x4E800421, 0x4E800021)      # bctrl, blrl


def decode_site(img, va):
    """Decodifica del ELF `stb rS,0xd4(rA)`, `lbz rD,0xd4(rA)` o `ld rD,DS(rA)` (forma DS, DS cualquiera). Falla cerrado."""
    w = img.u32(va)
    if w is not None and (w >> 26) in (34, 38) and (w & 0xFFFF) == 0xD4:
        return {"kind": "stb" if (w >> 26) == 38 else "lbz", "reg": (w >> 21) & 31, "ra": (w >> 16) & 31}
    if w is not None and (w >> 26) == 58 and (w & 3) == 0:
        return {"kind": "ld", "reg": (w >> 21) & 31, "ra": (w >> 16) & 31, "off": w & 0xFFFC}
    raise ValueError("0x%x no es stb/lbz con desplazamiento 0xd4 ni ld (palabra %s)" % (va, "%08x" % w if w is not None else None))


def is_call_return(img, ret):
    """¿La instrucción anterior a `ret` es una llamada (bl/bla/bctrl/blrl)? None si `ret` no está en la imagen."""
    w = img.u32(ret - 4) if ret >= 4 else None
    if w is None:
        return None
    return ((w >> 26) == 18 and bool(w & 1)) or w in BL_LIKE


def walk_chain(read, img, r1, depth=3):
    """Cadena de retroceso PPC64: bc=[sp]; la dirección de retorno de la función actual está en [bc+16]."""
    out, sp = [], r1
    for _ in range(depth):
        b = read(sp, 8)
        if len(b) < 8:
            break
        bc = struct.unpack(">Q", b)[0]
        if not (sp < bc <= 0xFFFFFFFF) or bc - sp > 0x100000:
            break
        r = read(bc + 16, 8)
        if len(r) < 8:
            break
        ret = struct.unpack(">Q", r)[0]
        out.append({"ret": hex(ret), "call": is_call_return(img, ret)})
        sp = bc
    return out


class RouteLabel:
    """Paso de la ruta en curso: el siguiente al último que `route_run.py` imprimió como terminado en route.log."""

    def __init__(self, route_json, route_log):
        with open(route_json, encoding="utf-8") as f:
            self.names = [s["name"] for s in json.load(f)["steps"]]
        self.log = route_log

    def _lines(self):
        try:
            with open(self.log, encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
        except OSError:
            return []

    def current(self):
        done = sum(1 for ln in self._lines() if ln.startswith("{") and '"name"' in ln)
        return self.names[done] if done < len(self.names) else "fin"

    def finished(self):
        return any(ln.startswith("RUTA ") for ln in self._lines())


class FileLabel:
    """Etiqueta manual: primera línea de un archivo que se edita a mano o con un script (cuando no hay ruta automática)."""

    def __init__(self, path):
        self.path = path

    def current(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return f.readline().strip() or None
        except OSError:
            return None

    def finished(self):
        return False


def find_game_thread(log_path):
    """Id del hilo `GameThread` según el log de RPCS3 (el id cambia entre arranques)."""
    pat = re.compile(r"PPU\[0x([0-9a-f]+)\] Thread \(GameThread\)")
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = pat.search(ln)
            if m:
                return m.group(1).zfill(16)
    raise RuntimeError("no hay GameThread en %s: pasar --thread" % log_path)


def parse_dumps(specs):
    out = []
    for sp in specs:
        rn, off, ln = sp.split(":")
        if rn != "ra" and not re.fullmatch(r"r(\d|[12]\d|3[01])", rn):
            raise ValueError("registro inválido en --dump: %s" % rn)
        out.append((sp, rn, int(off, 0), int(ln, 0)))
    return out


def load_sites(path, img):
    sites = {}
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.split("#")[0].strip()
            if not ln:
                continue
            p = ln.split(None, 1)
            va = int(p[0], 0)
            d = decode_site(img, va)
            d["name"] = p[1] if len(p) > 1 else "%08x" % va
            d["va"] = va
            sites[va] = d
    return sites


class Probe:
    def __init__(self, g, img, sites, tid, out, label=None, cap_key=10, cap_site=500, dumps=(), all_regs=False):
        self.g, self.img, self.sites, self.tid, self.out, self.label = g, img, sites, tid, out, label
        self.cap_key, self.cap_site = cap_key, cap_site
        self.dumps, self.all_regs = list(dumps), all_regs   # dumps: [(nombre, 'ra'|'rN', desplazamiento, largo)]
        self.keys = Counter()                 # (sitio, lr, val, es_fuente) -> veces
        self.site_hits = Counter()
        self.site_font = Counter()
        self.nonfont_logged = Counter()
        self.proc_ms, self.wait_ms = [], []
        self.retired = set()
        self.t0 = time.time()
        self.n = 0
        self.threads = []

    def emit(self, rec):
        self.out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.out.flush()

    def select(self, tid):
        self.g.cmd("Hg" + tid)

    def find_hit_thread(self):
        """Busca entre todos los hilos el que está parado en un sitio (el golpe lo dio otro hilo)."""
        if not self.threads:
            tl = self.g.cmd("qfThreadInfo")
            self.threads = [x for x in tl[1:].rstrip("l").split(",") if x] if tl.startswith("m") else []
        for t in self.threads:
            self.select(t)
            r = parse_g(self.g.cmd("g"))
            if r.get("pc") in self.sites:
                return t, r
        return None, None

    def handle_hit(self, t_wait, via=None):
        t1 = time.time()
        tid_hit = self.tid
        r = parse_g(self.g.cmd("g"))
        if r.get("pc") not in self.sites:
            r_juego = r
            tid_hit, r = self.find_hit_thread()
            self.select(self.tid)
            if tid_hit is None:
                r = r_juego
                rec = {"t": round(time.time() - self.t0, 3), "evento": "parada_sin_sitio" if via is None else "vigia_sin_sitio",
                       "pc": hex(r.get("pc", 0)), "lr": hex(r.get("lr", 0)), "hilo_juego": self.tid}
                if via is not None:      # tabla de PC de todos los hilos, para ver dónde está parado cada uno
                    rec["hilos"] = {}
                    for t in self.threads:
                        self.select(t)
                        rr = parse_g(self.g.cmd("g"))
                        rec["hilos"][t[-4:]] = [hex(rr.get("pc", 0)), hex(rr.get("lr", 0))]
                    self.select(self.tid)
                self.emit(rec)
                return False
            self.select(tid_hit)
        pc = r["pc"]
        s = self.sites[pc]
        obj = r["r%d" % s["ra"]]
        if s["kind"] == "ld":                # el valor que se va a cargar; no hay objeto de fuente que comprobar
            b = self.g.read(obj + s["off"], 8)
            val = int.from_bytes(b, "big") if len(b) == 8 else None
            vtable, is_font = None, True
        else:
            vt = self.g.read(obj, 4)
            vtable = struct.unpack(">I", vt)[0] if len(vt) == 4 else None
            is_font = vtable == FONT_VTABLE
            if s["kind"] == "stb":
                val = r["r%d" % s["reg"]] & 0xFF
            else:
                b = self.g.read(obj + 0xD4, 1)
                val = b[0] if b else None
        key = (pc, r["lr"], val, is_font)
        self.keys[key] += 1
        self.site_hits[pc] += 1
        if is_font:
            self.site_font[pc] += 1
        self.n += 1
        log_it = (self.keys[key] <= self.cap_key) if is_font else (self.nonfont_logged[pc] < 3)
        if log_it and not is_font:
            self.nonfont_logged[pc] += 1
        rec = None
        if log_it:
            rec = {"t": round(time.time() - self.t0, 3), "n": self.n, "label": self.label.current() if self.label else None,
                   "site": hex(pc), "name": s["name"], "kind": s["kind"], "tid": tid_hit, "lr": hex(r["lr"]), "obj": hex(obj),
                   "is_font": is_font, "vtable": hex(vtable) if vtable is not None else None, "val": (hex(val) if s["kind"] == "ld" and val is not None else val),
                   "r3_r10": [hex(r["r%d" % i]) for i in range(3, 11)], "r1": hex(r["r1"]),
                   "chain": walk_chain(self.g.read, self.img, r["r1"]), "veces_clave": self.keys[key]}
            if via:
                rec["via"] = via
            if self.dumps:
                rec["dump"] = {}
                for name, rn, off, ln in self.dumps:
                    base = r["r%d" % s["ra"]] if rn == "ra" else r[rn]
                    rec["dump"][name] = {"base": hex(base + off), "hex": self.g.read(base + off, ln).hex()}
            if self.all_regs:
                rec["gpr"] = {"r%d" % i: hex(r["r%d" % i]) for i in range(32)}
        # reanudar: quitar el Z0, un paso (en el hilo que paró), reponerlo
        if tid_hit != self.tid:
            self.g.cmd("Hc" + tid_hit)
        self.g.rm_bp(pc)
        step = self.g.step(timeout=20.0)
        if self.site_hits[pc] >= self.cap_site:
            self.retired.add(pc)
            self.emit({"t": round(time.time() - self.t0, 3), "evento": "sitio_retirado", "site": hex(pc), "impactos": self.site_hits[pc]})
        else:
            self.g.bp(pc)
        if tid_hit != self.tid:
            self.g.cmd("Hc" + self.tid)
            self.select(self.tid)
        t_proc = (time.time() - t1) * 1000
        self.proc_ms.append(t_proc)
        self.wait_ms.append(t_wait * 1000)
        if rec:
            rec.update(ms_espera=round(t_wait * 1000, 1), ms_proceso=round(t_proc, 1), paso=step)
            self.emit(rec)
        return True

    def summary(self):
        def pct(a, p):
            return round(sorted(a)[min(len(a) - 1, int(len(a) * p))], 1) if a else None
        dur = time.time() - self.t0
        per_site = {hex(v): {"nombre": self.sites[v]["name"], "tipo": self.sites[v]["kind"], "impactos": self.site_hits[v],
                             "de_fuente": self.site_font[v], "retirado": v in self.retired,
                             "claves": sum(1 for k in self.keys if k[0] == v)} for v in self.sites}
        valores = defaultdict(Counter)
        for (pc, lr, val, isf), c in self.keys.items():
            if isf:
                valores[hex(pc)][str(val)] += c
        return {"resumen": {"duracion_s": round(dur, 1), "impactos": self.n, "impactos_por_s": round(self.n / dur, 3) if dur else None,
                            "ms_proceso_mediana": pct(self.proc_ms, 0.5), "ms_proceso_p95": pct(self.proc_ms, 0.95),
                            "ms_espera_mediana": pct(self.wait_ms, 0.5), "por_sitio": per_site,
                            "valores_en_objetos_de_fuente": {k: dict(v) for k, v in valores.items()}}}


def main(argv):
    ap = argparse.ArgumentParser(description="Sondeo con Z0 de las escrituras/lecturas de obj+0xd4")
    ap.add_argument("--elf", required=True)
    ap.add_argument("--sites", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--log", help="RPCS3.log (para hallar el GameThread)")
    ap.add_argument("--thread")
    ap.add_argument("--route")
    ap.add_argument("--route-log")
    ap.add_argument("--keep-after-route", action="store_true", help="no parar cuando la ruta termina (seguir hasta --duration o una señal)")
    ap.add_argument("--label-file", help="etiqueta manual (primera línea del archivo), alternativa a --route")
    ap.add_argument("--duration", type=float, default=600.0)
    ap.add_argument("--watchdog", type=float, default=0.0, help="si no hay parada en N s, interrumpir y mirar el PC (detecta un hilo parado en un Z0 sin parada comunicada)")
    ap.add_argument("--dump", action="append", default=[], help="REG:OFF:LEN (REG = ra del sitio o rN); vuelca memoria en cada registro de impacto")
    ap.add_argument("--all-regs", action="store_true", help="incluir r0..r31 en cada registro")
    ap.add_argument("--max-bps", type=int, default=8)
    ap.add_argument("--cap-key", type=int, default=10)
    ap.add_argument("--cap-site", type=int, default=500)
    ap.add_argument("--port", type=int, default=2346)
    a = ap.parse_args(argv[1:])
    if os.path.exists(a.out):
        print("error: %s ya existe" % a.out, file=sys.stderr)
        return 1
    img = opd_scan.Image.from_elf(a.elf)
    sites = load_sites(a.sites, img)
    if not sites:
        print("error: sin sitios", file=sys.stderr)
        return 1
    if len(sites) > a.max_bps:
        print("error: %d sitios > --max-bps %d (subir de a poco; el techo del servidor no está medido)" % (len(sites), a.max_bps), file=sys.stderr)
        return 1
    tid = a.thread.zfill(16) if a.thread else find_game_thread(a.log)
    label = RouteLabel(a.route, a.route_log) if a.route and a.route_log else (FileLabel(a.label_file) if a.label_file else None)
    g = Gdb("127.0.0.1", a.port, timeout=30.0)
    g.cmd("Hg" + tid)
    g.cmd("Hc" + tid)
    with open(a.out, "x", encoding="utf-8") as out:
        p = Probe(g, img, sites, tid, out, label, a.cap_key, a.cap_site, parse_dumps(a.dump), a.all_regs)
        p.emit({"evento": "inicio", "hilo": tid, "sitios": {hex(v): d for v, d in sites.items()}, "cap_key": a.cap_key, "cap_site": a.cap_site})
        for va in sites:
            if not g.bp(va):
                p.emit({"evento": "error", "detalle": "Z0 rechazado en 0x%x" % va})
                for v in sites:
                    g.rm_bp(v)
                return 1
        deadline = time.time() + a.duration
        reason = "duracion"
        stop_req = []
        route_over = lambda: bool(label and not a.keep_after_route and label.finished())
        # SIGINT/SIGTERM piden una parada ordenada (quitar los Z0 antes de salir); una shell no interactiva deja SIGINT ignorado
        for sg in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sg, lambda *_: stop_req.append(1))
        try:
            while time.time() < deadline and not stop_req:
                if route_over():
                    reason = "ruta_terminada"
                    break
                t_c = time.time()
                g.cont()
                stop = None
                via = None
                while time.time() < deadline and not stop_req and not route_over():
                    try:
                        stop = g.wait_stop(timeout=2.0)
                        break
                    except (TimeoutError, OSError):
                        if a.watchdog and time.time() - t_c > a.watchdog:
                            stop = g.interrupt(timeout=20.0)
                            via = "vigia"
                            break
                        continue
                if stop is None:
                    if stop_req:
                        reason = "senal"
                    elif route_over():
                        reason = "ruta_terminada"
                    g.interrupt(timeout=20.0)
                    break
                p.handle_hit(time.time() - t_c, via)
        except KeyboardInterrupt:
            reason = "interrumpido"
        finally:
            if g.running:               # con el objetivo en marcha el proxy rechaza el rm: parar primero
                try:
                    g.interrupt(timeout=20.0)
                except Exception:   # noqa: BLE001
                    pass
            for v in sites:
                if v not in p.retired:
                    try:
                        g.rm_bp(v)
                    except Exception:   # noqa: BLE001
                        pass
            p.emit({"evento": "fin", "motivo": reason})
            p.emit(p.summary())
            try:
                g.cont()
            except Exception:   # noqa: BLE001
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
