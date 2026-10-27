#!/usr/bin/env python3
"""Resuelve llamadores indirectos de una función PS3 (PPC64, 32 bits efectivos) a partir de una imagen de memoria (#20).

Una llamada indirecta usa un descriptor de función (OPD): dos u32 consecutivos (código, TOC). Para una función F:
  1. verifica el formato OPD: el TOC sale del OPD de `e_entry` (ELF) o de --toc (obligatorio con --raw) y debe ser el
     segundo campo más frecuente entre los pares (u32 en código, u32 en datos) con >= --min-count (1000) apariciones;
     si no, ABORTA. Los TOC adicionales con >= --min-count pares a < 1 MiB del principal también se aceptan (el EBOOT usa 0xD5CAA8 y 0xD6CA90);
  2. busca los OPD (F, TOC);
  3. por cada OPD busca (a) u32 == dirección del OPD en datos (vtables, tablas, slots de TOC) y
     (b) direcciones construidas en código: `lis rD,hi` + `addi|ori rD,rD,lo` (con rD como destino o como origen),
     o `addis rD,r2,hi` + `addi` con r2 = TOC; también (c) u32 == F directo (punteros a código sin OPD).
Para cada acierto de datos muestra el contexto (palabras vecinas) y si los vecinos también son OPD válidos (vtable).

Entradas (una de dos):
  --elf <EBOOT.elf>                      mapea los PT_LOAD (rango de código = segmentos con PF_X)
  --raw <volcado> --base <VA> --code <lo-hi> --toc <r2>   volcado crudo de RAM que empieza en la VA `--base`
Salida: texto por stdout y, con --json <ruta>, un JSON (la ruta no debe existir). Direcciones en hex.
  python3 -I tools/opd_scan.py --elf work/eboot/EBOOT.elf --func 0x5cd7f0 [--toc 0xD5CAA8] [--json out.json]
Limitaciones: solo ve lo que hay en la imagen (un ELF estático no trae punteros construidos en runtime; para eso
hace falta un volcado de RAM); las direcciones construidas se buscan en una ventana de 8 instrucciones.
"""
import argparse
import array
import json
import os
import struct
import sys
from collections import Counter

WINDOW = 8


class ScanError(Exception):
    pass


class Image:
    """Lista de segmentos [(va, bytes)] y rangos ejecutables [(lo, hi)]."""

    def __init__(self, segs, code, entry_toc=None):
        self.segs = sorted(segs)
        self.code = code
        self.entry_toc = entry_toc
        for (a, da), (b, _) in zip(self.segs, self.segs[1:]):
            if a + len(da) > b:
                raise ScanError("segmentos solapados")

    @classmethod
    def from_elf(cls, path):
        with open(path, "rb") as f:
            d = f.read()
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 2:
            raise ScanError("no es un ELF64 big-endian")
        (entry,) = struct.unpack(">Q", d[24:32])
        (phoff,) = struct.unpack(">Q", d[32:40])
        phentsize, phnum = struct.unpack(">HH", d[54:58])
        segs, code = [], []
        for i in range(phnum):
            t, fl, off, va, _pa, fs, _ms, _al = struct.unpack(">IIQQQQQQ", d[phoff + i * phentsize:phoff + (i + 1) * phentsize])
            if t != 1 or fs == 0:
                continue
            if off + fs > len(d):
                raise ScanError("PT_LOAD fuera del archivo")
            segs.append((va, d[off:off + fs]))
            if fl & 1:
                code.append((va, va + fs))
        if not code:
            raise ScanError("sin segmentos ejecutables")
        img = cls(segs, code)
        ec, et = img.u32(entry), img.u32(entry + 4)
        if ec is None or et is None or not img.in_code(ec):
            raise ScanError("e_entry 0x%x no apunta a un OPD (código, TOC) válido" % entry)
        img.entry_toc = et
        return img

    @classmethod
    def from_raw(cls, path, base, code):
        with open(path, "rb") as f:
            return cls([(base, f.read())], [code])

    def in_code(self, a):
        return any(lo <= a < hi for lo, hi in self.code)

    def u32(self, va):
        for b, d in self.segs:
            if b <= va and va + 4 <= b + len(d):
                return struct.unpack(">I", d[va - b:va - b + 4])[0]
        return None

    def words(self):
        """Itera (va, u32) en todas las posiciones alineadas a 4."""
        for b, d in self.segs:
            n = len(d) // 4
            arr = array.array("I", d[:n * 4])
            if sys.byteorder == "little":
                arr.byteswap()
            start = (-b) % 4
            for i in range(start, n):
                yield b + 4 * i, arr[i]


def detect_toc(img, toc_hint, min_count):
    """Valida el formato OPD (código, TOC) y devuelve ([toc principal, otros TOC], estadística, palabras). Falla cerrado.

    El TOC no se adivina por proporción (hay otras tablas de pares con otro segundo campo): sale del OPD de
    `e_entry` (ELF) o de --toc (volcado crudo), y debe ser además el segundo campo más frecuente entre los
    pares (código, dato) alineados a 4, con al menos `min_count` ocurrencias.
    """
    anchor = img.entry_toc
    if anchor is not None and toc_hint is not None and anchor != toc_hint:
        raise ScanError("--toc 0x%x != TOC del OPD de e_entry 0x%x" % (toc_hint, anchor))
    toc = toc_hint if toc_hint is not None else anchor
    if toc is None:
        raise ScanError("con --raw hay que dar --toc (r2 del módulo, p. ej. de Ghidra)")
    w = dict(img.words())
    spans = [(b, b + len(d)) for b, d in img.segs]
    cnt = Counter()
    for va, v in w.items():
        if img.in_code(v) and v % 4 == 0:
            nxt = w.get(va + 4)
            if nxt and not img.in_code(nxt) and any(lo <= nxt < hi for lo, hi in spans):
                cnt[nxt] += 1
    n = cnt.get(toc, 0)
    top = cnt.most_common(3)
    stat = {"toc": toc, "toc_source": "--toc" if toc_hint is not None else "e_entry", "pairs_with_toc": n,
            "top_second_fields": [[hex(k), c] for k, c in top]}
    if n < min_count:
        raise ScanError("solo %d pares (código, 0x%x) < %d: el formato OPD no se confirma (%s)" % (n, toc, min_count, stat))
    if not top or top[0][0] != toc:
        raise ScanError("0x%x no es el segundo campo más frecuente: %s" % (toc, stat))
    # Otras bases de TOC: la TOC de PPC64 cubre ±32 KiB, así que un binario grande usa varias (el EBOOT: 0xD5CAA8 y
    # 0xD6CA90; los hilos del juego corren con r2=0xD6CA90, docs/puente_rpcs3.md Fase 0). Se aceptan las que tienen
    # >= min_count pares, no el cero, y cuya base queda a < 1 MiB de la principal.
    others = sorted(k for k, c in cnt.items() if k != toc and k and c >= min_count and abs(k - toc) < (1 << 20))
    stat["other_tocs"] = [[hex(k), cnt[k]] for k in others]
    return [toc] + others, stat, w


def ppc_scan(img, targets, tocs):
    """Direcciones construidas en código. Devuelve {valor: [va_de_la_primera_instrucción, ...]}."""
    hits = {t: [] for t in targets}
    for lo, hi in img.code:
        seg = next((d for b, d in img.segs if b <= lo and hi <= b + len(d)), None)
        if seg is None:
            continue
        b = next(b for b, d in img.segs if d is seg)
        n = (hi - lo) // 4
        off = (lo - b)
        arr = array.array("I", seg[off:off + n * 4])
        if sys.byteorder == "little":
            arr.byteswap()
        for i in range(n):
            ins = arr[i]
            op = ins >> 26
            if op != 15:                     # addis rD,rA,imm (lis si rA=0)
                continue
            rd, ra, imm = (ins >> 21) & 31, (ins >> 16) & 31, ins & 0xFFFF
            if ra == 0:
                bases = (0,)
            elif ra == 2:
                bases = tocs
            else:
                continue
            hi16 = (imm - 0x10000 if imm & 0x8000 else imm) << 16
            for j in range(i + 1, min(i + 1 + WINDOW, n)):
                nx = arr[j]
                nop = nx >> 26
                if nop not in (14, 24):      # addi / ori
                    continue
                if nop == 14:
                    nrd, nra, nimm = (nx >> 21) & 31, (nx >> 16) & 31, nx & 0xFFFF
                    lo16 = nimm - 0x10000 if nimm & 0x8000 else nimm
                else:                         # ori rA,rS,imm: rS en bits 21-25, rA en 16-20
                    nrd, nra, nimm = (nx >> 16) & 31, (nx >> 21) & 31, nx & 0xFFFF
                    lo16 = nimm
                if nra != rd:
                    continue
                for base in bases:
                    val = ((base + hi16 + lo16) if nop == 14 else ((base + hi16) | lo16)) & 0xFFFFFFFF
                    if val in hits and (lo + 4 * i) not in hits[val]:
                        hits[val].append(lo + 4 * i)
                if nrd == rd:
                    break                    # el registro se sobreescribe
    return hits


def scan(img, func, toc_hint=None, min_count=1000):
    tocs, stat, w = detect_toc(img, toc_hint, min_count)
    out = {"func": func, "format": stat, "opds": [], "direct_code_pointers": []}
    opd_addrs = [va for va, v in w.items() if v == func and w.get(va + 4) in tocs]
    out["direct_code_pointers"] = sorted(va for va, v in w.items() if v == func and va not in opd_addrs)
    is_opd = lambda va: va in w and img.in_code(w[va]) and w.get(va + 4) in tocs
    ctor = ppc_scan(img, set(opd_addrs) | {func}, tocs)
    for o in sorted(opd_addrs):
        refs = sorted(va for va, v in w.items() if v == o)
        rec = {"opd": o, "toc": w.get(o + 4), "align8": o % 8 == 0, "data_refs": [], "code_built": sorted(ctor[o])}
        for r in refs:
            nb = []
            for k in range(-2, 3):
                v = w.get(r + 4 * k)
                nb.append({"va": r + 4 * k, "u32": v, "is_opd": bool(v is not None and is_opd(v))})
            rec["data_refs"].append({"va": r, "neighbors": nb, "vtable_like": sum(1 for x in nb if x["is_opd"]) >= 2})
        out["opds"].append(rec)
    out["code_built_func_direct"] = sorted(ctor[func])
    return out


def report(res):
    f = res["format"]
    L = ["formato OPD: TOC 0x%08x (%s), %d pares; otros TOC aceptados: %s; segundos campos más frecuentes: %s" % (f["toc"], f["toc_source"], f["pairs_with_toc"], f["other_tocs"], f["top_second_fields"]),
         "función 0x%08x: %d OPD, %d u32 a código sin OPD" % (res["func"], len(res["opds"]), len(res["direct_code_pointers"]))]
    for o in res["opds"]:
        L.append("  OPD 0x%08x (TOC 0x%08x, alineado a 8: %s): %d referencias en datos, %d direcciones construidas en código" %
                 (o["opd"], o["toc"], o["align8"], len(o["data_refs"]), len(o["code_built"])))
        for r in o["data_refs"]:
            L.append("    dato 0x%08x%s: %s" % (r["va"], " [tipo vtable]" if r["vtable_like"] else "",
                                               " ".join(("*" if n["va"] == r["va"] else "") + ("OPD:" if n["is_opd"] else "") + ("%08x" % n["u32"] if n["u32"] is not None else "--") for n in r["neighbors"])))
        for c in o["code_built"]:
            L.append("    código 0x%08x construye la dirección del OPD" % c)
    for d in res["direct_code_pointers"]:
        L.append("  u32 == función en 0x%08x" % d)
    for c in res["code_built_func_direct"]:
        L.append("  código 0x%08x construye la dirección de la función" % c)
    return "\n".join(L)


def _int(s):
    return int(s, 0)


def main(argv):
    ap = argparse.ArgumentParser(description="Llamadores indirectos por OPD")
    ap.add_argument("--elf")
    ap.add_argument("--raw")
    ap.add_argument("--base", type=_int)
    ap.add_argument("--code", help="lo-hi (hex) del rango de código del volcado crudo")
    ap.add_argument("--func", type=_int, required=True)
    ap.add_argument("--toc", type=_int)
    ap.add_argument("--min-count", type=int, default=1000)
    ap.add_argument("--json")
    a = ap.parse_args(argv[1:])
    try:
        if bool(a.elf) == bool(a.raw):
            raise ScanError("usar --elf o --raw")
        if a.raw:
            if a.base is None or not a.code:
                raise ScanError("--raw requiere --base y --code lo-hi")
            lo, hi = (int(x, 16) for x in a.code.split("-"))
            img = Image.from_raw(a.raw, a.base, (lo, hi))
        else:
            img = Image.from_elf(a.elf)
        if a.json and os.path.exists(a.json):
            raise ScanError("%s ya existe" % a.json)
        res = scan(img, a.func, a.toc, a.min_count)
    except (ScanError, OSError) as e:
        print("ERROR:", e, file=sys.stderr)
        return 1
    print(report(res))
    if a.json:
        with open(a.json, "x") as f:
            json.dump(res, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
