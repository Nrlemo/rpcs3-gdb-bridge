#!/usr/bin/env python3
"""Escáner de fugas: comprueba que un repo git no contiene datos de ningún juego (ni en el estado actual ni en el historial).

Revisa:
  * árbol (HEAD), modo ESTRICTO: extensiones prohibidas (ejecutables, imágenes, volcados, registros comprimidos...), archivos binarios
    (con byte NUL), archivos grandes, texto CJK (kana/kanji), rutas absolutas de usuario y cualquier coincidencia con la DENYLIST;
  * historial COMPLETO: cada blob de `git rev-list --objects --all` con las mismas reglas, más mensajes, autores y etiquetas.
    Las coincidencias de la denylist en blobs antiguos se muestran como AVISO (se admiten por decisión del proyecto: constantes
    de versiones viejas) y fallan solo con --strict-history; en mensajes, autores y etiquetas siempre fallan.

Denylist (archivo externo, que NO debe versionarse en este repo): una entrada por línea; `#` comenta; `re:<regex>` para expresiones
regulares; el resto son cadenas literales sin distinguir mayúsculas.
Uso: python3 -I tools/check_no_game_data.py --denylist <archivo> [--repo .] [--mode tree|history|both] [--strict-history]
                                            [--max-size 204800]
Código de salida: 0 sin FALLA; 1 si hay alguna FALLA.
"""
import argparse
import os
import re
import subprocess
import sys

FORBIDDEN_EXT = {".elf", ".self", ".sprx", ".bin", ".iso", ".pkg", ".psarc", ".sdat", ".wtd", ".png", ".jpg", ".jpeg", ".dds",
                 ".bmp", ".gif", ".tga", ".mp4", ".jsonl", ".gz", ".zip", ".7z", ".rar"}
CJK = re.compile("[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uff00-\uffef]")
ABS_PATH = re.compile(r"(/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+|/storage/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\)")


class Deny:
    def __init__(self, path):
        self.lit, self.rx = [], []
        with open(path, encoding="utf-8") as f:
            for ln in f:
                ln = ln.rstrip("\n")
                if not ln.strip() or ln.lstrip().startswith("#"):
                    continue
                if ln.startswith("re:"):
                    self.rx.append((ln, re.compile(ln[3:], re.I)))
                else:
                    self.lit.append((ln, ln.lower()))

    def hits(self, text):
        low = text.lower()
        out = [orig for orig, l in self.lit if l in low]
        out += [orig for orig, r in self.rx if r.search(text)]
        return out


def git(repo, *args, inp=None):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, input=inp)
    if p.returncode != 0:
        raise SystemExit("git %s falló: %s" % (" ".join(args), p.stderr.decode("utf-8", "replace")))
    return p.stdout


def read_blobs(repo, shas):
    """Devuelve {sha: bytes} leyendo en bloque con cat-file --batch."""
    out = git(repo, "cat-file", "--batch", inp=("\n".join(shas) + "\n").encode())
    res, i = {}, 0
    while i < len(out):
        j = out.index(b"\n", i)
        parts = out[i:j].split()
        if len(parts) < 3:
            break
        sha, typ, size = parts[0].decode(), parts[1], int(parts[2])
        res[sha] = (typ, out[j + 1:j + 1 + size])
        i = j + 1 + size + 1
    return res


def check_blob(name, data, deny, max_size, findings, deny_level):
    """Reglas comunes; las coincidencias de la denylist van con el nivel `deny_level` ('FALLA' o 'AVISO')."""
    ext = os.path.splitext(name)[1].lower()
    if ext in FORBIDDEN_EXT:
        findings.append(("FALLA", name, "extensión prohibida %s" % ext))
    if len(data) > max_size:
        findings.append(("FALLA", name, "archivo de %d bytes (> %d)" % (len(data), max_size)))
    if b"\0" in data:
        findings.append(("FALLA", name, "contenido binario (byte NUL)"))
        return
    txt = data.decode("utf-8", "replace")
    if CJK.search(txt):
        findings.append(("FALLA", name, "texto CJK (kana/kanji)"))
    m = ABS_PATH.search(txt)
    if m:
        findings.append(("FALLA", name, "ruta absoluta de usuario (%s...)" % m.group(0)))
    for h in deny.hits(txt):
        findings.append((deny_level, name, "denylist: %s" % h))
    for h in deny.hits(name):
        findings.append(("FALLA", name, "nombre de archivo en la denylist: %s" % h))


def scan_tree(repo, deny, max_size):
    findings = []
    ents = git(repo, "ls-tree", "-r", "-z", "HEAD").split(b"\0")
    items = []
    for e in ents:
        if not e:
            continue
        meta, path = e.split(b"\t", 1)
        mode, typ, sha = meta.decode().split()
        if typ == "blob":
            items.append((sha, path.decode("utf-8", "replace")))
    blobs = read_blobs(repo, [s for s, _ in items]) if items else {}
    for sha, path in items:
        check_blob(path, blobs[sha][1], deny, max_size, findings, "FALLA")
    return list(dict.fromkeys(findings)), len(items)


def scan_history(repo, deny, max_size, strict):
    findings = []
    objs = [o for o in git(repo, "rev-list", "--objects", "--all").decode("utf-8", "replace").splitlines() if o.strip()]
    names = {}
    for o in objs:
        p = o.split(None, 1)
        names.setdefault(p[0], p[1] if len(p) > 1 else "")
    blobs = read_blobs(repo, list(names))
    nblobs = 0
    for sha, (typ, data) in blobs.items():
        if typ != b"blob":
            continue
        nblobs += 1
        check_blob(names[sha] or sha[:10], data, deny, max_size, findings, "FALLA" if strict else "AVISO")
    # mensajes, autores y etiquetas: siempre FALLA
    log = git(repo, "log", "--all", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e").decode("utf-8", "replace")
    ncommits = 0
    for rec in log.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        ncommits += 1
        h, *rest = rec.split("\x00")
        text = "\n".join(rest)
        for hit in deny.hits(text):
            findings.append(("FALLA", "commit %s" % h[:10], "mensaje/autor con denylist: %s" % hit))
        if CJK.search(text):
            findings.append(("FALLA", "commit %s" % h[:10], "texto CJK en mensaje/autor"))
        if ABS_PATH.search(text):
            findings.append(("FALLA", "commit %s" % h[:10], "ruta absoluta de usuario en mensaje"))
    tags = git(repo, "for-each-ref", "--format=%(refname)%00%(contents)%00%(taggername)%00%(taggeremail)", "refs/tags").decode("utf-8", "replace")
    for ln in tags.splitlines():
        for hit in deny.hits(ln):
            findings.append(("FALLA", "etiqueta", "denylist: %s" % hit))
    return list(dict.fromkeys(findings)), nblobs, ncommits


def main(argv):
    ap = argparse.ArgumentParser(description="Escáner de fugas de datos de un juego en un repo git (árbol e historial)")
    ap.add_argument("--denylist", required=True)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--mode", choices=("tree", "history", "both"), default="both")
    ap.add_argument("--strict-history", action="store_true", help="las coincidencias de la denylist en blobs antiguos también fallan")
    ap.add_argument("--max-size", type=int, default=204800)
    a = ap.parse_args(argv[1:])
    deny = Deny(a.denylist)
    if not (deny.lit or deny.rx):
        print("ERROR: la denylist está vacía", file=sys.stderr)
        return 2
    allf = []
    if a.mode in ("tree", "both"):
        f, n = scan_tree(a.repo, deny, a.max_size)
        print("ÁRBOL (HEAD, estricto): %d archivos revisados, %d FALLA" % (n, sum(1 for x in f if x[0] == "FALLA")))
        allf += [("árbol",) + x for x in f]
    if a.mode in ("history", "both"):
        f, nb, nc = scan_history(a.repo, deny, a.max_size, a.strict_history)
        print("HISTORIAL: %d blobs, %d commits revisados; %d FALLA, %d AVISO" % (
            nb, nc, sum(1 for x in f if x[0] == "FALLA"), sum(1 for x in f if x[0] == "AVISO")))
        allf += [("historial",) + x for x in f]
    seen = set()
    for where, level, name, why in allf:
        key = (where, level, name, why)
        if key in seen:
            continue
        seen.add(key)
        print("  [%s] %s %s: %s" % (level, where, name, why))
    nfail = sum(1 for x in allf if x[1] == "FALLA")
    print("RESULTADO: %s" % ("FALLA (%d)" % nfail if nfail else "OK"))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
