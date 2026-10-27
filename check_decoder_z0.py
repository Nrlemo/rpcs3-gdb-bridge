#!/usr/bin/env python3
"""Control de la Fase 0 (#20): con el decoder LLVM, ¿el servidor acepta `Z0` pero nunca para? (docs/puente_rpcs3.md)

Se conecta al PROXY con el juego corriendo con `PPU Decoder: Recompiler (LLVM)`. Toma muestras de LR con interrupciones
(LR en el EBOOT = direcciones de retorno que el juego recorre), pone `Z0` en cada una y espera 20 s por un impacto; prueba
también un `s`. Los mismos pasos con el intérprete dieron impactos (fase0.py).
Uso: python3 -I tools/rpcs3_bridge/fase0_llvm.py <salida.json> <id_hilo_hex> [puerto_proxy=2346]
"""
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gdbrsp import Gdb  # noqa: E402
from validate_server import parse_g, in_code  # noqa: E402

R = {}


def main(argv):
    out, tid = argv[1], argv[2].zfill(16)
    port = int(argv[3]) if len(argv) > 3 else 2346
    if os.path.exists(out):
        print("error: %s ya existe" % out, file=sys.stderr)
        return 1
    g = Gdb("127.0.0.1", port, timeout=30.0)
    g.cmd("Hg" + tid)
    g.cmd("Hc" + tid)
    regs = lambda: parse_g(g.cmd("g"))
    samples = []
    for _ in range(8):
        g.cont()
        time.sleep(2.0)
        s = g.interrupt(timeout=20.0)
        r = regs()
        samples.append({"stop": s, "pc": hex(r.get("pc", 0)), "lr": hex(r.get("lr", 0))})
    R["muestras"] = samples
    R["pcs_distintos"] = len({x["pc"] for x in samples})
    print("muestras: %d PCs distintos de 8" % R["pcs_distintos"], flush=True)
    cands = [int(a, 16) for a, _ in Counter(x["lr"] for x in samples).most_common() if in_code(int(a, 16))][:4]
    R["z0"] = []
    for a in cands:
        rec = {"addr": hex(a), "reply": g.cmd("Z0,%x,4" % a)}
        g.cont()
        try:
            rec["stop"] = g.wait_stop(20.0)
            rec["pc"] = hex(regs()["pc"])
        except Exception:       # noqa: BLE001
            rec["sin_impacto_en_20s"] = True
            g.interrupt(timeout=20.0)
        g.cmd("z0,%x,4" % a)
        R["z0"].append(rec)
        print(rec, flush=True)
    t = {}
    try:
        t["paso"] = g.step(timeout=15.0)
    except Exception as e:      # noqa: BLE001
        t["paso_error"] = repr(e)
        try:
            g.interrupt(timeout=20.0)
        except Exception:       # noqa: BLE001
            pass
    R["step"] = t
    print("step:", t, flush=True)
    with open(out, "x") as f:
        json.dump(R, f, indent=1)
    g.cont()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
