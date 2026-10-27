#!/usr/bin/env python3
"""Fase 0 del puente (#20): ¿el servidor GDB real de RPCS3 (intérprete PPU) para en un Z0 y reanuda? (docs/puente_rpcs3.md)

Se conecta AL PROXY (no al 2345) con el juego ya corriendo; conectar el proxy pausa el emulador. Pruebas, en orden:
  T0 hilos (`qfThreadInfo`) y registros por `g` de cada uno; se elige el hilo del juego (el primero con LR en el EBOOT, o el
     id dado como 3.er argumento). Sin `Hg<id>` el servidor usa el PRIMER hilo PPU, que no es el del juego.
  T1 5 pasos con `s`                     (¿S05 y avanza el PC?)
  T2 Z0 a pocas instrucciones sin saltos  (¿para exactamente ahí?)
  T3 marcha libre + interrupción         (¿el juego corre? PCs distintos entre muestras)
  T4 bucle de Z0 recurrente x5           (rm -> paso -> Z0 -> continuar; el patrón de la Fase 2)
  T6 continuar SIN quitar el Z0         (¿vuelve a parar en la misma instrucción?)
  T5 `D`, desconexión del cliente, reconexión y lectura (¿el proxy mantiene viva la sesión real?)
Uso: python3 -I tools/rpcs3_bridge/fase0.py <salida.json> [puerto_proxy=2346] [id_hilo_hex]
No cierra nunca la conexión del proxy al servidor. La salida no debe existir.
"""
import json
import os
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from gdbrsp import Gdb  # noqa: E402

CODE = (0x10000, 0xCEBA68)
TOC = 0xD5CAA8
OFFS = {"pc": 1024, "msr": 1040, "cr": 1056, "lr": 1064, "ctr": 1080, "xer": 1096, "fpscr": 1104}
R = {}


def say(*a):
    print(*a, flush=True)


def parse_g(h):
    out = {"len": len(h)}
    if len(h) != 1112:
        return out
    out.update({f"r{i}": int(h[i * 16:i * 16 + 16], 16) for i in range(32)})
    for k in ("pc", "lr", "ctr"):
        out[k] = int(h[OFFS[k]:OFFS[k] + 16], 16)
    out["cr"] = int(h[OFFS["cr"]:OFFS["cr"] + 8], 16)
    return out


def regs(g):
    return parse_g(g.cmd("g"))


def in_code(a):
    return CODE[0] <= a < CODE[1]


def is_branch(ins):
    op = ins >> 26
    return op in (16, 17, 18, 19)       # bc, sc, b, bclr/bcctr


def main(argv):
    out = argv[1]
    port = int(argv[2]) if len(argv) > 2 else 2346
    if os.path.exists(out):
        print("error: %s ya existe" % out, file=sys.stderr)
        return 1
    g = Gdb("127.0.0.1", port, timeout=30.0)
    R["features"] = g.features
    R["T0"] = {"stop_reason": g.cmd("?")}
    tl = g.cmd("qfThreadInfo")
    ids = [x for x in tl[1:].rstrip("l").split(",") if x] if tl.startswith("m") else []
    threads = {}
    for tid in ids:
        g.cmd("Hg" + tid)
        rr = regs(g)
        threads[tid] = {"pc": hex(rr.get("pc", 0)), "lr": hex(rr.get("lr", 0)), "r2": hex(rr.get("r2", 0))}
    R["T0"]["hilos"] = threads
    want = argv[3].zfill(16) if len(argv) > 3 else None
    tid = want or next((t for t in ids if in_code(int(threads[t]["lr"], 16))), ids[0] if ids else None)
    R["T0"]["hilo_elegido"] = tid
    if tid:
        g.cmd("Hg" + tid)
        g.cmd("Hc" + tid)
    r0 = regs(g)
    R["T0"].update({k: (hex(v) if isinstance(v, int) and k != "len" else v) for k, v in r0.items() if k in ("len", "pc", "lr", "ctr", "cr", "r1", "r2", "r3")})
    R["T0"]["pc_en_codigo"] = in_code(r0.get("pc", 0))
    R["T0"]["r2_es_TOC"] = r0.get("r2") == TOC
    say("T0", R["T0"])

    # T1: pasos
    pcs = []
    for _ in range(5):
        s = g.step(timeout=20.0)
        pcs.append((s, hex(regs(g).get("pc", 0))))
    R["T1"] = {"pasos": pcs, "pc_avanza": len({p for _, p in pcs}) > 1, "todos_S05": all(s == "S05" for s, _ in pcs)}
    say("T1", R["T1"])

    # T2: Z0 pocas instrucciones adelante, sin saltos
    pc = regs(g)["pc"]
    code = g.read(pc, 0x40)
    words = struct.unpack(">%dI" % (len(code) // 4), code[: len(code) // 4 * 4])
    k = next((i for i in range(2, len(words)) if not any(is_branch(w) for w in words[:i])), None)
    t2 = {"pc": hex(pc)}
    if k is None:
        t2["omitida"] = "no hay 2+ instrucciones sin salto"
    else:
        x = pc + 4 * k
        t2.update({"z0": hex(x), "ok_Z0": g.bp(x)})
        g.cont()
        try:
            stop = g.wait_stop(30.0)
            t2.update({"stop": stop, "pc_al_parar": hex(regs(g)["pc"])})
            t2["para_exacto"] = regs(g)["pc"] == x
        except Exception as e:      # noqa: BLE001
            t2["error"] = repr(e)
            g.interrupt()
        g.rm_bp(x)
    R["T2"] = t2
    say("T2", t2)

    # T3: marcha libre y muestras
    samples = []
    for _ in range(8):
        g.cont()
        time.sleep(2.0)
        s = g.interrupt(timeout=20.0)
        rr = regs(g)
        samples.append({"stop": s, "pc": hex(rr.get("pc", 0)), "lr": hex(rr.get("lr", 0))})
    pcs = [x["pc"] for x in samples]
    R["T3"] = {"muestras": samples, "pcs_distintos": len(set(pcs))}
    say("T3", R["T3"]["pcs_distintos"], "PCs distintos de 8")

    # T4: bucle de Z0 recurrente sobre candidatos (LR muestreados, repetidos primero)
    from collections import Counter
    cands = [int(a, 16) for a, _ in Counter(x["lr"] for x in samples).most_common() if in_code(int(a, 16))]
    t4 = {"candidatos": [hex(c) for c in cands], "intentos": []}
    for a in cands[:4]:
        att = {"addr": hex(a), "hits": []}
        ok = g.bp(a)
        att["ok_Z0"] = ok
        for i in range(5):
            g.cont()
            try:
                stop = g.wait_stop(20.0)
            except Exception:       # noqa: BLE001
                att["sin_impacto_en_20s"] = i
                g.interrupt()
                break
            rr = regs(g)
            att["hits"].append({"stop": stop, "pc": hex(rr["pc"]), "lr": hex(rr["lr"]), "r3": hex(rr["r3"]), "r4": hex(rr["r4"])})
            g.rm_bp(a)
            st = g.step(timeout=20.0)       # salir del breakpoint
            att["hits"][-1]["tras_paso"] = [st, hex(regs(g)["pc"])]
            g.bp(a)
        g.rm_bp(a)
        t4["intentos"].append(att)
        if len(att["hits"]) == 5:
            t4["bucle_completo"] = hex(a)
            break
    R["T4"] = t4
    say("T4", json.dumps(t4)[:600])

    # T6: continuar sin quitar el Z0 (usa la dirección del bucle completo de T4, o la de T2)
    a6 = int(t4["bucle_completo"], 16) if "bucle_completo" in t4 else (int(t2["z0"], 16) if "z0" in t2 else None)
    t6 = {"addr": hex(a6) if a6 else None}
    if a6:
        g.bp(a6)
        g.cont()
        try:
            t6["hit1"] = [g.wait_stop(20.0), hex(regs(g)["pc"])]
            g.cont()                                  # sin rm_bp ni paso
            t0_ = time.time()
            t6["hit2"] = [g.wait_stop(10.0), hex(regs(g)["pc"])]
            t6["hit2_en_s"] = round(time.time() - t0_, 2)
            t6["se_queda_en_la_misma_instruccion"] = t6["hit1"][1] == t6["hit2"][1]
        except Exception as e:      # noqa: BLE001
            t6["error"] = repr(e)
            g.interrupt()
        g.rm_bp(a6)
    R["T6"] = t6
    say("T6", t6)

    # T5: D, cierre del cliente, reconexión
    t5 = {"D": g.cmd("D")}
    pc5 = regs(g)["pc"]
    g.close()
    time.sleep(1.0)
    try:
        g2 = Gdb("127.0.0.1", port, timeout=30.0)
        t5["reconecta"] = True
        t5["stop_reason"] = g2.cmd("?")
        if tid:
            g2.cmd("Hg" + tid)
        t5["lee_codigo"] = g2.read(pc5, 16).hex()
        t5["pc_igual"] = regs(g2)["pc"] == pc5
        g2.cont()
        time.sleep(3.0)
        s = g2.interrupt(timeout=20.0)
        t5["marcha_tras_reconectar"] = s
        g2.cont()                 # se deja el juego corriendo
    except Exception as e:      # noqa: BLE001
        t5["error"] = repr(e)
    R["T5"] = t5
    say("T5", t5)
    with open(out, "x") as f:
        json.dump(R, f, indent=1)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BaseException:
        if len(sys.argv) > 1 and not os.path.exists(sys.argv[1]) and R:
            with open(sys.argv[1] + ".parcial", "w") as f:
                json.dump(R, f, indent=1)
        raise
