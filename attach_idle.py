#!/usr/bin/env python3
"""Control A/B: conectarse al proxy SIN poner Z0, reanudar con `c` y quedarse conectado N segundos.
Sirve para saber si un estancamiento lo causan los Z0 o el solo hecho de estar conectado.
Uso: python3 -I attach_idle.py <segundos> <id_hilo_hex> [--port 2346]
Al terminar: interrumpe, reanuda y sale (el proxy mantiene la conexión con RPCS3).
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gdbrsp import Gdb  # noqa: E402


def build_parser():
    ap = argparse.ArgumentParser(description="Conectado sin Z0, corriendo, N segundos")
    ap.add_argument("segundos", type=float)
    ap.add_argument("thread", help="id del hilo a depurar (hex); el servidor usa por defecto el primer hilo, que no suele ser el del programa")
    ap.add_argument("--port", type=int, default=2346, help="puerto del proxy (def. %(default)s)")
    return ap


def main(argv):
    a = build_parser().parse_args(argv[1:])
    tid = a.thread.zfill(16)
    g = Gdb("127.0.0.1", a.port, timeout=30.0)
    g.cmd("Hg" + tid)
    g.cmd("Hc" + tid)
    g.cont()
    print("conectado y corriendo (sin Z0)", flush=True)
    t_end = time.time() + a.segundos
    while time.time() < t_end:
        time.sleep(1)
    g.interrupt(timeout=20.0)
    g.cont()
    print("fin", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
