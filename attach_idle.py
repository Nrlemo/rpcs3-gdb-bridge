#!/usr/bin/env python3
"""Control A/B de la Fase 2 (#20): conectarse al proxy SIN poner Z0, reanudar con `c` y quedarse conectado N segundos.
Sirve para saber si el estancamiento del juego lo causan los Z0 o el solo hecho de estar conectado.
Uso: python3 -I tools/rpcs3_bridge/attach_idle.py <segundos> [id_hilo_hex] [puerto=2346]
Al terminar: interrumpe, reanuda y sale (el proxy mantiene la conexión con RPCS3).
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from gdbrsp import Gdb  # noqa: E402

secs = float(sys.argv[1])
tid = (sys.argv[2] if len(sys.argv) > 2 else "1000006").zfill(16)
g = Gdb("127.0.0.1", int(sys.argv[3]) if len(sys.argv) > 3 else 2346, timeout=30.0)
g.cmd("Hg" + tid)
g.cmd("Hc" + tid)
g.cont()
print("conectado y corriendo (sin Z0)", flush=True)
t_end = time.time() + secs
while time.time() < t_end:
    time.sleep(1)
g.interrupt(timeout=20.0)
g.cont()
print("fin", flush=True)
