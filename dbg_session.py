#!/usr/bin/env python3
"""Sesión de depuración persistente contra el servidor GDB de RPCS3.

Existe por una limitación del servidor (ver `gdbrsp.py`): **si el cliente cierra el socket, el
hilo del servidor muere y el emulador queda congelado**. Como además solo se admite una conexión por
arranque, y cada arranque cuesta varios minutos, no se puede explorar con invocaciones sueltas:
hace falta un proceso que mantenga la conexión abierta mientras se le mandan trabajos.

Este proceso se queda vivo, con el socket abierto, y ejecuta los fragmentos de Python que aparezcan
en `<dir>/in/` (por orden alfabético), con el objeto `Gdb` disponible como `g`. La salida de cada
fragmento va a `<dir>/out/<nombre>.txt` y el fragmento se mueve a `<dir>/done/`.

Uso: python3 -I dbg_session.py [<dir=./dbg_session>]
     # y desde fuera:  cp trabajo.py dbg_session/in/01_trabajo.py ; esperar dbg_session/out/01_trabajo.py.txt
Terminar: matar el proceso (el emulador quedará congelado: hacerlo solo al final de la corrida).
"""
import io
import os
import sys
import time
import traceback
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.getcwd()   # directorio desde el que se lanzó; se expone a los fragmentos
from gdbrsp import Gdb  # noqa: E402


def main(argv) -> int:
    d = argv[1] if len(argv) > 1 else os.path.join(ROOT, "dbg_session")
    for sub in ("in", "out", "done"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    log = open(os.path.join(d, "session.log"), "a", buffering=1)

    def say(*a):
        print(*a, file=log)

    g = Gdb(timeout=600)
    env = {"g": g, "ROOT": ROOT, "time": time}
    say(f"[{time.strftime('%H:%M:%S')}] conectado; emulación PAUSADA por la conexión. {g.features}")
    open(os.path.join(d, "ready"), "w").write(str(os.getpid()))
    try:
        while True:
            jobs = sorted(f for f in os.listdir(os.path.join(d, "in")) if f.endswith(".py"))
            if not jobs:
                time.sleep(0.3)
                continue
            j = jobs[0]
            src = os.path.join(d, "in", j)
            code = open(src).read()
            say(f"[{time.strftime('%H:%M:%S')}] ejecutando {j}")
            buf = io.StringIO()
            t0 = time.time()
            try:
                with contextlib.redirect_stdout(buf):
                    exec(compile(code, j, "exec"), env)   # noqa: S102 - fragmentos propios de depuración
            except Exception:
                buf.write("\n--- EXCEPCIÓN ---\n" + traceback.format_exc())
            buf.write(f"\n[{time.time()-t0:.1f}s]\n")
            with open(os.path.join(d, "out", j + ".txt"), "w") as f:
                f.write(buf.getvalue())
            os.replace(src, os.path.join(d, "done", j))
            say(f"[{time.strftime('%H:%M:%S')}] {j} listo ({time.time()-t0:.1f}s)")
    except KeyboardInterrupt:
        say("interrumpido: se reanuda la emulación y se deja el socket abierto")
        try:
            g.cont()
        except OSError:
            pass
        time.sleep(3600)   # no cerrar el socket: cerrarlo congela el emulador
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
