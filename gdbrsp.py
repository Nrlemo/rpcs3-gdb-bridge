#!/usr/bin/env python3
"""Cliente mínimo del protocolo GDB remoto (RSP) para el servidor de RPCS3.

RPCS3 levanta el servidor en cada arranque si `config.yml` tiene `GDB Server: <host>:<puerto>`
(por defecto `127.0.0.1:2345`); en el log aparece «GDB: Started listening on …».
Se usa como módulo (clase `Gdb`) o por línea de órdenes para consultas sueltas.

IMPORTANTE (leído en `rpcs3/Emu/GDB.cpp` y verificado en el log):
  * **Al aceptar la conexión el emulador queda PAUSADO**; `cont()` lo reanuda.
  * **No hay forma de desconectarse.** El servidor no implementa `D`, y cuando `recv` devuelve 0
    (el cliente cerró) lanza el error fatal «Tried to read char, but no data was available»: el hilo
    muere y **el emulador queda congelado**. O sea: una sola sesión por arranque, y el proceso cliente
    no puede terminar mientras se quiera seguir usando el programa (ver `dbg_session.py` y `proxy.py`).
  * **`m` no respeta el `PacketSize` anunciado** (0x1200): acepta cualquier longitud y responde en un
    solo paquete. Como el coste por paquete es fijo (~41 ms), conviene leer en bloques grandes.
    Devuelve lo leído hasta la primera dirección inválida (una respuesta corta marca el fin del tramo).
La memoria solo se puede leer con el emulador detenido.

Uso:
  python3 -I gdbrsp.py probe                      capacidades del servidor y soporte de breakpoints/watchpoints
  python3 -I gdbrsp.py read <addr> <len>          vuelca memoria (hex + ASCII)
  python3 -I gdbrsp.py search <hex|str:TEXTO> [ini] [fin]   busca un patrón en memoria
  python3 -I gdbrsp.py regs                       registros del hilo actual
Direcciones en hex (0x...) o decimal.
"""
import binascii
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 2345
# Registros PPU que expone RPCS3 (numeración del paquete `g`): 0-31 GPR, 32-63 FPR, 64 PC, 65 MSR, 66 CR, 67 LR, 68 CTR, 69 XER.
REG_NAMES = {64: "PC", 65: "MSR", 66: "CR", 67: "LR", 68: "CTR", 69: "XER"}


class GdbError(Exception):
    pass


class Gdb:
    def __init__(self, host=HOST, port=PORT, timeout=20.0):
        self.s = socket.create_connection((host, port), timeout=5.0)
        # Sin TCP_NODELAY cada paquete paga el retardo de Nagle + ACK diferido (~30-40 ms): con ~2 KiB de
        # memoria por paquete, barrer 256 MiB pasaría de minutos a horas.
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.settimeout(timeout)
        self.buf = b""
        self.packet_size = 0x1000
        # Al aceptar la conexión RPCS3 PAUSA la emulación ("Emulation is being paused"): se entra ya detenido.
        self.running = False
        feats = self.cmd("qSupported:multiprocess+;xmlRegisters=powerpc")
        self.features = feats
        for f in feats.split(";"):
            if f.startswith("PacketSize="):
                self.packet_size = int(f.split("=")[1], 16)

    # --- transporte ---------------------------------------------------
    def _send(self, data: str):
        p = data.encode()
        ck = sum(p) & 0xFF
        self.s.sendall(b"$" + p + b"#" + f"{ck:02x}".encode())

    def _recv_raw(self) -> bytes:
        while True:
            i = self.buf.find(b"$")
            j = self.buf.find(b"#", i + 1) if i >= 0 else -1
            if i >= 0 and j >= 0 and len(self.buf) >= j + 3:
                body = self.buf[i + 1:j]
                self.buf = self.buf[j + 3:]
                self.s.sendall(b"+")
                return body
            chunk = self.s.recv(65536)
            if not chunk:
                raise GdbError("conexión cerrada por RPCS3")
            self.buf += chunk

    def drain(self):
        """Descarta lo que el servidor haya dejado pendiente (y lo reconoce).

        Si queda una respuesta sin leer, el siguiente paquete llega donde el servidor espera un ACK
        y la sesión se desincroniza («Wrong acknowledge character received»).
        """
        old = self.s.gettimeout()
        self.s.settimeout(0.2)
        try:
            while True:
                chunk = self.s.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
        except (TimeoutError, OSError):
            pass
        finally:
            self.s.settimeout(old)
        if b"$" in self.buf:
            self.s.sendall(b"+")
        self.buf = b""

    def cmd(self, data: str, retries=1) -> str:
        """Envía un paquete y devuelve la respuesta (descarta los '+' de ack)."""
        for _ in range(retries + 1):
            self._send(data)
            r = self._recv_raw().decode("latin1")
            if r:
                return r
        return ""

    # --- control ------------------------------------------------------
    def stop(self):
        """Detiene el emulador (break 0x03). Idempotente."""
        if not self.running:
            return
        self.s.sendall(b"\x03")
        self._recv_raw()
        self.running = False

    def cont(self):
        """Reanuda la emulación. No espera respuesta (el servidor solo contesta al parar)."""
        # Sin drain(): podría comerse una parada pendiente (docs/servidor_gdb_rpcs3.md, «Reanudar y paradas»).
        self._send("c")
        self.running = True

    def wait_stop(self, timeout=120.0) -> str:
        """Espera una parada (p. ej. un breakpoint). Devuelve el paquete de estado."""
        old = self.s.gettimeout()
        self.s.settimeout(timeout)
        try:
            while True:
                r = self._recv_raw().decode("latin1")
                if r:  # los paquetes vacíos no son la parada: se ignoran
                    self.running = False
                    return r
        finally:
            self.s.settimeout(old)

    def step(self, timeout=20.0) -> str:
        """Ejecuta una instrucción (`s`) y devuelve el paquete de parada. Solo con el emulador detenido."""
        self._send("s")
        self.running = True
        return self.wait_stop(timeout)

    def interrupt(self, timeout=20.0) -> str:
        """Detiene un objetivo en marcha con 0x03 y devuelve el paquete de parada."""
        self.s.sendall(b"\x03")
        self.running = True
        return self.wait_stop(timeout)

    # --- memoria ------------------------------------------------------
    def read(self, addr: int, length: int) -> bytes:
        """Lee memoria (el emulador debe estar detenido).

        Devuelve lo que haya podido leer: b'' si la primera dirección es inválida, o un bloque más
        corto que `length` si el tramo termina antes (el servidor corta en la primera inválida).
        """
        out = b""
        while length > 0:
            n = min(self.CHUNK, length)
            r = self.cmd(f"m{addr:x},{n:x}")
            if not r or r.startswith("E"):
                break
            b = binascii.unhexlify(r)
            out += b
            if len(b) < n:       # fin del tramo mapeado
                break
            addr += n
            length -= n
        return out

    def write(self, addr: int, data: bytes) -> bool:
        r = self.cmd(f"M{addr:x},{len(data):x}:" + binascii.hexlify(data).decode())
        return r == "OK"

    # El servidor no limita `m`. Medido contra RPCS3 0.0.43: 4 KiB ~0,1 MiB/s, 64-256 KiB ~28 MiB/s,
    # 1 MiB ~17 MiB/s, 4 MiB ~6,6 MiB/s. El óptimo está en 256 KiB.
    CHUNK = 256 << 10

    def chunk(self) -> int:
        return self.CHUNK

    def regions(self, start=0, end=1 << 32, grain=1 << 20, progress=None):
        """Mapa aproximado de memoria: prueba una lectura corta cada `grain` y agrupa los tramos legibles.

        Devuelve [(ini, fin)] con granularidad `grain` (un tramo legible puede empezar algo antes).
        """
        out, a, cur = [], start, None
        while a < end:
            ok = bool(self.read(a, 16))
            if ok and cur is None:
                cur = a
            elif not ok and cur is not None:
                out.append((cur, a))
                cur = None
            if progress:
                progress(a, ok)
            a += grain
        if cur is not None:
            out.append((cur, min(a, end)))
        return out

    def search(self, pat: bytes, start: int, end: int, progress=None):
        """Busca `pat` en [start, end), saltando los tramos no legibles. Devuelve las direcciones.

        Lee de a un paquete y arrastra `len(pat)-1` bytes de solape para no perder coincidencias
        a caballo entre dos lecturas. Un tramo ilegible corta el solape (no se cose a través del hueco).
        """
        hits, step, a = [], self.chunk(), start
        carry, carry_addr = b"", 0
        while a < end:
            n = min(step, end - a)
            blk = self.read(a, n)
            if blk:
                buf = (carry + blk) if carry and carry_addr + len(carry) == a else blk
                base = a - (len(buf) - len(blk))
                i = buf.find(pat)
                while i >= 0:
                    hits.append(base + i)
                    i = buf.find(pat, i + 1)
                carry, carry_addr = blk[-(len(pat) - 1):] if len(pat) > 1 else b"", a + len(blk) - (len(pat) - 1)
            else:
                carry = b""
            if progress:
                progress(a, len(hits), bool(blk))
            a += n
        return hits

    # --- registros ----------------------------------------------------
    def regs(self) -> dict:
        """Lee los registros del hilo actual. Prefiere `p<n>` (RPCS3 lo soporta y evita parsear `g`)."""
        out = {}
        for n in list(range(32)) + list(REG_NAMES):
            r = self.cmd(f"p{n:x}")
            if not r or r.startswith("E"):
                continue
            try:
                v = int(r, 16)
            except ValueError:
                continue
            out[REG_NAMES.get(n, f"r{n}")] = v
        return out

    # --- puntos de parada ---------------------------------------------
    def bp(self, addr: int, kind=0, size=4) -> bool:
        """Z<kind>: 0 software, 1 hardware, 2 write watch, 3 read watch, 4 access watch."""
        return self.cmd(f"Z{kind},{addr:x},{size:x}") == "OK"

    def rm_bp(self, addr: int, kind=0, size=4) -> bool:
        return self.cmd(f"z{kind},{addr:x},{size:x}") == "OK"

    def close(self):
        """Cierra el socket. ATENCIÓN: esto **congela el emulador** (el servidor no sobrevive a que el
        cliente cierre; `D` no existe). Úsalo solo cuando la corrida ya se da por terminada."""
        try:
            self.s.close()
        except OSError:
            pass


def _int(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _dump(addr, data):
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        print(f"{addr+i:08x}  {binascii.hexlify(row, b' ').decode():<47}  {txt}")


def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    g = Gdb()
    try:
        c = argv[1]
        if c == "probe":
            print("qSupported:", g.features)
            print("?:", g.cmd("?"))
            print("hilos:", g.cmd("qfThreadInfo"))
            g.stop()
            print("detenido. ? ->", g.cmd("?"))
            for k, name in ((0, "Z0 breakpoint software"), (1, "Z1 breakpoint hardware"),
                            (2, "Z2 watchpoint escritura"), (3, "Z3 watchpoint lectura"),
                            (4, "Z4 watchpoint acceso")):
                r = g.cmd(f"Z{k},10000,4")
                ok = r == "OK"
                if ok:
                    g.cmd(f"z{k},10000,4")
                print(f"  {name}: {'SÍ' if ok else 'no'} ({r!r})")
            g.cont()
        elif c == "read":
            g.stop()
            a, n = _int(argv[2]), _int(argv[3])
            d = g.read(a, n)
            if not d:
                print("tramo no mapeado o error")
            else:
                _dump(a, d)
            g.cont()
        elif c == "search":
            pat = argv[2]
            pat = pat[4:].encode() if pat.startswith("str:") else binascii.unhexlify(pat)
            ini = _int(argv[3]) if len(argv) > 3 else 0x10000
            fin = _int(argv[4]) if len(argv) > 4 else 0x10000000
            g.stop()
            t0 = time.time()

            def prog(a, n, mapped):
                if (a >> 20) % 16 == 0:
                    print(f"  {a:#010x} hits={n} {time.time()-t0:.0f}s", file=sys.stderr)
            hits = g.search(pat, ini, fin, prog)
            print(f"{len(hits)} coincidencias en {time.time()-t0:.0f}s:")
            for h in hits[:40]:
                print(f"  {h:#010x}")
            g.cont()
        elif c == "regs":
            g.stop()
            for k, v in g.regs().items():
                print(f"  {k:<4} {v:#018x}")
            g.cont()
        else:
            print(__doc__, file=sys.stderr)
            return 2
    finally:
        g.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
