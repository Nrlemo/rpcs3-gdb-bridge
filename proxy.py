#!/usr/bin/env python3
"""Proxy RSP persistente para el servidor GDB de RPCS3 (#20).

Problema (leído en `rpcs3/Emu/GDB.cpp`, ver `docs/verificacion_watchpoints_rpcs3.md` §1.2): el servidor
solo atiende una conexión por arranque, no implementa `D` y, si el cliente cierra el socket, el hilo
muere y el emulador queda congelado. Este proxy abre UNA conexión al servidor y no la cierra nunca;
los clientes se conectan al proxy, de a uno por vez, y pueden irse y volver.

Qué hace con cada paquete del cliente:
  * `D`            -> responde `OK` él mismo; el servidor no se entera (no-op).
  * `k`            -> se bloquea (apagaría RPCS3: `GracefulShutdown`); con `--allow-kill` se reenvía.
  * `c` / `s`      -> se traducen a `vCont;c` / `vCont;s`. El servidor no tiene `c` ni `s` planos
                      (responde vacío y no reanuda); hipótesis por lectura de código, sin probar en vivo.
  * `0x03`         -> se reenvía si el objetivo corre.
  * cualquier otro -> se reenvía tal cual y se devuelve la respuesta.
Al conectarse un cliente nuevo con el objetivo corriendo, el proxy lo interrumpe (`0x03`) y descarta esa
parada: todo cliente empieza con el objetivo detenido, como al conectarse a RPCS3. Si un cliente se va con el
objetivo corriendo, su parada futura se descarta (no se la come el siguiente cliente).
Mientras el objetivo corre, un paquete que no sea `0x03` se rechaza con `E01` (el servidor se tragaría esos bytes).

Si el servidor cierra la conexión, el proxy termina con código 2 (falla cerrada). Un Ctrl-C solo avisa;
el segundo en 5 s sale (al salir el proceso se cierra el socket y RPCS3 queda congelado).

Registro: JSONL, una línea por evento (`t`, `ev`, `dir`, `body` truncado a 200 car., `len`). No se sobreescribe
un registro existente.

Uso:
  python3 -I tools/rpcs3_bridge/proxy.py [--upstream 127.0.0.1:2345] [--listen 127.0.0.1:2346]
        [--log work/tmp/bridge/<fecha>.jsonl] [--allow-kill] [--no-translate]
Luego los clientes (p. ej. `tools/gdbrsp.py` con el puerto del proxy) se conectan a --listen.
"""
import argparse
import json
import os
import selectors
import signal
import socket
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRUNC = 200


class UpstreamClosed(Exception):
    pass


def frame(body: bytes) -> bytes:
    return b"$" + body + b"#" + b"%02x" % (sum(body) & 0xFF)


class PacketParser:
    """Separa un flujo RSP en eventos: ('pkt', cuerpo_crudo, checksum_ok), ('ack',), ('nak',), ('int',), ('junk', byte)."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes) -> list:
        self.buf += data
        out = []
        while self.buf:
            c = self.buf[0]
            if c == 0x2B:
                out.append(("ack", b"", True)); del self.buf[0]
            elif c == 0x2D:
                out.append(("nak", b"", True)); del self.buf[0]
            elif c == 0x03:
                out.append(("int", b"", True)); del self.buf[0]
            elif c == 0x24:
                j = self.buf.find(b"#")
                if j < 0 or len(self.buf) < j + 3:
                    break
                body = bytes(self.buf[1:j])
                try:
                    ok = int(bytes(self.buf[j + 1:j + 3]), 16) == (sum(body) & 0xFF)
                except ValueError:
                    ok = False
                del self.buf[:j + 3]
                out.append(("pkt", body, ok))
            else:
                out.append(("junk", bytes([c]), False)); del self.buf[0]
        return out


class Bridge:
    def __init__(self, upstream, listen=("127.0.0.1", 2346), log_path=None, allow_kill=False, translate=True):
        if tuple(upstream) == tuple(listen):
            raise ValueError("--listen no puede ser igual a --upstream")
        self.upstream_addr, self.listen_addr = tuple(upstream), tuple(listen)
        self.allow_kill, self.translate = allow_kill, translate
        self.log_path, self._logf = log_path, None
        self.up = self.lsock = self.client = None
        self.up_parser, self.cl_parser = PacketParser(), PacketParser()
        self.pending = []          # respuestas que el servidor nos debe: {"body", "deliver"}
        self.running = False       # se reenvió un vCont;c|s y aún no hubo respuesta
        self.last_fwd, self.nak_retries, self.last_to_client = b"", 0, b""
        self.sel = selectors.DefaultSelector()
        self._client_registered = False
        self._stop = False
        self.listen_port = None

    # --- registro -------------------------------------------------------
    def _log(self, ev, **kw):
        if self._logf is None:
            return
        rec = {"t": round(time.time(), 3), "ev": ev}
        for k, v in kw.items():
            if isinstance(v, (bytes, bytearray)):
                rec["len"] = len(v)
                v = bytes(v).decode("latin1")[:TRUNC]
            rec[k] = v
        self._logf.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._logf.flush()

    # --- ciclo de vida --------------------------------------------------
    def open(self):
        if self.log_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
            self._logf = open(self.log_path, "x", encoding="utf-8")   # 'x': falla si existe
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(self.listen_addr)
        self.lsock.listen(1)
        self.listen_port = self.lsock.getsockname()[1]
        # Se conecta al servidor al final: esa conexión PAUSA el emulador.
        self.up = socket.create_connection(self.upstream_addr, timeout=5.0)
        self.up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.up.settimeout(None)
        self.sel.register(self.lsock, selectors.EVENT_READ, "listen")
        self.sel.register(self.up, selectors.EVENT_READ, "up")
        self._log("open", upstream="%s:%d" % self.upstream_addr, listen="%s:%d" % (self.listen_addr[0], self.listen_port))

    def stop(self):
        self._stop = True

    def serve(self) -> int:
        try:
            while not self._stop:
                for key, _ in self.sel.select(0.1):
                    if key.data == "listen":
                        self._accept()
                    elif key.data == "up":
                        self._on_upstream()
                    elif key.data == "client":
                        self._on_client()
                self._sync_client_reg()
        except UpstreamClosed as e:
            self._log("upstream_closed", detail=str(e))
            return 2
        finally:
            self._log("exit")
            if self._logf:
                self._logf.close()
        return 0

    # --- clientes -------------------------------------------------------
    def _accept(self):
        s, addr = self.lsock.accept()
        if self.client is not None:
            self._log("client_rejected", addr="%s:%d" % addr)
            s.close()
            return
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(5.0)
        self.client, self.cl_parser = s, PacketParser()
        self._log("client_connect", addr="%s:%d" % addr, running=self.running)
        if self.running:
            self.up.sendall(b"\x03")
            self._log("interrupt_on_attach", dir="p2u")
            for p in self.pending:
                p["deliver"] = False

    def _drop_client(self, why):
        self._log("client_disconnect", why=why)
        if self._client_registered:
            self.sel.unregister(self.client)
            self._client_registered = False
        try:
            self.client.close()
        except OSError:
            pass
        self.client = None
        for p in self.pending:
            p["deliver"] = False

    def _sync_client_reg(self):
        """El cliente solo se atiende sin respuestas huérfanas pendientes del servidor."""
        orphans = any(not p["deliver"] for p in self.pending)
        want = self.client is not None and not orphans
        if want and not self._client_registered:
            self.sel.register(self.client, selectors.EVENT_READ, "client")
            self._client_registered = True
        elif not want and self._client_registered:
            self.sel.unregister(self.client)
            self._client_registered = False

    def _to_client(self, body: bytes):
        self.last_to_client = frame(body)
        try:
            self.client.sendall(self.last_to_client)
        except OSError as e:
            self._drop_client("envío: %s" % e)
            return
        self._log("pkt", dir="p2c", body=body)

    def _on_client(self):
        try:
            data = self.client.recv(65536)
        except OSError as e:
            self._drop_client("recv: %s" % e)
            return
        if not data:
            self._drop_client("eof")
            return
        for kind, body, ok in self.cl_parser.feed(data):
            if self.client is None:
                return
            if kind == "int":
                self._log("int", dir="c2p", forwarded=self.running)
                if self.running:
                    self.up.sendall(b"\x03")
            elif kind == "nak":
                if self.last_to_client:
                    self.client.sendall(self.last_to_client)
            elif kind == "pkt":
                if not ok:
                    self._log("bad_checksum", dir="c2p", body=body)
                    self.client.sendall(b"-")
                    continue
                self.client.sendall(b"+")
                self._log("pkt", dir="c2p", body=body)
                self._dispatch(body)
            elif kind == "junk":
                self._log("junk", dir="c2p", body=body)

    def _local_reply(self, body: bytes, why: str):
        self._log("local", why=why, body=body)
        self._to_client(body)

    def _dispatch(self, body: bytes):
        if self.pending:
            self._local_reply(b"E01", "paquete con el servidor ocupado")
            return
        if body == b"D" or body.startswith(b"D;"):
            self._local_reply(b"OK", "detach = no-op")
            return
        if body == b"k":
            if not self.allow_kill:
                self._log("kill_blocked")
                return
            self._forward(body, expect_reply=False)
            return
        if self.translate and body in (b"c", b"s"):
            self._log("translate", frm=body, to=b"vCont;" + body)
            body = b"vCont;" + body
        self._forward(body)

    def _forward(self, body: bytes, expect_reply=True):
        self.up.sendall(frame(body))
        self.last_fwd, self.nak_retries = body, 0
        self._log("pkt", dir="p2u", body=body)
        if expect_reply:
            self.pending.append({"body": body, "deliver": True})
            self.running = body.startswith(b"vCont;")

    # --- servidor -------------------------------------------------------
    def _on_upstream(self):
        data = self.up.recv(65536)
        if not data:
            raise UpstreamClosed("RPCS3 cerró la conexión")
        for kind, body, ok in self.up_parser.feed(data):
            if kind == "ack":
                continue
            if kind == "nak":
                self.nak_retries += 1
                if self.nak_retries > 3:
                    raise UpstreamClosed("el servidor rechazó 3 veces el mismo paquete")
                self.up.sendall(frame(self.last_fwd))
            elif kind == "pkt":
                if not ok:
                    self._log("bad_checksum", dir="u2p", body=body)
                    self.up.sendall(b"-")
                    continue
                self.up.sendall(b"+")
                self._log("pkt", dir="u2p", body=body)
                if not self.pending:
                    self._log("unsolicited", body=body)
                    continue
                p = self.pending.pop(0)
                self.running = False
                if p["deliver"] and self.client is not None:
                    self._to_client(body)
                else:
                    self._log("orphan_reply", body=body)
            else:
                self._log("junk", dir="u2p", body=body)


def _addr(s):
    h, _, p = s.rpartition(":")
    return h, int(p)


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--upstream", default="127.0.0.1:2345")
    ap.add_argument("--listen", default="127.0.0.1:2346")
    ap.add_argument("--log", default=os.path.join(ROOT, "work/tmp/bridge", time.strftime("%Y%m%d_%H%M%S") + ".jsonl"))
    ap.add_argument("--allow-kill", action="store_true")
    ap.add_argument("--no-translate", action="store_true")
    a = ap.parse_args(argv[1:])
    b = Bridge(_addr(a.upstream), _addr(a.listen), a.log, a.allow_kill, not a.no_translate)
    b.open()
    print("proxy: %s -> %s:%d | log %s" % (a.upstream, b.listen_addr[0], b.listen_port, a.log), flush=True)
    last = [0.0]

    def on_int(*_):
        if time.time() - last[0] < 5:
            b.stop()
        else:
            last[0] = time.time()
            print("Ctrl-C: salir cierra la conexión a RPCS3 y lo CONGELA. Repetí en 5 s para salir.", flush=True)

    signal.signal(signal.SIGINT, on_int)
    return b.serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
