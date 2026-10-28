#!/usr/bin/env python3
"""Servidor RSP simulado que imita las reglas de `rpcs3/Emu/GDB.cpp` (0.0.43) que importan al proxy (#20).

Reglas copiadas del código (no del comportamiento observado del emulador):
  * una sola conexión; al conectarse el objetivo queda pausado;
  * cada paquete válido se reconoce con `+`; cada respuesta espera un `+` (otro carácter = desincronización,
    se anota en `protocol_errors`; `-` reenvía);
  * solo existen `qSupported`, `?`, `m`, `M`, `g`, `p`, `H`, `qC`, `qfThreadInfo`, `qAttached`, `vCont?`,
    `vCont;c|s`, `Z0`/`z0`, `k`; todo lo demás (incluidos `c`, `s`, `D`, `Z1`-`Z4`) responde vacío;
  * `vCont;c` espera leyendo byte a byte: solo `0x03` (o un `trigger_stop()` de la prueba) lo detiene; los
    demás bytes se tragan (`swallowed`);
  * si el cliente cierra el socket el servidor queda `frozen` (como RPCS3: error fatal «Tried to read char»).
Opciones de prueba (todas apagadas por defecto: el comportamiento base no cambia): `pc` (PC que devuelve `g`), `honor_bps` (un
`vCont;c` con un `Z0` en `pc` para al instante), `advance_on_cont` (cada `vCont;c` avanza `pc` 4 y sigue corriendo: un `Z0` ignorado),
`stop_always` (cada `vCont;c` para al instante, con o sin `Z0`), `reject_z0` (`Z0` responde vacío), `z0_reply` (respuesta fija a `Z0`),
`silent_pcs` (con `honor_bps`, un `Z0` en estos PC no para ni avisa: el hilo queda ahí), `step_advances` (cada `vCont;s` avanza `pc` 4).
Memoria simulada: `BASE`..`BASE+SIZE`, byte i = i & 0xFF. `m` corta en la primera dirección inválida.
Solo para pruebas: no escucha en el puerto 2345 salvo que se pida (por defecto puerto efímero).
"""
import socket
import threading

BASE, SIZE = 0x10000, 0x1000


class Eof(Exception):
    pass


class MockRsp:
    def __init__(self, host="127.0.0.1", port=0):
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind((host, port))
        self.ls.listen(1)
        self.ls.settimeout(0.1)
        self.port = self.ls.getsockname()[1]
        self.seen, self.protocol_errors, self.bps = [], [], set()
        self.swallowed, self.frozen, self.killed, self.paused = 0, False, False, False
        self.pc, self.honor_bps, self.advance_on_cont, self.stop_always = 0, False, False, False
        self.reject_z0, self.z0_reply = False, None
        self.silent_pcs, self.step_advances = set(), False
        self.connected = threading.Event()
        self._trigger = threading.Event()
        self._end = False
        self.conn = None
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    def close(self):
        self._end = True
        self.th.join(2)
        for s in (self.conn, self.ls):
            try:
                s.close()
            except (OSError, AttributeError):
                pass

    def trigger_stop(self):
        """Simula que un breakpoint se alcanza mientras el objetivo corre."""
        self._trigger.set()

    # --- E/S byte a byte ------------------------------------------------
    def _read(self):
        """Un byte, o None si pasaron 0,1 s sin datos."""
        if self._end:
            raise Eof()
        try:
            c = self.conn.recv(1)
        except socket.timeout:
            return None
        if not c:
            raise Eof()
        return c

    def _read_blocking(self):
        while True:
            c = self._read()
            if c is not None:
                return c

    def _frame(self, body: str) -> bytes:
        b = body.encode("latin1")
        return b"$" + b + b"#" + b"%02x" % (sum(b) & 0xFF)

    def _send_ack(self, body: str):
        """send_cmd_ack: envía y espera '+'."""
        while True:
            self.conn.sendall(self._frame(body))
            c = self._read_blocking()
            if c == b"+":
                return
            if c != b"-":
                self.protocol_errors.append("ack inesperado %r tras responder %r" % (c, body[:40]))
                return

    def _read_cmd(self):
        """Devuelve ('int',) o ('pkt', cuerpo). Reconoce con '+'/'-' como read_cmd del servidor."""
        while True:
            c = self._read_blocking()
            if c == b"\x03":
                return ("int", "")
            if c != b"$":
                if c == b"+":
                    c = self._read_blocking()
                if c != b"$":
                    self.protocol_errors.append("se esperaba '$', llegó %r" % c)
                    raise Eof()      # el servidor real lanza excepción aquí
            body = bytearray()
            while True:
                c = self._read_blocking()
                if c == b"#":
                    break
                if c == b"}":
                    c = bytes([self._read_blocking()[0] ^ 0x20])
                body += c
            ck = int(self._read_blocking() + self._read_blocking(), 16)
            # el servidor real suma los bytes ya des-escapados; con cuerpos ASCII sin '}' es lo mismo
            if ck != (sum(body) & 0xFF):
                self.conn.sendall(b"-")
                continue
            self.conn.sendall(b"+")
            return ("pkt", body.decode("latin1"))

    # --- órdenes --------------------------------------------------------
    def _mem(self, addr, n):
        out = bytearray()
        for a in range(addr, addr + n):
            if not (BASE <= a < BASE + SIZE):
                break
            out.append((a - BASE) & 0xFF)
        return out.hex()

    def _handle(self, cmd: str) -> str:
        self.seen.append(cmd)
        if cmd == "?":
            return "S05"
        if cmd.startswith("qSupported"):
            return "PacketSize=1200"
        if cmd == "vCont?":
            return "vCont;c;s;C;S"
        if cmd.startswith("m"):
            a, n = cmd[1:].split(",")
            r = self._mem(int(a, 16), int(n, 16))
            return r if r or int(n, 16) == 0 else "E01"
        if cmd == "g":
            return "0" * 1024 + "%016x" % self.pc + "0" * (1112 - 1040)
        if cmd.startswith("p"):
            return "%016x" % (0x1234 + int(cmd[1:], 16))
        if cmd.startswith("H"):
            return "OK"
        if cmd == "qC":
            return "QC0000000000000001"
        if cmd == "qAttached":
            return "1"
        if cmd.startswith("Z0,") and (self.reject_z0 or self.z0_reply is not None):
            return "" if self.reject_z0 else self.z0_reply
        if cmd.startswith("Z0,"):
            self.bps.add(int(cmd.split(",")[1], 16)); return "OK"
        if cmd.startswith("z0,"):
            self.bps.discard(int(cmd.split(",")[1], 16)); return "OK"
        return ""      # incluye c, s, D, Z1-Z4, qXfer...

    def _run(self):
        while not self._end:
            try:
                self.conn, _ = self.ls.accept()
                break
            except socket.timeout:
                continue
        else:
            return
        self.conn.settimeout(0.1)
        self.paused = True
        self.connected.set()
        try:
            while not self._end:
                kind, cmd = self._read_cmd()
                if kind == "int":
                    continue
                if cmd == "k":
                    self.seen.append(cmd); self.killed = True
                    continue
                if cmd.startswith("vCont;") and cmd[6:7] in ("c", "s") and len(cmd) == 7:
                    self.seen.append(cmd)
                    self.paused = False
                    if cmd[6] == "s" and self.step_advances:
                        self.pc += 4
                    if cmd[6] == "c":
                        self._trigger.clear()
                        immediate = self.stop_always or (self.honor_bps and self.pc in self.bps and self.pc not in self.silent_pcs)
                        if self.advance_on_cont and not immediate:
                            self.pc += 4
                        while not immediate:
                            if self._trigger.is_set():
                                break
                            c = self._read()
                            if c is None:
                                continue
                            if c == b"\x03":
                                break
                            self.swallowed += 1
                    self.paused = True
                    self._send_ack("S05")
                    continue
                if cmd.startswith("vCont;"):
                    self.seen.append(cmd)
                    self._send_ack("")
                    continue
                self._send_ack(self._handle(cmd))
        except Eof:
            if not self._end:
                self.frozen = True
