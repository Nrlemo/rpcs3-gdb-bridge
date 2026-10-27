#!/usr/bin/env python3
"""Proxy RSP (tools/rpcs3_bridge/proxy.py) contra un servidor simulado (mock_rsp.py), sin RPCS3 (#20).
Puertos efímeros; nunca se conecta al 2345. Uso: python3 -I tests/test_rpcs3_bridge.py
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "rpcs3_bridge"))
import mock_rsp  # noqa: E402
import proxy  # noqa: E402
from gdbrsp import Gdb  # noqa: E402


class Base(unittest.TestCase):
    bridge_kw = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mock = mock_rsp.MockRsp()
        self.log = os.path.join(self.tmp.name, "t.jsonl")
        self.br = proxy.Bridge(("127.0.0.1", self.mock.port), ("127.0.0.1", 0), self.log, **self.bridge_kw)
        self.br.open()
        self.mock.connected.wait(2)
        self.rc = []
        self.th = threading.Thread(target=lambda: self.rc.append(self.br.serve()), daemon=True)
        self.th.start()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.br.stop()
        self.th.join(3)
        self.mock.close()
        self.tmp.cleanup()

    def client(self):
        c = Gdb("127.0.0.1", self.br.listen_port, timeout=3.0)
        self.clients.append(c)
        return c

    def events(self):
        with open(self.log) as f:
            return [json.loads(x) for x in f]

    def assertClean(self):
        self.assertEqual(self.mock.protocol_errors, [])
        self.assertFalse(self.mock.frozen, "el proxy cerró la conexión al servidor")


class TestRelay(Base):
    def test_lectura_y_registros_idénticos_a_directo(self):
        c = self.client()
        self.assertIn("PacketSize=1200", c.features)
        self.assertEqual(c.read(mock_rsp.BASE, 16), bytes(range(16)))
        # tramo que termina antes de lo pedido: el servidor corta en la primera dirección inválida
        self.assertEqual(len(c.read(mock_rsp.BASE + mock_rsp.SIZE - 8, 64)), 8)
        self.assertEqual(c.cmd("g"), "00" * 556)
        self.assertEqual(c.cmd("p40"), "%016x" % (0x1234 + 0x40))
        self.assertClean()

    def test_paquete_con_checksum_malo_no_se_reenvia(self):
        s = socket.create_connection(("127.0.0.1", self.br.listen_port), timeout=3)
        s.sendall(b"$m10000,4#00")
        self.assertEqual(s.recv(1), b"-")
        s.close()
        time.sleep(0.2)
        self.assertEqual(self.mock.seen, [])
        self.assertClean()

    def test_zx_no_soportados_responden_vacío(self):
        c = self.client()
        self.assertEqual(c.cmd("Z2,10000,4"), "")
        self.assertTrue(c.bp(0x10000))
        self.assertIn(0x10000, self.mock.bps)
        self.assertClean()


class TestDetach(Base):
    def test_D_es_noop_y_cliente_nuevo_sigue_leyendo(self):
        c = self.client()
        self.assertEqual(c.cmd("D"), "OK")
        c.close()
        self.clients.remove(c)
        time.sleep(0.2)
        self.assertNotIn("D", self.mock.seen)
        self.assertClean()
        c2 = self.client()
        self.assertEqual(c2.read(mock_rsp.BASE, 4), bytes(range(4)))
        self.assertClean()

    def test_cierre_sin_D_no_congela(self):
        c = self.client()
        c.read(mock_rsp.BASE, 4)
        c.close()
        self.clients.remove(c)
        time.sleep(0.3)
        self.assertClean()
        self.assertEqual(self.client().cmd("?"), "S05")

    def test_segundo_cliente_simultáneo_se_rechaza(self):
        self.client().read(mock_rsp.BASE, 4)
        s = socket.create_connection(("127.0.0.1", self.br.listen_port), timeout=3)
        self.assertEqual(s.recv(10), b"")       # cerrado por el proxy
        s.close()
        self.assertTrue(any(e["ev"] == "client_rejected" for e in self.events()))
        self.assertClean()

    def test_k_bloqueado_por_defecto(self):
        c = self.client()
        c._send("k")
        time.sleep(0.3)
        self.assertFalse(self.mock.killed)
        self.assertEqual(c.read(mock_rsp.BASE, 2), bytes(range(2)))
        self.assertTrue(any(e["ev"] == "kill_blocked" for e in self.events()))


class TestKillPermitido(Base):
    bridge_kw = {"allow_kill": True}

    def test_k_se_reenvía_con_allow_kill(self):
        self.client()._send("k")
        time.sleep(0.3)
        self.assertTrue(self.mock.killed)


class TestRun(Base):
    def test_c_se_traduce_y_0x03_detiene(self):
        c = self.client()
        c.cont()                       # el cliente manda 'c' plano; el servidor solo conoce vCont;c
        time.sleep(0.2)
        self.assertIn("vCont;c", self.mock.seen)
        self.assertEqual(c.interrupt(), "S05")
        self.assertClean()
        self.assertEqual(c.read(mock_rsp.BASE, 4), bytes(range(4)))

    def test_breakpoint_durante_la_marcha_llega_al_cliente(self):
        c = self.client()
        self.assertTrue(c.bp(0x10010))
        c.cont()
        time.sleep(0.2)
        self.mock.trigger_stop()
        self.assertEqual(c.wait_stop(3.0), "S05")
        self.assertClean()

    def test_sin_traducción_c_plano_responde_vacío_y_no_corre(self):
        self.br.translate = False
        c = self.client()
        self.assertEqual(c.cmd("c"), "")
        self.assertNotIn("vCont;c", self.mock.seen)

    def test_cliente_se_va_corriendo_y_el_siguiente_empieza_detenido(self):
        c = self.client()
        c.cont()
        time.sleep(0.2)
        c.close()
        self.clients.remove(c)
        c2 = self.client()
        self.assertEqual(c2.cmd("?"), "S05")      # el proxy interrumpió y descartó la parada
        self.assertEqual(c2.read(mock_rsp.BASE, 4), bytes(range(4)))
        self.assertEqual(self.mock.swallowed, 0)
        self.assertClean()
        evs = [e["ev"] for e in self.events()]
        self.assertIn("interrupt_on_attach", evs)
        self.assertIn("orphan_reply", evs)

    def test_paquete_mientras_corre_se_rechaza_sin_llegar_al_servidor(self):
        c = self.client()
        c.cont()
        time.sleep(0.2)
        c._send("m10000,4")
        self.assertEqual(c._recv_raw().decode(), "E01")
        self.assertEqual(self.mock.swallowed, 0)
        self.assertEqual(c.interrupt(), "S05")
        self.assertClean()


class TestUpstream(unittest.TestCase):
    def test_si_el_servidor_cierra_termina_con_codigo_2(self):
        mock = mock_rsp.MockRsp()
        br = proxy.Bridge(("127.0.0.1", mock.port), ("127.0.0.1", 0))
        br.open()
        mock.connected.wait(2)
        out = []
        t = threading.Thread(target=lambda: out.append(br.serve()), daemon=True)
        t.start()
        mock.close()
        t.join(3)
        self.assertEqual(out, [2])

    def test_listen_igual_a_upstream_se_rechaza(self):
        with self.assertRaises(ValueError):
            proxy.Bridge(("127.0.0.1", 2345), ("127.0.0.1", 2345))

    def test_log_existente_no_se_sobrescribe(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.jsonl")
            open(p, "w").write("previo")
            mock = mock_rsp.MockRsp()
            br = proxy.Bridge(("127.0.0.1", mock.port), ("127.0.0.1", 0), p)
            with self.assertRaises(FileExistsError):
                br.open()
            mock.close()
            self.assertEqual(open(p).read(), "previo")


class TestParser(unittest.TestCase):
    def test_fragmentado_y_mezclado(self):
        p = proxy.PacketParser()
        raw = proxy.frame(b"m10,4") + b"\x03+" + proxy.frame(b"g")
        ev = []
        for i in range(0, len(raw), 3):
            ev += p.feed(raw[i:i + 3])
        self.assertEqual([(k, b, ok) for k, b, ok in ev],
                         [("pkt", b"m10,4", True), ("int", b"", True), ("ack", b"", True), ("pkt", b"g", True)])

    def test_checksum_malo(self):
        self.assertEqual(proxy.PacketParser().feed(b"$g#00"), [("pkt", b"g", False)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
