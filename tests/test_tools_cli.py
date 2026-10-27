#!/usr/bin/env python3
"""Herramientas de línea de órdenes sin emulador: diseño del paquete `g`, rangos de código, errores de uso y valores por defecto.
Uso: python3 -I tests/test_tools_cli.py
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import attach_idle  # noqa: E402
import check_decoder_z0  # noqa: E402
import proxy  # noqa: E402
import validate_server as vs  # noqa: E402


def g_hex(**f):
    gpr = "".join("%016x" % f.get("r%d" % i, i) for i in range(32))
    fpr = "0" * 512
    return gpr + fpr + "%016x" % f.get("pc", 0) + "0" * 16 + "%08x" % f.get("cr", 0) + "%016x" % f.get("lr", 0) + "%016x" % f.get("ctr", 0) + "0" * 16


class TestParseG(unittest.TestCase):
    def test_diseno_del_paquete_g(self):
        h = g_hex(pc=0x1234, lr=0x5678, ctr=0x9ABC, cr=0x22000022, r31=0xCAFE)
        self.assertEqual(len(h), 1112)
        r = vs.parse_g(h)
        self.assertEqual((r["pc"], r["lr"], r["ctr"], r["cr"], r["r31"], r["r1"]), (0x1234, 0x5678, 0x9ABC, 0x22000022, 0xCAFE, 1))

    def test_longitud_inesperada_no_se_interpreta(self):
        self.assertEqual(vs.parse_g("00" * 10), {"len": 20})


class TestRangos(unittest.TestCase):
    def tearDown(self):
        vs.CODE_RANGES.clear()

    def test_code_lo_hi(self):
        vs.set_code_ranges(code="10000-20000")
        self.assertTrue(vs.in_code(0x10000) and vs.in_code(0x1FFFF))
        self.assertFalse(vs.in_code(0x20000) or vs.in_code(0xFFFF))

    def test_sin_rango_nada_es_codigo(self):
        vs.set_code_ranges()
        self.assertFalse(vs.in_code(0x10000))


class TestUso(unittest.TestCase):
    def test_validate_server_exige_hilo_o_rango(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(vs.main(["x", os.path.join(d, "o.json")]), 2)

    def test_validate_server_no_sobrescribe(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "o.json")
            open(p, "w").close()
            self.assertEqual(vs.main(["x", p, "--thread", "1"]), 1)

    def test_check_decoder_exige_rango(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(check_decoder_z0.main(["x", os.path.join(d, "o.json"), "1"]), 2)

    def test_attach_idle_exige_hilo(self):
        with self.assertRaises(SystemExit):
            attach_idle.build_parser().parse_args(["5"])
        a = attach_idle.build_parser().parse_args(["5", "1000001"])
        self.assertEqual((a.segundos, a.thread, a.port), (5.0, "1000001", 2346))

    def test_proxy_registro_por_defecto_relativo_al_cwd(self):
        a = proxy.build_parser().parse_args([])
        self.assertTrue(a.log.startswith(os.path.join(os.getcwd(), "rpcs3_bridge_logs")))
        self.assertTrue(a.log.endswith(".jsonl"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
