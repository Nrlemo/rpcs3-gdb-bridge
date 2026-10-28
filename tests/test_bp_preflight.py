#!/usr/bin/env python3
"""bp_preflight.py y su uso desde bp_probe.py SIN RPCS3: servidor simulado (mock_rsp.py, por socket real) y dobles de prueba.
Todo es simulado: lo que estos tests demuestran es la lógica de decisión del cliente; que RPCS3 real se comporte como el simulado
solo se comprueba corriendo `python3 -I bp_preflight.py` contra un RPCS3 (ver README).
Uso: python3 -I tests/test_bp_preflight.py
"""
import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import bp_preflight as pf  # noqa: E402
import bp_probe  # noqa: E402
import mock_rsp  # noqa: E402
import proxy  # noqa: E402
import opd_scan  # noqa: E402
from gdbrsp import Gdb, GdbError  # noqa: E402

TID = "0000000001000006"
PC = 0x20010


class Base(unittest.TestCase):
    """Gdb real -> proxy.py real -> servidor simulado. El servidor de RPCS3 no tiene `c` plano: sin el proxy (que lo traduce a
    `vCont;c`) un `cont()` no reanuda nada, así que el camino real de uso es este."""
    connect = True          # el proxy atiende UN solo cliente: bp_probe.main abre el suyo

    def setUp(self):
        p = mock.patch.object(pf, "CONTROL_TIMEOUT", 0.2)      # el control espera sin parada: acortarlo
        p.start()
        self.addCleanup(p.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.mock = mock_rsp.MockRsp()
        self.mock.pc = PC
        self.br = proxy.Bridge(("127.0.0.1", self.mock.port), ("127.0.0.1", 0), os.path.join(self.tmp.name, "t.jsonl"))
        self.br.open()
        self.mock.connected.wait(2)
        self.th = threading.Thread(target=self.br.serve, daemon=True)
        self.th.start()
        self.port = self.br.listen_port
        self.g = Gdb("127.0.0.1", self.port, timeout=3.0) if self.connect else None

    def tearDown(self):
        if self.g:
            self.g.close()
        self.br.stop()
        self.th.join(3)
        self.mock.close()
        self.tmp.cleanup()

    def check(self, **kw):
        kw.setdefault("timeout", 0.5)
        return pf.check_breakpoints(self.g, TID, **kw)

    def assertClean(self):
        self.assertEqual(self.mock.bps, set(), "quedó un Z0 puesto")
        self.assertEqual(self.mock.protocol_errors, [])
        self.assertFalse(self.mock.frozen)
        self.assertFalse(self.mock.paused is False, "el objetivo quedó en marcha")


class TestVeredictos(Base):
    def test_pass_con_parada_real_en_el_pc(self):
        self.mock.honor_bps = True
        r = self.check()
        self.assertEqual((r.verdict, r.address, r.cleanup_ok), (pf.PASS, PC, True), r.reason)
        self.assertTrue(r.allows_probe)
        self.assertClean()
        self.assertFalse(self.g.running)                      # queda detenido, como al entrar
        self.assertEqual(self.mock.seen.count("vCont;c"), 2)  # prueba + control sin breakpoint

    def test_z0_rechazado_es_fail(self):
        self.mock.reject_z0 = True
        r = self.check()
        self.assertEqual(r.verdict, pf.FAIL)
        self.assertIn("rechaz", r.reason)
        self.assertFalse(r.allows_probe)
        self.assertNotIn("vCont;c", self.mock.seen)           # ni siquiera se reanudó
        self.assertClean()

    def test_z0_aceptado_pero_sin_parada_y_el_hilo_avanza_es_fail(self):
        self.mock.advance_on_cont = True                      # un Z0 que se ignora: el hilo ejecuta la instrucción y sigue
        r = self.check()
        self.assertEqual(r.verdict, pf.FAIL, r.reason)
        self.assertIn("0x20014", r.reason)
        self.assertFalse(r.allows_probe)
        self.assertClean()                                     # Z0 retirado aunque falló

    def test_timeout_con_el_pc_sin_cambios_es_inconcluso_no_fail(self):
        r = self.check()                                       # el simulado acepta, no para y el PC no se mueve: parada silenciosa
        self.assertEqual(r.verdict, pf.INCONCLUSIVE, r.reason)
        self.assertIn("silenciosa", r.reason)
        self.assertFalse(r.allows_probe)
        self.assertClean()
        self.assertFalse(self.g.running)

    def test_parada_tambien_sin_breakpoint_no_es_atribuible(self):
        self.mock.stop_always = True                           # el servidor para siempre, haya o no Z0
        r = self.check()
        self.assertEqual(r.verdict, pf.INCONCLUSIVE, r.reason)
        self.assertIn("SIN breakpoint", r.reason)
        self.assertClean()

    def test_sin_control_el_pass_lo_dice(self):
        self.mock.honor_bps = True
        r = self.check(control=False)
        self.assertEqual(r.verdict, pf.PASS)
        self.assertIn("control", r.reason)
        self.assertEqual(self.mock.seen.count("vCont;c"), 1)
        self.assertClean()

    def test_reanuda_solo_si_se_pide_y_la_limpieza_fue_correcta(self):
        self.mock.honor_bps = True
        r = self.check(resume=True)
        self.assertEqual(r.verdict, pf.PASS)
        self.assertTrue(self.g.running)
        deadline = time.time() + 2
        while self.mock.seen.count("vCont;c") < 3 and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.mock.seen.count("vCont;c"), 3)   # prueba + control + reanudación final
        self.g.interrupt(timeout=2.0)


class TestEntradaYReplicas(Base):
    def test_objetivo_en_marcha_es_inconcluso_y_no_toca_nada(self):
        self.g.cont()
        try:
            r = self.check()
            self.assertEqual(r.verdict, pf.INCONCLUSIVE)
            self.assertIn("en marcha", r.reason)
            self.assertNotIn("Z0,20010,4", self.mock.seen)
        finally:
            self.g.interrupt(timeout=2.0)

    def test_pc_no_alineado_o_cero(self):
        for pc in (0, PC + 2):
            self.mock.pc = pc
            r = self.check()
            self.assertEqual(r.verdict, pf.INCONCLUSIVE)
            self.assertFalse(any(c.startswith("Z0") for c in self.mock.seen))

    def test_no_pisa_un_breakpoint_conocido(self):
        self.mock.honor_bps = True
        r = self.check(avoid={PC})
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("no se pisa", r.reason)
        self.assertFalse(any(c.startswith(("Z0", "z0")) for c in self.mock.seen))   # ni se puso ni se quitó nada

    def test_pc_fuera_del_codigo(self):
        r = self.check(is_code=lambda a: False)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("fuera del código", r.reason)

    def test_respuesta_inesperada_a_z0_es_inconclusa(self):
        self.mock.z0_reply = "T05basura"
        r = self.check()
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("inesperada", r.reason)

    def test_error_e01_a_z0_es_rechazo(self):
        self.mock.z0_reply = "E01"
        self.assertEqual(self.check().verdict, pf.FAIL)


class ScriptedGdb:
    """Doble que devuelve respuestas fijas (sin red) para caminos que el simulado no cubre."""

    def __init__(self, replies, stop="S05", wait=None, rm="OK", interrupt_exc=None):
        self.replies, self.stop, self.wait, self.rm, self.interrupt_exc = replies, stop, wait, rm, interrupt_exc
        self.running, self.calls = False, []

    def drain(self):
        pass

    def cmd(self, c):
        self.calls.append(c)
        if c.startswith("z0"):
            if isinstance(self.rm, Exception):
                raise self.rm
            return self.rm
        r = self.replies.get(c.split(",")[0], self.replies.get(c[:1], "OK"))
        if isinstance(r, Exception):
            raise r
        return r(c) if callable(r) else r

    def cont(self):
        self.calls.append("c")
        self.running = True

    def wait_stop(self, timeout=0):
        if isinstance(self.wait, Exception):
            raise self.wait
        self.running = False
        return self.stop

    def interrupt(self, timeout=0):
        self.calls.append("int")
        if self.interrupt_exc:
            raise self.interrupt_exc
        self.running = False
        return "S05"


def g_pkt(pc):
    return "0" * 1024 + "%016x" % pc + "0" * 72


class TestErrores(unittest.TestCase):
    def test_conexion_cerrada_al_continuar_es_inconcluso_y_se_intenta_limpiar(self):
        g = ScriptedGdb({"g": g_pkt(PC), "?": "S05"}, wait=GdbError("conexión cerrada por RPCS3"))
        r = pf.check_breakpoints(g, TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("conexión cerrada", r.reason)
        self.assertIn("z0,20010,4", g.calls)                   # intentó quitar el Z0
        self.assertFalse(r.allows_probe)

    def test_error_de_socket_en_la_primera_orden(self):
        g = ScriptedGdb({"H": OSError("reset")})
        r = pf.check_breakpoints(g, TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertTrue(r.cleanup_ok)                          # nada que limpiar

    def test_g_con_longitud_inesperada(self):
        r = pf.check_breakpoints(ScriptedGdb({"g": "00" * 5, "?": "S05"}), TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)

    def test_parada_con_otra_senal(self):
        g = ScriptedGdb({"g": g_pkt(PC), "?": "S05"}, stop="S0b")
        r = pf.check_breakpoints(g, TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("S0b", r.reason)

    def test_parada_ajena_con_otro_pc(self):
        seq = iter([g_pkt(PC), g_pkt(PC + 0x100)])
        g = ScriptedGdb({"g": lambda c: next(seq), "?": "S05"})
        r = pf.check_breakpoints(g, TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("ajena", r.reason)

    def test_parada_de_salida_no_es_parada_de_breakpoint(self):
        g = ScriptedGdb({"g": g_pkt(PC), "?": "S05"}, stop="W00")
        self.assertEqual(pf.check_breakpoints(g, TID, 0.1).verdict, pf.INCONCLUSIVE)

    def test_timeout_e_interrupcion_fallida_deja_aviso_de_limpieza(self):
        g = ScriptedGdb({"g": g_pkt(PC), "?": "S05"}, wait=TimeoutError(), interrupt_exc=GdbError("muerto"))
        r = pf.check_breakpoints(g, TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertFalse(r.cleanup_ok)
        self.assertFalse(r.allows_probe)
        self.assertIn("ATENCIÓN", r.report())

    def test_z0_de_limpieza_no_confirmado_invalida_un_pass(self):
        g = ScriptedGdb({"g": g_pkt(PC), "?": "S05"}, rm="E01")      # el control no puede quitar el Z0
        r = pf.check_breakpoints(g, TID, 0.1)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertFalse(r.cleanup_ok)

    def test_pass_con_limpieza_fallida_no_autoriza(self):
        r = pf.Result(pf.PASS, "x", PC, cleanup_ok=False)
        self.assertFalse(r.allows_probe)


class TestInforme(unittest.TestCase):
    def test_informe_conciso_y_codigos_de_salida(self):
        self.assertEqual(pf.EXIT_CODES, {pf.PASS: 0, pf.FAIL: 1, pf.INCONCLUSIVE: 3})
        txt = pf.Result(pf.INCONCLUSIVE, "motivo", PC).report()
        self.assertIn("INCONCLUSIVE (PC 0x20010)", txt)
        self.assertIn("NO prueba", txt)
        self.assertNotIn("NO prueba", pf.Result(pf.PASS, "motivo", PC).report())


class TestCli(Base):
    connect = False

    def run_main(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = pf.main(["bp_preflight.py", "--thread", TID, "--port", str(self.port), "--timeout", "0.5", *extra])
        return rc, out.getvalue()

    def test_cli_pass_reanuda_por_defecto(self):
        self.mock.honor_bps = True
        rc, out = self.run_main()
        self.assertEqual(rc, 0)
        self.assertIn("PASS", out)

    def test_cli_codigo_de_salida_fail(self):
        self.mock.reject_z0 = True
        rc, out = self.run_main()
        self.assertEqual(rc, 1)

    def test_cli_exige_hilo_o_log(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            pf.main(["bp_preflight.py"])


# --- bp_probe.py: no avanza sin PASS -----------------------------------------------------------------------------------------------
STB = 0x98000000 | (5 << 21) | (28 << 16) | 0x24          # stb r5,0x24(r28)


class TestBpProbeExigePass(Base):
    connect = False

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.sites = os.path.join(self.tmp.name, "sitios.txt")
        self.out = os.path.join(self.tmp.name, "salida.jsonl")
        with open(self.sites, "w") as f:
            f.write("0x20018 escritura\n")
        self.img = opd_scan.Image([(0x20010, struct.pack(">III", 0, 0, STB))], [(0x20010, 0x2001C)])
        self.patch = mock.patch.object(opd_scan.Image, "from_elf", return_value=self.img)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()
        super().tearDown()

    def run_probe(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = bp_probe.main(["bp_probe.py", "--elf", "x.elf", "--sites", self.sites, "--out", self.out, "--thread", TID,
                                "--port", str(self.port), "--preflight-timeout", "0.5", "--duration", "0.3", "--watchdog", "0", *extra])
        return rc, err.getvalue()

    def sets_bps(self):
        return any(c.startswith("Z0,20018") for c in self.mock.seen)

    def test_rechaza_con_fail(self):
        self.mock.reject_z0 = True
        rc, err = self.run_probe()
        self.assertEqual(rc, 3)
        self.assertIn("FAIL", err)
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(self.sets_bps())

    def test_rechaza_con_inconcluso(self):
        rc, err = self.run_probe()                             # parada silenciosa simulada
        self.assertEqual(rc, 3)
        self.assertIn("INCONCLUSIVE", err)
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(self.sets_bps())

    def test_con_pass_sondea(self):
        self.mock.honor_bps = True
        rc, err = self.run_probe()
        self.assertEqual(rc, 0, err)
        self.assertIn("PASS", err)
        self.assertTrue(self.sets_bps())
        with open(self.out) as f:
            ev = [json.loads(x) for x in f]
        self.assertEqual(ev[0]["evento"], "inicio")
        self.assertEqual(ev[0]["preflight"]["veredicto"], pf.PASS)
        self.assertFalse(ev[0]["preflight"]["ignorado"])

    def test_ignore_preflight_avisa_y_lo_anota(self):
        rc, err = self.run_probe("--ignore-preflight")
        self.assertEqual(rc, 0, err)
        self.assertIn("AVISO: --ignore-preflight", err)
        with open(self.out) as f:
            ev = json.loads(f.readline())
        self.assertEqual((ev["preflight"]["veredicto"], ev["preflight"]["ignorado"]), (pf.INCONCLUSIVE, True))

    def test_ignore_preflight_no_cubre_una_limpieza_fallida(self):
        self.mock.honor_bps = True
        with mock.patch.object(pf, "_remove", return_value=False):
            rc, err = self.run_probe("--ignore-preflight")
        self.assertEqual(rc, 3)
        self.assertIn("sucio", err)
        self.assertFalse(os.path.exists(self.out))

    def test_opciones_nuevas_del_parser(self):
        a = bp_probe.build_parser().parse_args(["--elf", "e", "--sites", "s", "--out", "o"])
        self.assertEqual((a.preflight_timeout, a.ignore_preflight), (5.0, False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
