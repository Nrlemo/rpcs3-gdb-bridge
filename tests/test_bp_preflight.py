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
import bp_probe as bp  # noqa: E402
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


ALT_A, ALT_B, ALT_C = 0x30000, 0x30010, 0x30020


def alts(*addrs):
    """`alternates` de prueba: las direcciones ya «validadas» por quien llama."""
    return lambda regs, read: [(a, "retorno_%d" % i) for i, a in enumerate(addrs, 1)]


class TestReintento(Base):
    """Servidor simulado. Un intento «plazo vencido con el PC sin cambios» no es evidencia: se prueba OTRA dirección validada,
    con el ciclo completo. Nunca se avanza el hilo con `s`, ni se cambia de hilo, ni se suma al PC."""

    def setUp(self):
        super().setUp()
        self.mock.honor_bps = True
        self.mock.silent_pcs = {PC}                          # el primer intento: Z0 aceptado, sin parada y el PC no se mueve

    def assertSinPasos(self):
        self.assertNotIn("vCont;s", self.mock.seen)
        self.assertEqual({c for c in self.mock.seen if c.startswith("Hg")}, {"Hg" + TID})   # un solo hilo

    def test_inconcluso_y_luego_pass_genuino(self):
        self.mock.reach = {ALT_A}
        r = self.check(alternates=alts(ALT_A, ALT_B))
        self.assertEqual((r.verdict, r.address), (pf.PASS, ALT_A), r.reason)
        self.assertTrue(r.allows_probe)
        self.assertEqual([(a["n"], a["veredicto"], a["pc"]) for a in r.attempts],
                         [(1, pf.INCONCLUSIVE, hex(PC)), (2, pf.PASS, hex(ALT_A))])
        self.assertEqual(r.attempts[1]["origen"], "retorno_1")
        self.assertEqual(r.attempts[1]["pc_tras_parada"], hex(ALT_A))
        self.assertEqual(self.mock.seen.count("vCont;c"), 3)   # intento 1 (plazo) + intento 2 (prueba) + su control
        self.assertTrue(r.attempts[1]["control"].startswith("sin parada"))
        self.assertTrue(any("PASS en el intento 2" in n for n in r.notes), r.notes)
        self.assertSinPasos()
        self.assertClean()

    def test_inconcluso_repetido_llega_al_limite(self):
        r = self.check(alternates=alts(ALT_A, ALT_B, ALT_C), attempts=3)       # ninguna se alcanza
        self.assertEqual(r.verdict, pf.INCONCLUSIVE, r.reason)
        self.assertFalse(r.allows_probe)
        self.assertEqual(len(r.attempts), 3)
        self.assertEqual([a["pc"] for a in r.attempts], [hex(PC), hex(ALT_A), hex(ALT_B)])   # ALT_C no se usa
        self.assertTrue(any("límite de 3 intentos" in n for n in r.notes), r.notes)
        self.assertSinPasos()
        self.assertClean()                                  # cada Z0 se quitó

    def test_fail_por_avance_no_se_reintenta(self):
        self.mock.honor_bps, self.mock.silent_pcs = False, set()
        self.mock.advance_on_cont = True                    # Z0 ignorado: el hilo ejecuta la instrucción y sigue

        def boom(regs, read):
            raise AssertionError("no debía buscar alternativas")
        r = self.check(alternates=boom)
        self.assertEqual((r.verdict, len(r.attempts)), (pf.FAIL, 1))
        self.assertClean()

    def test_intento_alternativo_nunca_da_fail(self):
        calls = []

        def alternates(regs, read):
            calls.append(1)
            return [(ALT_A, "retorno_1")]
        # primer intento inconcluso; en el segundo el hilo se mueve sin parar: INCONCLUSIVE, no FAIL
        self.mock.advance_on_cont = False
        orig = self.mock._handle

        def handle(cmd):
            if cmd.startswith("Z0,%x" % ALT_A):
                self.mock.pc = PC + 0x40                    # el hilo ya no está donde empezó
            return orig(cmd)
        self.mock._handle = handle
        r = self.check(alternates=alternates, attempts=2)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE, r.reason)
        self.assertEqual(len(r.attempts), 2)
        self.assertIn("no prueba que el hilo pasara", r.attempts[1]["motivo"])
        self.assertEqual(calls, [1])
        self.assertClean()

    def test_fail_por_rechazo_no_se_reintenta(self):
        self.mock.reject_z0 = True

        def boom(regs, read):
            raise AssertionError("no debía buscar alternativas")
        r = self.check(alternates=boom)
        self.assertEqual((r.verdict, len(r.attempts)), (pf.FAIL, 1))
        self.assertClean()

    def test_sin_alternates_no_hay_direccion_segura(self):
        r = self.check(alternates=None)
        self.assertEqual((r.verdict, len(r.attempts)), (pf.INCONCLUSIVE, 1))
        self.assertTrue(any("se necesita --elf" in n for n in r.notes), r.notes)
        self.assertClean()

    def test_ninguna_alternativa_valida(self):
        # misma dirección, desalineada, con breakpoint conocido y fuera del código: todas descartadas
        bad = alts(PC, ALT_A + 2, ALT_B, ALT_C)
        r = self.check(alternates=bad, avoid={ALT_B}, is_code=lambda a: a != ALT_C)
        self.assertEqual((r.verdict, len(r.attempts)), (pf.INCONCLUSIVE, 1))
        self.assertTrue(any("no hay otra dirección alternativa válida" in n for n in r.notes), r.notes)
        self.assertFalse(any(c.startswith("Z0,3") for c in self.mock.seen))
        self.assertClean()

    def test_alternates_que_falla_deja_inconcluso(self):
        def boom(regs, read):
            raise ValueError("cadena corrupta")
        r = self.check(alternates=boom)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertTrue(any("error al buscar" in n for n in r.notes), r.notes)
        self.assertClean()

    def test_attempts_1_desactiva_los_reintentos(self):
        def boom(regs, read):
            raise AssertionError("no debía buscar alternativas")
        r = self.check(alternates=boom, attempts=1)
        self.assertEqual((r.verdict, len(r.attempts)), (pf.INCONCLUSIVE, 1))
        self.assertClean()

    def test_parada_ajena_en_la_alternativa_es_inconclusa(self):
        self.mock.reach = {ALT_A}
        orig = self.mock._handle
        self.mock.stop_always = False

        # el servidor para en otro PC al alcanzar la alternativa
        def handle(cmd):
            if cmd == "g" and self.mock.pc == ALT_A:
                self.mock.pc = ALT_A + 0x100
            return orig(cmd)
        self.mock._handle = handle
        r = self.check(alternates=alts(ALT_A, ALT_B), attempts=2)
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("ajena", r.reason)
        self.assertClean()

    def test_rechazo_de_z0_en_la_alternativa_es_inconcluso_no_fail(self):
        orig = self.mock._handle

        def handle(cmd):
            if cmd.startswith("Z0,%x" % ALT_A):
                self.mock.seen.append(cmd)
                return "E01"
            return orig(cmd)
        self.mock._handle = handle
        r = self.check(alternates=alts(ALT_A, ALT_B))
        self.assertEqual(r.verdict, pf.INCONCLUSIVE, r.reason)
        self.assertEqual(len(r.attempts), 2)                # se detiene: no sigue con ALT_B
        self.assertEqual(r.attempts[1]["respuesta_z0"], "E01")
        self.assertClean()


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

    def read(self, addr, n):
        return b""

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
        w = self.wait
        if isinstance(w, list):
            w = w.pop(0) if w else TimeoutError()
        if isinstance(w, Exception):
            raise w
        self.running = False
        return w if isinstance(w, str) else self.stop

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

    def test_ctrl_c_con_el_z0_puesto_limpia_y_propaga(self):
        class G(ScriptedGdb):
            def wait_stop(self, timeout=0):
                raise KeyboardInterrupt()                    # el usuario interrumpe mientras el objetivo corre con el Z0 puesto
        g = G({"g": g_pkt(PC), "?": "S05"})
        with self.assertRaises(KeyboardInterrupt):
            pf.check_breakpoints(g, TID, 0.1)
        self.assertIn("int", g.calls)                       # paró el objetivo...
        self.assertIn("z0,20010,4", g.calls)                # ...y quitó el Z0 antes de salir
        self.assertFalse(g.running)

    def test_pass_con_limpieza_fallida_no_autoriza(self):
        r = pf.Result(pf.PASS, "x", PC, cleanup_ok=False)
        self.assertFalse(r.allows_probe)


class TestReintentoConDobles(unittest.TestCase):
    """Dobles sin red: simulados, como todo este archivo."""

    def g(self, **kw):
        kw.setdefault("wait", [TimeoutError(), TimeoutError()])
        return ScriptedGdb({"g": g_pkt(PC), "?": "S05"}, **kw)

    def test_error_de_conexion_en_el_reintento_detiene_todo(self):
        g = self.g(wait=[TimeoutError(), GdbError("conexión cerrada por RPCS3")])
        r = pf.check_breakpoints(g, TID, 0.1, alternates=alts(ALT_A, ALT_B))
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertIn("conexión cerrada", r.reason)
        self.assertEqual(len(r.attempts), 2)                # no sigue con ALT_B
        self.assertIn("z0,30000,4", g.calls)                # intentó limpiar el Z0 del reintento
        self.assertFalse(r.allows_probe)

    def test_timeout_en_el_reintento_con_interrupcion_fallida_ensucia_la_limpieza(self):
        g = self.g()
        n = {"i": 0}
        orig = g.interrupt

        def interrupt(timeout=0):
            n["i"] += 1
            if n["i"] >= 2:                                 # las del reintento (también la de la limpieza)
                raise GdbError("muerto")
            return orig(timeout)
        g.interrupt = interrupt
        r = pf.check_breakpoints(g, TID, 0.1, alternates=alts(ALT_A))
        self.assertEqual(r.verdict, pf.INCONCLUSIVE)
        self.assertFalse(r.cleanup_ok)
        self.assertFalse(r.allows_probe)
        self.assertIn("interrupción falló", r.attempts[1]["motivo"])

    def test_el_control_tambien_se_exige_en_el_reintento(self):
        pcs = iter([PC, PC, PC, PC, ALT_A, ALT_A, ALT_A])    # preámbulo 1, tras interrumpir, candidatas, preámbulo 2, tras la parada...
        g = ScriptedGdb({"g": lambda c: g_pkt(next(pcs)), "?": "S05"}, wait=[TimeoutError(), "S05", "S05"])   # el control también para
        r = pf.check_breakpoints(g, TID, 0.1, alternates=alts(ALT_A))
        self.assertEqual(r.verdict, pf.INCONCLUSIVE, r.reason)
        self.assertIn("también paró SIN breakpoint", r.reason)
        self.assertTrue(r.attempts[1]["control"].startswith("paró"))
        self.assertFalse(r.allows_probe)

    def test_limpieza_fallida_del_primer_intento_impide_reintentar(self):
        def boom(regs, read):
            raise AssertionError("no debía buscar alternativas")
        g = self.g(rm="E01")
        r = pf.check_breakpoints(g, TID, 0.1, alternates=boom)
        self.assertEqual(len(r.attempts), 1)
        self.assertFalse(r.cleanup_ok)
        self.assertFalse(r.allows_probe)
        self.assertNotIn("Z0,30000,4", g.calls)

    def test_limpieza_fallida_en_el_reintento_impide_el_sondeo(self):
        g = self.g(wait=[TimeoutError(), "S05"])
        seq = iter([True, False, False, False])             # 1.º intento limpia bien; luego no se puede quitar el Z0
        with mock.patch.object(pf, "_remove", side_effect=lambda *_: next(seq)):
            r = pf.check_breakpoints(g, TID, 0.1, alternates=alts(ALT_A))
        self.assertFalse(r.cleanup_ok)
        self.assertFalse(r.allows_probe)

    def test_cada_intento_queda_registrado_y_serializa(self):
        g = self.g()
        r = pf.check_breakpoints(g, TID, 0.1, alternates=alts(ALT_A), attempts=2)
        d = json.loads(json.dumps(r.to_dict()))
        for a in d["intentos"]:
            for k in ("n", "origen", "hilo", "pc", "timeout_s", "veredicto", "motivo", "limpieza_ok", "segundos", "respuesta_z0"):
                self.assertIn(k, a)
        self.assertEqual([a["hilo"] for a in d["intentos"]], [TID, TID])
        self.assertEqual(d["intentos"][0]["pc_tras_interrupcion"], hex(PC))
        self.assertIn("intento 2", r.report())

    def test_nunca_se_usa_paso_ni_otro_hilo(self):
        g = self.g()
        pf.check_breakpoints(g, TID, 0.1, alternates=alts(ALT_A, ALT_B))
        self.assertNotIn("s", g.calls)
        self.assertEqual({c for c in g.calls if c.startswith(("Hg", "Hc"))}, {"Hg" + TID, "Hc" + TID})


class TestMakeAlternates(unittest.TestCase):
    """bp_probe.make_alternates: solo direcciones de retorno comprobadas contra el ELF."""

    def setUp(self):
        # 0x21000: bl (retorno 0x21004 válido); 0x21008: nop (0x2100c NO sigue a una llamada); 0x2100c: bctrl (retorno 0x21010 válido)
        code = struct.pack(">IIII", 0x48000001, 0x60000000, 0x60000000, 0x4E800421) + struct.pack(">I", 0x60000000)
        self.img = opd_scan.Image([(0x21000, code)], [(0x21000, 0x21014)])

    def mem(self, d):
        m = {}
        for a, v in d.items():
            m.update({a + i: b for i, b in enumerate(struct.pack(">Q", v))})
        return lambda addr, n: bytes(m[addr + i] for i in range(n)) if all(addr + i in m for i in range(n)) else b""

    def test_lr_y_cadena_filtrados_y_sin_repetidos(self):
        read = self.mem({0x1000: 0x1100, 0x1110: 0x21004, 0x1100: 0x1200, 0x1210: 0x2100c})   # ret1 válido, ret2 sin llamada previa
        out = bp.make_alternates(self.img)({"lr": 0x21010, "r1": 0x1000}, read)
        self.assertEqual(out, [(0x21010, "lr"), (0x21004, "retorno_1")])        # 0x21010 sigue a bctrl; 0x2100c se descarta
        out2 = bp.make_alternates(self.img)({"lr": 0x21004, "r1": 0x1000}, read)
        self.assertEqual(out2, [(0x21004, "lr")])                                # el retorno repetido no se duplica

    def test_lr_fuera_del_elf_o_sin_cadena_no_da_candidatos(self):
        out = bp.make_alternates(self.img)({"lr": 0x900000, "r1": 0x1000}, lambda a, n: b"")
        self.assertEqual(out, [])


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

    def test_cli_json_guarda_un_registro_por_intento_y_no_sobrescribe(self):
        self.mock.honor_bps = True
        p = os.path.join(self.tmp.name, "r.json")
        rc, out = self.run_main("--json", p)
        self.assertEqual(rc, 0)
        d = json.load(open(p, encoding="utf-8"))
        self.assertEqual((d["veredicto"], d["codigo_salida"], d["hilo"], len(d["intentos"])), (pf.PASS, 0, TID, 1))
        self.assertEqual(d["intentos"][0]["respuesta_z0"], "OK")
        with contextlib.redirect_stderr(io.StringIO()):
            rc2, _ = self.run_main("--json", p)               # ya existe: no se sobrescribe ni se toca el objetivo
        self.assertEqual(rc2, 2)

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
        att = ev[0]["preflight"]["intentos"]                 # cada intento queda registrado en la salida
        self.assertEqual((len(att), att[0]["hilo"], att[0]["veredicto"], att[0]["limpieza_ok"]), (1, TID, pf.PASS, True))

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

    def test_bp_probe_entrega_alternativas_validadas_y_sus_intentos(self):
        seen = {}
        orig = pf.check_breakpoints

        def spy(*a, **kw):
            seen.update(kw)
            seen["pos"] = a
            return orig(*a, **kw)
        self.mock.honor_bps = True
        with mock.patch.object(pf, "check_breakpoints", spy):
            rc, err = self.run_probe("--preflight-attempts", "2")
        self.assertEqual(rc, 0, err)
        self.assertEqual(seen["attempts"], 2)
        self.assertEqual(seen["avoid"].keys(), {0x20018})                    # sus sitios no se pisan
        self.assertTrue(callable(seen["alternates"]))                        # make_alternates(img): retornos validados contra el ELF
        self.assertEqual(seen["alternates"]({"lr": 0x1, "r1": 0x1000}, lambda a, n: b""), [])

    def test_opciones_nuevas_del_parser(self):
        a = bp_probe.build_parser().parse_args(["--elf", "e", "--sites", "s", "--out", "o"])
        self.assertEqual((a.preflight_timeout, a.ignore_preflight, a.preflight_attempts), (5.0, False, 3))
        self.assertEqual(pf.build_parser().parse_args(["--thread", "1"]).attempts, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
