#!/usr/bin/env python3
"""tools/rpcs3_bridge/bp_probe.py sin emulador: decodificación sobre el EBOOT real, cadena de retroceso, etiquetas de ruta y manejo de
impactos con un Gdb simulado (Fase 2, #20). Uso: python3 -I tests/test_bp_probe.py
"""
import io
import json
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "rpcs3_bridge"))
import bp_probe as bp  # noqa: E402
import opd_scan  # noqa: E402

ELF = os.path.join(ROOT, "work/eboot/EBOOT.elf")


def g_packet(**regs):
    r = {f"r{i}": 0 for i in range(32)}
    r.update(regs)
    s = "".join("%016x" % r[f"r{i}"] for i in range(32)) + "0" * 512
    s += "%016x" % r.get("pc", 0) + "0" * 16 + "%08x" % 0 + "%016x" % r.get("lr", 0) + "%016x" % 0 + "0" * 16
    assert len(s) == 1112
    return s


class FakeGdb:
    def __init__(self, mem, regs_seq):
        self.mem, self.regs_seq = mem, list(regs_seq)
        self.calls = []
        self.running = False

    def cmd(self, c):
        self.calls.append(c)
        if c == "g":
            return g_packet(**self.regs_seq[0])
        return "OK"

    def read(self, addr, n):
        return bytes(self.mem.get(addr + i, 0) for i in range(n)) if all((addr + i) in self.mem for i in range(n)) else b""

    def bp(self, a):
        self.calls.append("Z0,%x" % a)
        return True

    def rm_bp(self, a):
        self.calls.append("z0,%x" % a)
        return True

    def step(self, timeout=0):
        self.calls.append("s")
        return "S05"


def write(path, text, mode="w"):
    with open(path, mode) as f:
        f.write(text)


def put(mem, addr, data):
    for i, b in enumerate(data):
        mem[addr + i] = b


@unittest.skipUnless(os.path.exists(ELF), "falta work/eboot/EBOOT.elf")
class TestEboot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = opd_scan.Image.from_elf(ELF)

    def test_decode_stb_y_lbz(self):
        self.assertEqual(bp.decode_site(self.img, 0x48974), {"kind": "stb", "reg": 0, "ra": 28})
        self.assertEqual(bp.decode_site(self.img, 0xA14CCC), {"kind": "lbz", "reg": 30, "ra": 31})   # el sitio de patch_trace.py
        self.assertEqual(bp.decode_site(self.img, 0x571FC), {"kind": "stb", "reg": 5, "ra": 3})

    def test_decode_falla_cerrado(self):
        for va in (0x10000, 0x48978, 0x5CD7F0):
            with self.assertRaises(ValueError):
                bp.decode_site(self.img, va)

    def test_retorno_es_llamada(self):
        self.assertTrue(bp.is_call_return(self.img, 0x5CD7F4))      # justo después del `bl 0x5cce98` de 0x5cd7f0
        self.assertFalse(bp.is_call_return(self.img, 0x5CD7F8))
        self.assertIsNone(bp.is_call_return(self.img, 0xFFFFFFF0))


class TestCadena(unittest.TestCase):
    def setUp(self):
        self.img = opd_scan.Image([(0x5CD7F0, struct.pack(">II", 0x4BFFF6A9, 0x5460063E))], [(0x5CD7F0, 0x5CD7F8)])

    def mem(self, d):
        m = {}
        for a, v in d.items():
            put(m, a, struct.pack(">Q", v))
        return lambda addr, n: bytes(m.get(addr + i, 0) for i in range(n)) if (addr in m or True) and addr in d else b""

    def test_dos_marcos(self):
        read = self.mem({0x1000: 0x1100, 0x1110: 0x5CD7F4, 0x1100: 0x1200, 0x1210: 0x5CD7F4})
        ch = bp.walk_chain(read, self.img, 0x1000, depth=3)
        self.assertEqual([c["ret"] for c in ch], ["0x5cd7f4", "0x5cd7f4"])
        self.assertTrue(all(c["call"] for c in ch))

    def test_cadena_corrupta_se_corta(self):
        read = self.mem({0x1000: 0x0800})          # el back chain apunta hacia abajo: inválido
        self.assertEqual(bp.walk_chain(read, self.img, 0x1000), [])
        read = self.mem({0x1000: 0x1100})          # sin palabra de retorno legible
        self.assertEqual(bp.walk_chain(read, self.img, 0x1000), [])


class TestRuta(unittest.TestCase):
    def test_etiquetas(self):
        with tempfile.TemporaryDirectory() as d:
            rj, rl = os.path.join(d, "r.json"), os.path.join(d, "route.log")
            write(rj, json.dumps({"steps": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}))
            lab = bp.RouteLabel(rj, rl)
            self.assertEqual(lab.current(), "a")                     # el log aún no existe
            write(rl, "ruido\n" + json.dumps({"name": "a", "status": "OK"}) + "\n")
            self.assertEqual(lab.current(), "b")
            self.assertFalse(lab.finished())
            write(rl, json.dumps({"name": "b"}) + "\n" + json.dumps({"name": "c"}) + "\nRUTA OK\n", "a")
            self.assertEqual(lab.current(), "fin")
            self.assertTrue(lab.finished())

    def test_etiqueta_manual(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "etq.txt")
            lab = bp.FileLabel(p)
            self.assertIsNone(lab.current())
            write(p, "dialogo1\nignorada\n")
            self.assertEqual(lab.current(), "dialogo1")
            self.assertFalse(lab.finished())

    def test_hilo_del_juego(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "RPCS3.log")
            write(p, "x\n·! 0:00:47 {PPU[0x1000006] Thread (GameThread) [HLE:0x00f42db4]} cellPamf\n")
            self.assertEqual(bp.find_game_thread(p), "0000000001000006")
            write(p, "nada\n")
            with self.assertRaises(RuntimeError):
                bp.find_game_thread(p)


class TestImpactos(unittest.TestCase):
    """Probe.handle_hit con un Gdb simulado."""

    def setUp(self):
        code = struct.pack(">II", 0x98000000 | (5 << 21) | (28 << 16) | 0xD4, 0)       # stb r5,0xd4(r28)
        self.img = opd_scan.Image([(0x48974, code)], [(0x48974, 0x4897C)])
        self.sites = {0x48974: {"va": 0x48974, "name": "w48974", **bp.decode_site(self.img, 0x48974)}}
        self.mem = {}
        put(self.mem, 0x30068B10, struct.pack(">I", bp.FONT_VTABLE))        # objeto de fuente
        put(self.mem, 0x30000000, struct.pack(">I", 0x12345678))            # otro objeto
        self.out = io.StringIO()

    def probe(self, regs_seq, **kw):
        g = FakeGdb(self.mem, regs_seq)
        p = bp.Probe(g, self.img, self.sites, "0000000001000006", self.out, **kw)
        return g, p

    def recs(self):
        return [json.loads(x) for x in self.out.getvalue().splitlines()]

    def test_escritura_en_objeto_de_fuente(self):
        g, p = self.probe([{"pc": 0x48974, "lr": 0x5CD7F4, "r28": 0x30068B10, "r5": 0x1FF, "r1": 0x1000}])
        self.assertTrue(p.handle_hit(0.01))
        r = self.recs()[0]
        self.assertTrue(r["is_font"])
        self.assertEqual(r["val"], 0xFF)                                    # solo el byte bajo de rS se guarda
        self.assertEqual((r["site"], r["obj"], r["lr"]), ("0x48974", "0x30068b10", "0x5cd7f4"))
        i = g.calls.index("z0,48974")                                       # quitar -> paso -> reponer
        self.assertEqual(g.calls[i:i + 3], ["z0,48974", "s", "Z0,48974"])

    def test_objeto_ajeno_se_cuenta_y_se_registra_poco(self):
        g, p = self.probe([{"pc": 0x48974, "lr": 1, "r28": 0x30000000, "r5": 1, "r1": 0x1000}])
        for _ in range(10):
            p.handle_hit(0.0)
        self.assertEqual(p.site_hits[0x48974], 10)
        self.assertEqual(p.site_font[0x48974], 0)
        self.assertEqual(len(self.recs()), 3)                               # solo los 3 primeros no-fuente

    def test_tope_por_clave_y_retiro_del_sitio(self):
        g, p = self.probe([{"pc": 0x48974, "lr": 0x5CD7F4, "r28": 0x30068B10, "r5": 1, "r1": 0x1000}], cap_key=2, cap_site=5)
        for _ in range(5):
            p.handle_hit(0.0)
        ev = self.recs()
        self.assertEqual(sum(1 for e in ev if e.get("kind")), 2)           # 2 registros de la misma clave
        self.assertTrue(any(e.get("evento") == "sitio_retirado" for e in ev))
        self.assertEqual(g.calls.count("Z0,48974"), 4)                      # a la 5.ª no se repone
        s = p.summary()["resumen"]
        self.assertEqual(s["por_sitio"]["0x48974"]["impactos"], 5)
        self.assertTrue(s["por_sitio"]["0x48974"]["retirado"])
        self.assertEqual(s["valores_en_objetos_de_fuente"], {"0x48974": {"1": 5}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
