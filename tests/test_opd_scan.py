#!/usr/bin/env python3
"""tools/opd_scan.py: imagen sintética (formato, vtable, direcciones construidas, fallo cerrado) y casos conocidos del
EBOOT real (work/eboot/EBOOT.elf, si existe; docs/vwf_renderizadores.md sesiones 2-3). Uso: python3 -I tests/test_opd_scan.py
"""
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import opd_scan as o  # noqa: E402

BASE, CODE_END, DATA_END, TOC = 0x10000, 0x11000, 0x12000, 0x11800
F, F_OPD = 0x10100, 0x11008


def lis(rd, imm):
    return (15 << 26) | (rd << 21) | imm


def addi(rd, ra, imm):
    return (14 << 26) | (rd << 21) | (ra << 16) | (imm & 0xFFFF)


def ori(ra, rs, imm):
    return (24 << 26) | (rs << 21) | (ra << 16) | imm


def synthetic():
    mem = bytearray(DATA_END - BASE)
    put = lambda va, v: mem.__setitem__(slice(va - BASE, va - BASE + 4), struct.pack(">I", v))
    for i in range(40):                       # OPD de relleno
        put(0x11100 + 8 * i, BASE + 4 * i); put(0x11104 + 8 * i, TOC)
    put(F_OPD, F); put(F_OPD + 4, TOC)       # OPD del objetivo
    put(0x11400, 0x11100); put(0x11404, 0x11108)   # vtable: OPD, OPD(F), OPD
    put(0x11408, F_OPD); put(0x1140C, 0)
    put(0x11410, 0x11110)
    put(0x11500, F_OPD)                       # puntero suelto al OPD
    put(0x10200, lis(9, 1)); put(0x10204, addi(9, 9, 0x1008))      # lis+addi -> OPD
    put(0x10300, lis(10, 1)); put(0x10304, ori(10, 10, 0x1008))     # lis+ori -> OPD
    put(0x10400, lis(11, 1)); put(0x10404, addi(12, 3, 0)); put(0x10408, addi(11, 11, 0x1008))  # con instrucción intermedia
    put(0x10500, lis(5, 1)); put(0x10504, addi(5, 5, 0x1100)); put(0x10508, addi(5, 5, -0xf8))  # el reg se sobreescribe
    return bytes(mem)


class TestSynthetic(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.td.name, "ram.bin")
        with open(self.path, "wb") as f:
            f.write(synthetic())
        self.img = o.Image.from_raw(self.path, BASE, (BASE, CODE_END))

    def tearDown(self):
        self.td.cleanup()

    def test_resuelve_opd_vtable_y_codigo(self):
        r = o.scan(self.img, F, TOC, min_count=10)
        self.assertEqual([x["opd"] for x in r["opds"]], [F_OPD])
        refs = {d["va"]: d for d in r["opds"][0]["data_refs"]}
        self.assertEqual(sorted(refs), [0x11408, 0x11500])
        self.assertTrue(refs[0x11408]["vtable_like"])
        self.assertFalse(refs[0x11500]["vtable_like"])
        self.assertEqual(r["opds"][0]["code_built"], [0x10200, 0x10300, 0x10400])
        self.assertEqual(r["direct_code_pointers"], [])

    def test_raw_exige_toc(self):
        with self.assertRaises(o.ScanError):
            o.scan(self.img, F, None, min_count=10)

    def test_toc_equivocado_falla_cerrado(self):
        with self.assertRaises(o.ScanError):
            o.scan(self.img, F, TOC + 8, min_count=10)

    def test_pocos_pares_falla_cerrado(self):
        with self.assertRaises(o.ScanError):
            o.scan(self.img, F, TOC, min_count=1000)

    def test_signo_de_addi_y_addis_toc(self):
        code = bytearray(0x1000)
        put = lambda va, v: code.__setitem__(slice(va - BASE, va - BASE + 4), struct.pack(">I", v))
        put(0x10000, lis(9, 2)); put(0x10004, addi(9, 9, -0x7FF8))          # 0x20000 - 0x7ff8 = 0x18008
        put(0x10010, (15 << 26) | (9 << 21) | (2 << 16) | 0xFFFF); put(0x10014, addi(9, 9, 0x10))  # TOC - 0x10000 + 0x10
        img = o.Image([(BASE, bytes(code))], [(BASE, BASE + 0x1000)])
        h = o.ppc_scan(img, {0x18008, TOC - 0x10000 + 0x10}, [TOC])
        self.assertEqual(h[0x18008], [0x10000])
        self.assertEqual(h[TOC - 0x10000 + 0x10], [0x10010])

    def test_json_no_sobrescribe(self):
        out = os.path.join(self.td.name, "x.json")
        open(out, "w").close()
        rc = o.main(["opd_scan", "--raw", self.path, "--base", hex(BASE), "--code", "10000-11000", "--toc", hex(TOC),
                     "--func", hex(F), "--min-count", "10", "--json", out])
        self.assertEqual(rc, 1)
        os.remove(out)
        rc = o.main(["opd_scan", "--raw", self.path, "--base", hex(BASE), "--code", "10000-11000", "--toc", hex(TOC),
                     "--func", hex(F), "--min-count", "10", "--json", out])
        self.assertEqual(rc, 0)
        self.assertGreater(os.path.getsize(out), 10)


ELF = os.path.join(ROOT, "work/eboot/EBOOT.elf")


@unittest.skipUnless(os.path.exists(ELF), "falta work/eboot/EBOOT.elf")
class TestEbootReal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = o.Image.from_elf(ELF)
        cls.res = {}

    def scan(self, f):
        if f not in self.res:
            self.res[f] = o.scan(self.img, f)
        return self.res[f]

    def test_formato(self):
        r = self.scan(0x5cde14)
        self.assertEqual(r["format"]["toc"], 0xD5CAA8)
        self.assertEqual(r["format"]["pairs_with_toc"], 26351)      # PrepPS3: 26 351 descriptores
        # segunda base de TOC: los hilos del juego corren con r2=0xD6CA90 (docs/puente_rpcs3.md, Fase 0, run 2)
        self.assertEqual(r["format"]["other_tocs"], [["0xd6ca90", 12201]])

    def test_destructor_de_fuente_en_vtable_cfb7e8(self):          # docs/vwf_renderizadores.md sesión 3
        r = self.scan(0x5cde14)
        self.assertEqual([x["opd"] for x in r["opds"]], [0xD22930])
        d = r["opds"][0]["data_refs"]
        self.assertEqual([x["va"] for x in d], [0xCFB7E8])
        self.assertTrue(d[0]["vtable_like"])

    def test_cargar_fuente_sin_referencias_estaticas(self):        # docs/vwf_renderizadores.md sesión 2
        r = self.scan(0x5cd768)
        self.assertEqual([x["opd"] for x in r["opds"]], [0xD228F8])
        self.assertEqual(r["opds"][0]["data_refs"], [])
        self.assertEqual(r["opds"][0]["code_built"], [])

    def test_005cd7f0_no_es_inicio_de_funcion(self):
        r = self.scan(0x5cd7f0)
        self.assertEqual(r["opds"], [])
        self.assertEqual(self.img.u32(0x5cd7f0) >> 26, 18)          # opcode b/bl
        self.assertEqual(self.img.u32(0x5cd7f0) & 1, 1)             # LK=1: es un bl


if __name__ == "__main__":
    unittest.main(verbosity=2)
