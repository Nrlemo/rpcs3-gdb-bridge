#!/usr/bin/env python3
"""opd_scan.py: imagen sintética (formato, vtable, direcciones construidas, fallo cerrado) y ELF sintético generado en los tests.
Uso: python3 -I tests/test_opd_scan.py
"""
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))
import build_elf  # noqa: E402
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


class TestElfSintetico(unittest.TestCase):
    """Image.from_elf y el modo --elf con un ELF generado (sin ningún programa real)."""
    CODE_LO, DATA_LO, TOC_E = 0x10000, 0x20000, 0x20C00     # el TOC cae dentro del segmento de datos
    F, F_OPD, VT = 0x10200, 0x20400, 0x20800

    @classmethod
    def build(cls):
        code = bytearray(0x1000)
        data = bytearray(0x1000)

        def put(buf, base, va, v):
            struct.pack_into(">I", buf, va - base, v)
        put(data, cls.DATA_LO, cls.DATA_LO, 0x10100)             # OPD de e_entry
        put(data, cls.DATA_LO, cls.DATA_LO + 4, cls.TOC_E)
        for i in range(40):                                        # OPD de relleno
            put(data, cls.DATA_LO, cls.DATA_LO + 0x40 + 8 * i, cls.CODE_LO + 4 * i)
            put(data, cls.DATA_LO, cls.DATA_LO + 0x44 + 8 * i, cls.TOC_E)
        put(data, cls.DATA_LO, cls.F_OPD, cls.F)
        put(data, cls.DATA_LO, cls.F_OPD + 4, cls.TOC_E)
        put(data, cls.DATA_LO, cls.VT, cls.DATA_LO + 0x40)         # vtable: OPD, OPD(F), OPD
        put(data, cls.DATA_LO, cls.VT + 4, cls.F_OPD)
        put(data, cls.DATA_LO, cls.VT + 8, cls.DATA_LO + 0x48)
        put(code, cls.CODE_LO, 0x10300, (15 << 26) | (9 << 21) | 2)                   # lis r9,2
        put(code, cls.CODE_LO, 0x10304, (14 << 26) | (9 << 21) | (9 << 16) | 0x0400)   # addi r9,r9,0x400 -> 0x20400 = OPD de F
        return build_elf.build_elf64_be([(cls.CODE_LO, bytes(code), 5), (cls.DATA_LO, bytes(data), 6)], entry=cls.DATA_LO)

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.td.name, "p.elf")
        with open(self.path, "wb") as f:
            f.write(self.build())

    def tearDown(self):
        self.td.cleanup()

    def test_from_elf_lee_segmentos_codigo_y_toc_del_entry(self):
        img = o.Image.from_elf(self.path)
        self.assertEqual(img.code, [(self.CODE_LO, self.CODE_LO + 0x1000)])
        self.assertEqual(img.entry_toc, self.TOC_E)
        self.assertEqual(img.u32(self.F_OPD), self.F)

    def test_scan_sobre_elf(self):
        r = o.scan(o.Image.from_elf(self.path), self.F, None, min_count=10)
        self.assertEqual(r["format"]["toc"], self.TOC_E)
        self.assertEqual([x["opd"] for x in r["opds"]], [self.F_OPD])
        refs = r["opds"][0]["data_refs"]
        self.assertEqual([d["va"] for d in refs], [self.VT + 4])
        self.assertTrue(refs[0]["vtable_like"])
        self.assertEqual(r["opds"][0]["code_built"], [0x10300])

    def test_cli_elf_y_json(self):
        out = os.path.join(self.td.name, "o.json")
        self.assertEqual(o.main(["opd_scan", "--elf", self.path, "--func", hex(self.F), "--min-count", "10", "--json", out]), 0)
        self.assertGreater(os.path.getsize(out), 10)

    def test_elf_invalido_falla_cerrado(self):
        bad = os.path.join(self.td.name, "bad.elf")
        with open(bad, "wb") as f:
            f.write(b"no soy un elf" * 10)
        with self.assertRaises(o.ScanError):
            o.Image.from_elf(bad)
        self.assertEqual(o.main(["opd_scan", "--elf", bad, "--func", "0x1000"]), 1)

    def test_elf_sin_segmento_ejecutable_o_entry_invalido(self):
        sin_x = os.path.join(self.td.name, "sinx.elf")
        with open(sin_x, "wb") as f:
            f.write(build_elf.build_elf64_be([(self.DATA_LO, bytes(0x100), 6)], entry=self.DATA_LO))
        with self.assertRaises(o.ScanError):
            o.Image.from_elf(sin_x)
        entry_malo = os.path.join(self.td.name, "entry.elf")
        with open(entry_malo, "wb") as f:
            f.write(build_elf.build_elf64_be([(self.CODE_LO, bytes(0x100), 5)], entry=self.CODE_LO))   # e_entry apunta a código, no a un OPD
        with self.assertRaises(o.ScanError):
            o.Image.from_elf(entry_malo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
