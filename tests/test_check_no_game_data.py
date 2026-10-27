#!/usr/bin/env python3
"""tools/check_no_game_data.py con repos git temporales: cada regla de fuga se prueba aparte, en árbol e historial.
Los textos sensibles (CJK, rutas de usuario) se construyen en tiempo de ejecución para que este archivo no dispare el escáner.
Uso: python3 -I tests/test_check_no_game_data.py
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import check_no_game_data as c  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
SECRETO = "secreto-123"


class Repo:
    def __init__(self, td):
        self.path = td
        self.run("init", "-q", "-b", "main")

    def run(self, *a):
        subprocess.run(GIT + ["-C", self.path, *a], check=True, capture_output=True)

    def commit(self, files, msg="cambio", remove=()):
        for name, data in files.items():
            p = os.path.join(self.path, name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        for name in remove:
            os.remove(os.path.join(self.path, name))
        self.run("add", "-A")
        self.run("commit", "-q", "-m", msg)


def scan(repo, deny_lines, *extra):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("\n".join(deny_lines) + "\n")
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = c.main(["x", "--denylist", f.name, "--repo", repo.path, *extra])
        return rc, out.getvalue()
    finally:
        os.remove(f.name)


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.r = Repo(self.td.name)

    def tearDown(self):
        self.td.cleanup()


class TestReglas(Base):
    def test_repo_limpio(self):
        self.r.commit({"README.md": "herramientas genéricas\n", "src/a.py": "print(1)\n"})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULTADO: OK", out)

    def test_extension_prohibida(self):
        self.r.commit({"captura.png": "x"})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 1)
        self.assertIn("extensión prohibida", out)

    def test_binario(self):
        self.r.commit({"datos.dat": b"abc\0def"})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 1)
        self.assertIn("binario", out)

    def test_archivo_grande(self):
        self.r.commit({"t.txt": "a" * 300})
        rc, out = scan(self.r, [SECRETO], "--max-size", "100")
        self.assertEqual(rc, 1)
        self.assertIn("> 100", out)

    def test_texto_cjk(self):
        self.r.commit({"t.txt": "hola " + chr(0x3042) + chr(0x4E00)})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 1)
        self.assertIn("CJK", out)

    def test_ruta_absoluta_de_usuario(self):
        self.r.commit({"t.txt": "ver /ho" + "me/usuario/proyecto/x"})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 1)
        self.assertIn("ruta absoluta", out)

    def test_denylist_en_el_arbol_falla(self):
        self.r.commit({"t.txt": "contiene %s en medio" % SECRETO.upper()})        # sin distinguir mayúsculas
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 1)
        self.assertIn("denylist: " + SECRETO, out)

    def test_denylist_regex(self):
        self.r.commit({"t.txt": "dirección 0x00abcdef aquí"})
        rc, _ = scan(self.r, [r"re:\b0x[0-9a-f]{8}\b"])
        self.assertEqual(rc, 1)

    def test_nombre_de_archivo_en_la_denylist(self):
        self.r.commit({SECRETO + ".txt": "nada"})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 1)
        self.assertIn("nombre de archivo", out)

    def test_denylist_vacia_es_error(self):
        self.r.commit({"t.txt": "x"})
        rc, _ = scan(self.r, ["# solo comentarios"])
        self.assertEqual(rc, 2)


class TestHistorial(Base):
    def test_constante_solo_en_un_blob_antiguo_es_aviso(self):
        self.r.commit({"t.txt": "valor %s\n" % SECRETO})
        self.r.commit({"t.txt": "valor neutro\n"})
        rc, out = scan(self.r, [SECRETO])
        self.assertEqual(rc, 0, out)
        self.assertIn("[AVISO] historial", out)
        self.assertIn("1 AVISO", out)

    def test_strict_history_la_convierte_en_falla(self):
        self.r.commit({"t.txt": "valor %s\n" % SECRETO})
        self.r.commit({"t.txt": "valor neutro\n"})
        rc, _ = scan(self.r, [SECRETO], "--strict-history")
        self.assertEqual(rc, 1)

    def test_binario_borrado_pero_en_el_historial_falla(self):
        self.r.commit({"vol.dat": b"\0\1\2"})
        self.r.commit({"README.md": "limpio"}, remove=["vol.dat"])
        rc, out = scan(self.r, [SECRETO], "--mode", "history")
        self.assertEqual(rc, 1)
        self.assertIn("binario", out)
        rc2, _ = scan(self.r, [SECRETO], "--mode", "tree")                 # el estado actual sí está limpio
        self.assertEqual(rc2, 0)

    def test_mensaje_de_commit_con_denylist_falla_siempre(self):
        self.r.commit({"t.txt": "x"}, msg="arreglo de %s" % SECRETO)
        rc, out = scan(self.r, [SECRETO], "--mode", "history")
        self.assertEqual(rc, 1)
        self.assertIn("mensaje/autor", out)

    def test_etiqueta_con_denylist_falla(self):
        self.r.commit({"t.txt": "x"})
        self.r.run("tag", "-a", "v0", "-m", "version de %s" % SECRETO)
        rc, out = scan(self.r, [SECRETO], "--mode", "history")
        self.assertEqual(rc, 1)
        self.assertIn("etiqueta", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
