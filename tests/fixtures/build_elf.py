"""Generador de ELF64 big-endian (PPC64) mínimo y sintético para los tests: solo cabecera + program headers + datos.
No contiene nada de ningún programa real. Uso: build_elf64_be([(va, bytes, flags), ...], entry) -> bytes
(flags: 5 = R+X (código), 6 = R+W (datos)). El offset de archivo de cada segmento es contiguo y alineado a 16."""
import struct

EHSIZE, PHENTSIZE = 64, 56


def build_elf64_be(segments, entry):
    phnum = len(segments)
    off = (EHSIZE + PHENTSIZE * phnum + 15) & ~15
    phdrs, blobs = b"", b""
    for va, data, flags in segments:
        phdrs += struct.pack(">IIQQQQQQ", 1, flags, off + len(blobs), va, va, len(data), len(data), 16)
        blobs += data + b"\0" * ((-len(data)) % 16)
    ident = b"\x7fELF" + bytes([2, 2, 1, 0]) + b"\0" * 8
    ehdr = ident + struct.pack(">HHIQQQIHHHHHH", 2, 21, 1, entry, EHSIZE, 0, 0, EHSIZE, PHENTSIZE, phnum, 64, 0, 0)
    assert len(ehdr) == EHSIZE
    pad = b"\0" * (off - EHSIZE - len(phdrs))
    return ehdr + phdrs + pad + blobs
