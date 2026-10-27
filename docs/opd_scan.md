# `opd_scan.py`: llamadores indirectos por descriptor de función (OPD)

En PPC64 de PS3 una llamada indirecta (`bctrl`) usa un **descriptor de función (OPD)**: dos `u32` consecutivos `(código, TOC)`, alineados a 8. Los punteros a función de un programa (vtables, tablas, callbacks) apuntan al OPD, no al código,
por lo que buscar referencias a la dirección de la función no encuentra a sus llamadores indirectos. `opd_scan.py` busca el OPD de una función y todo lo que apunta a él.

## Uso
```
python3 -I opd_scan.py --elf programa.elf --func 0x1000 [--toc 0x...] [--min-count 1000] [--json salida.json]
python3 -I opd_scan.py --raw volcado.bin --base 0x... --code lo-hi --toc 0x... --func 0x1000
```
`--elf` mapea los `PT_LOAD` (código = segmentos ejecutables) y toma el TOC del OPD de `e_entry`. `--raw` es un volcado crudo de RAM que empieza en `--base` (el TOC es obligatorio).

## Qué hace
1. **Valida el formato** (falla cerrado): el TOC debe ser el segundo campo más frecuente entre los pares `(u32 en código, u32 en datos)` y tener al menos `--min-count` apariciones. No se adivina por proporción: otras tablas pueden tener pares con otro segundo campo. Se aceptan además **otras bases de TOC** con ≥ `--min-count` pares a menos de 1 MiB de la principal: la TOC de PPC64 cubre ±32 KiB, así que un binario grande usa varias (en ejecución, distintos hilos corren con distinto `r2`; se comprobó leyéndolo con el servidor GDB).
2. Busca los OPD `(F, TOC)` de la función.
3. Por cada OPD: (a) `u32` que valgan su dirección en datos, con las 2 palabras vecinas de cada lado, y marca «tipo vtable» si ≥2 vecinos son también OPD válidos; (b) direcciones construidas en código: `lis rD,hi` + `addi|ori rD,rD,lo` (ventana de 8 instrucciones) o `addis rD,r2,hi` + `addi` con cada base de TOC; (c) `u32 == F` directo (punteros a código sin OPD).

## Límites
- Un ELF estático no trae los punteros construidos en ejecución: para eso hace falta un volcado de RAM (`--raw`). **Falta** una forma automatizada de tomar ese volcado, la comprobación de que el volcado corresponde al mismo programa (comparar código con el ELF) y la búsqueda por índice (base de OPD + n·8).
- Un OPD con 0 referencias no prueba que no se llame: solo que no hay un puntero completo en la imagen.
- Una función estática sin OPD no se encuentra por este camino.

## Tests
11 tests (`tests/test_opd_scan.py`): imagen sintética (formato, vtable, direcciones construidas, fallo cerrado) y un **ELF sintético generado** (`tests/fixtures/build_elf.py`) para `Image.from_elf`, el modo `--elf` y los casos de ELF inválido, sin segmento ejecutable o `e_entry` que no apunta a un OPD.
