# `bp_probe.py`: sondeo con `Z0` de accesos a un campo de un objeto

Pone `Z0` en una lista de instrucciones de un ejecutable PS3 que corre bajo RPCS3 y, en cada parada, registra quién accede: PC, LR, el valor, el objeto y los llamadores.
Sirve para responder «¿quién escribe/lee este campo en cada pantalla?» sin recompilar ni parchear el programa.

**Requisitos:** `PPU Decoder: Interpreter (static)` (con LLVM el servidor acepta `Z0` y nunca para, ver `servidor_gdb_rpcs3.md`), el proxy en marcha, el ELF del programa (descifrado) y un archivo de sitios.

## Verificación previa
Antes de poner ningún `Z0` ejecuta `bp_preflight.py` (`docs/bp_preflight.md`) y **no sondea salvo con PASS** (código de salida 3 y sin archivo de salida en otro caso). `--preflight-timeout N`; `--preflight-attempts N` (reintentos con otra dirección de retorno validada contra el ELF, sin avanzar el hilo); `--ignore-preflight` la salta con aviso y lo anota en el evento `inicio` (no cubre una limpieza fallida).

## Uso
```
python3 -I bp_probe.py --elf programa.elf --sites sitios.txt --out salida.jsonl [--log RPCS3.log | --thread <id_hex>]
    [--thread-name GameThread] [--object-vtable 0x...] [--field-offset 0x...]
    [--route ruta.json --route-log <dir>/route.log | --label-file etiqueta.txt] [--keep-after-route]
    [--watchdog 5] [--preflight-timeout 5] [--ignore-preflight] [--dump ra:0:0x80]... [--all-regs] [--duration 600] [--max-bps 8] [--cap-key 10] [--cap-site 500] [--port 2346]
```
- **Sitios** (`examples/sitios.ejemplo.txt`): una línea `0xVA [nombre]`. Se decodifican del propio ELF: `stb rS,D(rA)` (valor = byte bajo de `rS`, que aún no se ejecutó), `lbz rD,D(rA)` (valor = byte actual en `rA+D`, leído por `m`) o `ld rD,DS(rA)` (valor = la palabra de 8 B que se va a cargar). Si la instrucción no es de esas, **aborta**. `--field-offset` valida (opcional) que los `stb`/`lbz` usen ese desplazamiento.
- **Objeto buscado** (`--object-vtable`): si se da, solo «coinciden» los impactos con `*(u32*)rA == valor`; así el filtro no depende de direcciones fijas (que podrían cambiar entre arranques). Sin él, todo impacto coincide y no se lee el objeto.
- **Hilo:** `--thread` explícito, o `--log` + `--thread-name` (busca `PPU[0x…] Thread (<nombre>)` en el log de RPCS3).
- **Etiqueta de pantalla:** con una ruta automática (`--route` + `--route-log`, formato de `route_run`: una línea JSON por paso terminado) o a mano (`--label-file`, primera línea del archivo).
- **Volcados:** `--dump ra:0:0x80` vuelca 0x80 bytes desde `rA+0` de cada impacto (`ra` = registro base del sitio, o `rN`); `--all-regs` añade `r0..r31`.

## Qué hace en cada parada
1. Lee `g` del hilo; si el PC no es un sitio, busca entre todos los hilos el que paró (golpe de otro hilo).
2. Calcula valor, objeto, vtable (si se pidió), `r3..r10`, y **3 marcos de la cadena de retroceso** (`bc=[sp]`; el retorno de la función actual está en `[bc+16]`); cada retorno se comprueba contra el ELF: la instrucción anterior debe ser `bl`/`bla`/`bctrl`/`blrl` (`"call": true`).
3. Registra (JSONL) respetando los topes y **reanuda**: quita el `Z0`, un paso, lo repone, continúa.

Topes: `--cap-key` (registros por clave sitio+LR+valor+coincide), `--cap-site` (impactos por sitio; luego se retira el `Z0`). Los no coincidentes se registran solo 3 veces por sitio y se cuentan.

## Vigía (`--watchdog`, 5 s por defecto)
Un hilo puede quedar parado en un `Z0` **sin que el servidor lo comunique** (ver `servidor_gdb_rpcs3.md`). Pasados N segundos sin parada, el sondeo interrumpe (`0x03`), mira el PC del hilo y, si está en un sitio, lo procesa como impacto marcado `"via": "vigia"`; si no, registra `vigia_sin_sitio` con los PC de todos los hilos. `--watchdog 0` lo desactiva (los impactos silenciosos no se verían). **Coste:** cada impacto silencioso cuesta el intervalo del vigía: un sitio que se ejecuta cada fotograma avanza una vez por intervalo.

## Salida
Eventos `inicio`, impactos (`site`, `kind`, `lr`, `obj`, `match`, `vtable`, `val`, `r3_r10`, `r1`, `chain`, `veces_clave`, `ms_espera`, `ms_proceso`, `paso`, `label`, `via`), `sitio_retirado`, `parada_sin_sitio`, `vigia_sin_sitio`, `fin` (motivo) y `resumen` (impactos/s, mediana y p95 del coste por ciclo, impactos por sitio). Al terminar quita sus `Z0` y deja el programa corriendo; SIGINT/SIGTERM piden una parada ordenada (una shell no interactiva deja SIGINT ignorado).

## Cuándo usar `Z0` y cuándo no
Medido (n=4, intérprete): ≈ 0,5 s por impacto. Sirve para sitios **raros** (escrituras por widget, constantes). Para lecturas calientes (cada fotograma/glifo) conviene inyectar una cueva de código que anote en un anillo de memoria (no hay latencia de red), a costa de modificar el programa.

## Tests y límites
24 tests sintéticos (más los de la verificación previa en `tests/test_bp_preflight.py`) (`tests/test_bp_probe.py`), incluido el bucle completo contra un servidor simulado que nunca avisa de la parada (con y sin vigía) y dos mutaciones que los hacen fallar. **No probado:** otras versiones de RPCS3; el techo de `Z0` simultáneos (8 se aceptaron); qué pasa si el `Z0` lo alcanza un hilo distinto del seleccionado más allá de la búsqueda entre hilos.
