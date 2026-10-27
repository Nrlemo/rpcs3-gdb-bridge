# Scripts de Ghidra

## `FuncOf.java`
Función contenedora de cada dirección dada: `FuncOf.java <salida.txt> VA [VA ...]` → una línea por VA: `VA entrada nombre inicio-fin`, o `VA -` si ninguna función la contiene.

Ejecución sin tocar el proyecto (los cambios de los scripts se descartan con `-readOnly`, según el README de Ghidra):
```
analyzeHeadless <dir_proyecto> <proyecto> -process <programa> -noanalysis -readOnly \
    -scriptPath ghidra -postScript FuncOf.java $PWD/salida.txt 0x20010 0x20100
```
Límite: solo resuelve direcciones dentro del cuerpo de una función ya definida; si el cuerpo es incompleto (código sin desensamblar), devuelve `-`. En un caso real el 62 % de las direcciones consultadas (48 de 77) cayó ahí. Una extensión pendiente (`FuncOpd.java`) crearía en memoria las funciones de las entradas de la tabla OPD antes de consultar; **no está implementada**.
