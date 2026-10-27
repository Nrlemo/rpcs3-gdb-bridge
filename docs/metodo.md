# Método de trabajo (lecciones del desarrollo de estas herramientas)

Notas para quien amplíe el repo. Cada punto salió de un error real durante el desarrollo.

1. **Un servidor que dice `OK` no prueba nada.** El servidor GDB de RPCS3 contesta `OK` a un `Z0` aunque no lo instale (decoder LLVM, dirección no ejecutable...). Verifique por efecto (¿para? ¿en la dirección exacta?) y haga un **control positivo** (un sitio que sepa que se ejecuta) antes de fiarse de un resultado negativo.
2. **Compare A/B con una métrica fija, no con impresiones.** «Cuántas imágenes distintas hubo» se confundió con el estado del programa; la diferencia media del fotograma entre justo antes de pulsar y 66 s después (0,0 = idéntico píxel a píxel) separó «sin `Z0`» de «con `Z0`».
3. **Elija el hilo.** El servidor usa por defecto el primer hilo, que no suele ser el del programa; se perdieron minutos concluyendo «el programa no avanza» cuando era el hilo equivocado.
4. **Ponga tiempos máximos y un vigía.** Un paso sobre un hilo bloqueado y una parada silenciosa dejan al cliente esperando para siempre.
5. **Quite el `Z0` antes de continuar** (parada → leer → quitar → paso → reponer → continuar); si no, vuelve a parar al instante.
6. **Falle cerrado.** Ante un opcode, tamaño, formato o marcador inesperado, abortar con un error claro (`decode_site`, `opd_scan`, escáner de fugas).
7. **Pruebe las pruebas.** Rompa el código a propósito (mutación) y confirme que los tests fallan; un test que no puede fallar no cubre nada. Un test detectó un error propio (registros perdidos sin hilo en un sitio) que ninguna corrida real había ejercitado.
8. **Ghidra en solo lectura.** `analyzeHeadless ... -process <programa> -noanalysis -readOnly` descarta los cambios de los scripts (según el README de Ghidra), así que se puede desensamblar o crear funciones en memoria sin tocar el proyecto. Para guardar cambios, trabaje sobre una copia.
9. **Separe confirmado / hipótesis / pendiente** y diga qué no se probó (versiones, hardware, tamaños de muestra). Registre también los errores propios y los enfoques rechazados.
10. **No mate procesos con patrones amplios** (`pkill -f` coincidió con la propia shell): use PIDs.
11. **Nunca versione artefactos.** El `.gitignore` y `tools/check_no_game_data.py` existen porque un `git add -A` sin `.gitignore` metió `.pyc` en el historial (se purgó antes de publicar).
