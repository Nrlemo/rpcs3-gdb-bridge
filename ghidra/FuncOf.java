// Función contenedora de cada dirección dada. Args: <salida.txt> VA [VA ...]   (hex, p. ej. 0x48974)
// Salida: una línea por VA: "VA entrada nombre inicio-fin"; "VA -" si ninguna función la contiene.
// @category SRW
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class FuncOf extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                Address ad = toAddr(Long.decode(a[i]));
                Function f = currentProgram.getFunctionManager().getFunctionContaining(ad);
                if (f == null) {
                    w.printf("%08x -%n", ad.getOffset());
                } else {
                    AddressSetView b = f.getBody();
                    w.printf("%08x %08x %s %08x-%08x%n", ad.getOffset(), f.getEntryPoint().getOffset(), f.getName(),
                            b.getMinAddress().getOffset(), b.getMaxAddress().getOffset());
                }
            }
        }
    }
}
