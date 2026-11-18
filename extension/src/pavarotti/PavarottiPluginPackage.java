package pavarotti;

import ghidra.framework.plugintool.util.PluginPackage;
import javax.swing.ImageIcon;

public final class PavarottiPluginPackage extends PluginPackage {
    public PavarottiPluginPackage() {
        super("PAVAROTTI", new ImageIcon(PavarottiPluginPackage.class.getResource("sello.png")),
                "Expedientes OSINT y evidencias de ARTEX");
    }
}
