package pavarotti;

import java.nio.file.*;
import ghidra.*;
import ghidra.framework.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.classfinder.ClassSearcher;
import resources.ResourceManager;

/** Checks the installed module through the same Ghidra class loader as CodeBrowser. */
public class CheckInstallation implements GhidraLaunchable {
    @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
        if (!ClassSearcher.getClasses(Plugin.class).contains(PavarottiPlugin.class))
            throw new IllegalStateException("Ghidra no encontró el complemento PAVAROTTI.");
        try (var stream = ResourceManager.getResourceAsStream("defaultTools/CodeBrowser.tool")) {
            if (stream == null || !new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
                    .contains("<PACKAGE NAME=\"PAVAROTTI\""))
                throw new IllegalStateException("CodeBrowser no tiene activado el expediente PAVAROTTI.");
        }
        if (SourceStore.parse(Files.readAllBytes(Path.of(args[0]))).rows().isEmpty())
            throw new IllegalStateException("No se pudo leer el expediente de ejemplo.");
        System.out.println("PAVAROTTI OK · Ghidra " + Application.getApplicationVersion()
                + " · CodeBrowser · ARTEX · " + System.getProperty("os.name"));
    }
}
