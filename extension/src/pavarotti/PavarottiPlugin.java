package pavarotti;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import java.nio.file.Path;

@PluginInfo(status = PluginStatus.RELEASED, packageName = "PAVAROTTI", category = "OSINT",
        shortDescription = "Expediente PAVAROTTI", description = "Consulta fuentes y vincula hallazgos de ARTEX con direcciones del programa.")
public class PavarottiPlugin extends ProgramPlugin {
    private EvidencePanel panel;

    public PavarottiPlugin(PluginTool tool) { super(tool); }

    @Override protected void init() {
        super.init();
        ProjectLocator project = tool.getProject().getProjectLocator();
        Path archive = project.getMarkerFile().toPath().resolveSibling(project.getName() + ".pavarotti");
        panel = new EvidencePanel(this, tool, new SourceStore(archive.resolve("fuentes")));
        tool.addComponentProvider(panel, true);
        panel.reload();
    }

    boolean canLink() {
        return currentProgram != null && currentLocation != null &&
                currentLocation.getProgram() == currentProgram && currentProgram.canSave() &&
                currentProgram.getMemory().contains(currentLocation.getAddress());
    }

    String link(Finding finding) {
        if (!canLink()) throw new IllegalStateException("Selecciona una dirección en un programa editable.");
        Address address = currentLocation.getAddress();
        attach(currentProgram, address, finding);
        return "Marcador en " + currentProgram.getName() + " · " + address + ". Guarda el programa para conservarlo.";
    }

    static void attach(Program program, Address address, Finding finding) {
        String category = "PAVAROTTI/" + finding.digest() + "/" + finding.id();
        int transaction = program.startTransaction("Vincular fuente PAVAROTTI");
        boolean complete = false;
        try {
            program.getBookmarkManager().setBookmark(address, BookmarkType.NOTE, category, finding.title());
            complete = true;
        } finally { program.endTransaction(transaction, complete); }
    }

    @Override protected void locationChanged(ProgramLocation location) { if (panel != null) panel.updateActions(); }
    @Override protected void programDeactivated(Program program) { if (panel != null) panel.updateActions(); }
    @Override protected void dispose() {
        if (panel != null) { panel.close(); tool.removeComponentProvider(panel); }
        super.dispose();
    }
}
