package pavarotti;

import ghidra.*;
import ghidra.app.services.*;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.base.project.GhidraProject;
import ghidra.framework.*;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.nio.file.*;
import java.util.concurrent.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import org.jdom2.input.SAXBuilder;
import resources.ResourceManager;

public class DesktopTest implements GhidraLaunchable {
    public void launch(GhidraApplicationLayout layout, String[] args) {
        try {
            run(layout, args);
            System.out.println("PAVAROTTI DESKTOP OK");
            System.exit(0);
        } catch (Throwable error) {
            error.printStackTrace();
            System.exit(1);
        }
    }

    private void run(GhidraApplicationLayout layout, String[] args) throws Exception {
        GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
        config.setShowSplashScreen(false);
        Application.initializeApplication(layout, config);
        Path dir = Path.of(args[0]);
        GhidraProject project = GhidraProject.createProject(dir.toString(), "Muestra", true);
        SourceStore store = new SourceStore(dir.resolve("Muestra.pavarotti/fuentes"));
        Finding finding = store.ingest(Path.of(args[1])).rows().getFirst();
        Path bytes = Files.write(dir.resolve("ejemplo.bin"), new byte[]{0, 1, 2, 3});
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        Program imported = project.importProgram(bytes.toFile(), BinaryLoader.class, language, language.getDefaultCompilerSpec());
        GhidraProgramUtilities.markProgramNotToAskToAnalyze(imported);
        project.saveAs(imported, "/", "ejemplo.bin", false);
        project.close(imported);
        var domainFile = project.getProjectData().getFile("/ejemplo.bin");
        GhidraToolTemplate template;
        try (var resource = ResourceManager.getResourceAsStream("defaultTools/CodeBrowser.tool")) {
            template = new GhidraToolTemplate(new SAXBuilder().build(resource).getRootElement(), "CodeBrowser.tool");
        }
        PluginTool tool = edt(() -> {
            FrontEndTool front = new FrontEndTool(project.getProject().getProjectManager());
            front.setActiveProject(project.getProject());
            PluginTool browser = template.createTool(project.getProject());
            browser.setVisible(true);
            var program = browser.getService(ProgramManager.class).openProgram(domainFile);
            browser.getService(GoToService.class).goTo(program.getMinAddress());
            return browser;
        });
        Container panel = edt(() -> tool.getComponentProvider("PAVAROTTI").getComponent());
        JTable table = edt(() -> find(panel, JTable.class, null));
        for (int i = 0; i < 100 && edt(table::getRowCount) == 0; i++) Thread.sleep(100);
        edt(() -> {
            if (table.getRowCount() != 1) throw new AssertionError("No se cargó la fuente.");
            JTextField search = find(panel, JTextField.class, null);
            for (String query : new String[]{"CADENA OBSERVADA", finding.digest(), finding.id(), "info"}) {
                search.setText(query);
                if (table.getRowCount() != 1) throw new AssertionError("Búsqueda sin resultado: " + query);
            }
            search.setText(".*");
            if (table.getRowCount() != 0) throw new AssertionError("La búsqueda debe ser literal.");
            search.setText("");
            table.setRowSelectionInterval(0, 0);
            JButton link = find(panel, JButton.class, "Vincular dirección");
            if (!link.isEnabled()) throw new AssertionError("El vínculo está deshabilitado.");
            link.doClick();
            if (args.length > 2) {
                JFrame frame = tool.getToolFrame();
                BufferedImage image = new BufferedImage(frame.getWidth(), frame.getHeight(), BufferedImage.TYPE_INT_RGB);
                Graphics2D graphics = image.createGraphics();
                frame.paint(graphics); graphics.dispose();
                ImageIO.write(image, "png", Path.of(args[2]).toFile());
            }
            return null;
        });
        Program program = edt(() -> tool.getService(ProgramManager.class).getCurrentProgram());
        for (int i = 0; i < 150 && program.getCurrentTransactionInfo() != null; i++) Thread.sleep(100);
        domainFile.save(TaskMonitor.DUMMY);
        edt(() -> { tool.getService(ProgramManager.class).closeProgram(program, true); return null; });
        Program reopened = project.openProgram("/", "ejemplo.bin", true);
        Bookmark mark = reopened.getBookmarkManager().getBookmark(reopened.getMinAddress(), BookmarkType.NOTE,
                "PAVAROTTI/" + finding.digest() + "/" + finding.id());
        if (mark == null || !mark.getComment().equals(finding.title())) throw new AssertionError("Marcador no persistido.");
        project.close(reopened);
        project.close();
    }

    private static <T extends Component> T find(Container parent, Class<T> type, String label) {
        for (Component component : parent.getComponents()) {
            if (type.isInstance(component) && (label == null ||
                    component instanceof JButton button && label.equals(button.getText()))) return type.cast(component);
            if (component instanceof Container child) {
                T found = find(child, type, label);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static <T> T edt(Callable<T> operation) throws Exception {
        FutureTask<T> task = new FutureTask<>(operation);
        SwingUtilities.invokeAndWait(task);
        return task.get();
    }
}
