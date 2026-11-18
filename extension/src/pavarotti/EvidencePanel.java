package pavarotti;

import docking.WindowPosition;
import ghidra.framework.plugintool.*;
import ghidra.util.Msg;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;
import java.awt.*;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

final class EvidencePanel extends ComponentProviderAdapter {
    private final PavarottiPlugin plugin;
    private final SourceStore store;
    private final JPanel body = new JPanel(new BorderLayout(4, 4));
    private final FindingsModel model = new FindingsModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<FindingsModel> sorter = new TableRowSorter<>(model);
    private final JTextArea detail = new JTextArea();
    private final JTextField search = new JTextField(14);
    private final JLabel status = new JLabel("Leyendo expediente…");
    private final JButton importButton = new JButton("Importar ARTEX…");
    private final JButton register = new JButton("Registrar fuente…");
    private final JButton link = new JButton("Vincular dirección");
    private final JButton refresh = new JButton("Actualizar");
    private boolean busy;
    private boolean closed;

    EvidencePanel(PavarottiPlugin plugin, PluginTool tool, SourceStore store) {
        super(tool, "PAVAROTTI", plugin.getName());
        this.plugin = plugin;
        this.store = store;
        ImageIcon icon = new ImageIcon(getClass().getResource("sello.png"));
        setIcon(new ImageIcon(icon.getImage().getScaledInstance(20, 20, Image.SCALE_SMOOTH)));
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        body.setBorder(BorderFactory.createEmptyBorder(4, 5, 3, 5));
        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        bar.add(importButton); bar.add(register); bar.add(link); bar.add(refresh);
        bar.addSeparator();
        JLabel label = new JLabel("Buscar ");
        label.setLabelFor(search);
        bar.add(label); bar.add(search);
        body.add(bar, BorderLayout.NORTH);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowSorter(sorter);
        table.setFillsViewportHeight(true);
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer();
        renderer.putClientProperty("html.disable", true);
        table.setDefaultRenderer(Object.class, renderer);
        table.getColumnModel().getColumn(0).setPreferredWidth(210);
        table.getColumnModel().getColumn(3).setPreferredWidth(175);
        detail.setEditable(false); detail.setLineWrap(true); detail.setWrapStyleWord(true);
        detail.setMargin(new Insets(6, 8, 6, 8));
        detail.setText("Selecciona un hallazgo para consultar sus evidencias y su procedencia.");
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(table), new JScrollPane(detail));
        split.setResizeWeight(0.55); split.setDividerLocation(440);
        body.add(split, BorderLayout.CENTER);
        status.putClientProperty("html.disable", true);
        body.add(status, BorderLayout.SOUTH);
        body.setPreferredSize(new Dimension(840, 250));
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            Finding selected = selection();
            detail.setText(selected == null ? "Selecciona un hallazgo para ver sus evidencias." : selected.details());
            detail.setCaretPosition(0);
            updateActions();
        });
        importButton.addActionListener(e -> importFile());
        register.addActionListener(e -> registerSource());
        refresh.addActionListener(e -> reload());
        link.addActionListener(e -> {
            Finding finding = selection();
            if (finding == null) return;
            try { status.setText(plugin.link(finding)); }
            catch (RuntimeException ex) { Msg.showError(this, body, "Vincular dirección", ex.getMessage()); }
        });
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
        });
        updateActions();
    }

    private void filter() {
        String query = search.getText().strip();
        sorter.setRowFilter(query.isEmpty() ? null : RowFilter.regexFilter("(?iu)" + Pattern.quote(query)));
    }

    private Finding selection() {
        int view = table.getSelectedRow();
        if (view < 0) return null;
        int row = table.convertRowIndexToModel(view);
        return row < model.rows.size() ? model.rows.get(row) : null;
    }

    void updateActions() {
        importButton.setEnabled(!busy); register.setEnabled(!busy); refresh.setEnabled(!busy);
        link.setEnabled(!busy && selection() != null && plugin.canLink());
    }

    private void importFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Importar hallazgos de ARTEX");
        chooser.setFileFilter(new FileNameExtensionFilter("Exportación JSON de ARTEX", "json"));
        if (chooser.showOpenDialog(body) == JFileChooser.APPROVE_OPTION) {
            Path path = chooser.getSelectedFile().toPath();
            work(() -> store.ingest(path));
        }
    }

    private void registerSource() {
        JTextField title = new JTextField(32);
        JTextField url = new JTextField(32);
        JTextArea note = new JTextArea(5, 32);
        note.setLineWrap(true); note.setWrapStyleWord(true);
        Object[] fields = {"Título", title, "URL de la fuente pública", url, "Observación o cita", new JScrollPane(note)};
        if (JOptionPane.showConfirmDialog(body, fields, "Registrar fuente", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;
        String name = title.getText(), address = url.getText(), quote = note.getText();
        work(() -> store.observe(name, address, quote));
    }

    void reload() { work(() -> null); }
    void close() { closed = true; }

    private void work(Callable<SourceStore.Document> operation) {
        if (busy) return;
        busy = true; updateActions(); status.setText("Leyendo expediente…");
        new SwingWorker<SourceStore.Library, Void>() {
            private SourceStore.Document imported;
            protected SourceStore.Library doInBackground() throws Exception {
                imported = operation.call();
                return store.load();
            }
            protected void done() {
                if (closed) return;
                try {
                    SourceStore.Library library = get();
                    table.clearSelection();
                    model.rows = library.rows(); model.fireTableDataChanged();
                    if (imported != null && !imported.rows().isEmpty()) {
                        search.setText("");
                        int first = model.rows.indexOf(imported.rows().getFirst());
                        if (first >= 0) {
                            int view = table.convertRowIndexToView(first);
                            table.setRowSelectionInterval(view, view);
                            table.scrollRectToVisible(table.getCellRect(view, 0, true));
                        }
                    }
                    status.setText(model.rows.isEmpty() ? "Expediente vacío. Importa un JSON de ARTEX o registra una fuente."
                            : model.rows.size() + " hallazgo(s) en este proyecto.");
                    if (!library.errors().isEmpty()) Msg.showError(this, body, "Fuentes que requieren revisión",
                            String.join("\n", library.errors()));
                } catch (InterruptedException ex) { Thread.currentThread().interrupt(); }
                catch (ExecutionException ex) {
                    status.setText("No se pudo completar la lectura.");
                    Msg.showError(this, body, "Expediente PAVAROTTI", ex.getCause().getMessage());
                } finally { busy = false; updateActions(); }
            }
        }.execute();
    }

    @Override public JComponent getComponent() { return body; }

    private static final class FindingsModel extends AbstractTableModel {
        List<Finding> rows = List.of();
        final String[] columns = {"Hallazgo", "Severidad", "Verificación", "Activo o fuente"};
        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return columns.length; }
        public String getColumnName(int col) { return columns[col]; }
        public Object getValueAt(int row, int col) {
            Finding finding = rows.get(row);
            return switch (col) {
                case 0 -> finding.title(); case 1 -> finding.level();
                case 2 -> finding.verification(); default -> finding.assets();
            };
        }
    }
}
