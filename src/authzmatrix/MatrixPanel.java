package authzmatrix;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

/** The Results Matrix tab: live table of endpoints x identities, plus a request/response viewer. */
public class MatrixPanel extends JPanel implements AuthEngine.Listener {

    private final MontoyaApi api;
    private final AppState state;
    private final AuthEngine engine;

    private final MatrixTableModel model = new MatrixTableModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<MatrixTableModel> sorter = new TableRowSorter<>(model);

    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JComboBox<String> detailCombo = new JComboBox<>();
    private final Map<String, HttpRequestResponse> detailMap = new LinkedHashMap<>();
    private MatrixEntry selectedEntry;

    private final JButton importBtn = new JButton("Import Proxy History");
    private final JToggleButton liveToggle = new JToggleButton();
    private final JTextField filterField = new JTextField(16);

    private JPanel countsRow;
    private Verdict verdictFilter = null;   // set by clicking a count chip; null = show all
    private final Chip cRows   = new Chip("Rows 0",     new Color(96, 102, 116));
    private final Chip cBypass = new Chip("BYPASSED 0", Verdict.BYPASSED.color);
    private final Chip cNoAuth = new Chip("NO-AUTH 0",  Verdict.PUBLIC_NOAUTH.color);
    private final Chip cReview = new Chip("REVIEW 0",   Verdict.AMBIGUOUS.color);
    private final Chip cEnf    = new Chip("ENFORCED 0", Verdict.ENFORCED.color);
    private final Chip cWaf    = new Chip("WAF 0",      Verdict.INFRA_BLOCK.color);

    private final ConcurrentLinkedQueue<MatrixEntry> pendingAdds = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<MatrixEntry> pendingUpdates = new ConcurrentLinkedQueue<>();
    private final Timer flushTimer;

    public MatrixPanel(MontoyaApi api, AppState state, AuthEngine engine) {
        super(new BorderLayout());
        this.api = api;
        this.state = state;
        this.engine = engine;

        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        model.setIdentities(state.identitiesSnapshot());
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setRowSorter(sorter);
        table.setDefaultRenderer(Object.class, new VerdictCellRenderer());
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) onSelectRow(); });
        table.setRowHeight(26);
        table.setShowVerticalLines(false);
        table.setShowHorizontalLines(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
        table.getTableHeader().setFont(table.getTableHeader().getFont().deriveFont(Font.BOLD));
        sizeColumns();

        add(buildToolbar(), BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), buildDetail());
        split.setResizeWeight(0.5);
        add(split, BorderLayout.CENTER);

        state.addIdentitiesListener(() -> SwingUtilities.invokeLater(this::refreshColumns));

        flushTimer = new Timer(200, e -> drain());
        flushTimer.start();
        syncLiveToggle();
    }

    public void stop() { flushTimer.stop(); }

    // ---------------- toolbar ----------------

    private JComponent buildToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        importBtn.setFont(importBtn.getFont().deriveFont(Font.BOLD));
        importBtn.setForeground(new Color(58, 110, 206));
        importBtn.setToolTipText("Pull every in-scope request already in Proxy history and test it as each identity");
        importBtn.addActionListener(e -> importHistory());
        bar.add(importBtn);

        liveToggle.addActionListener(e -> {
            state.scan.liveEnabled = liveToggle.isSelected();
            state.save();
            syncLiveToggle();
        });
        bar.add(liveToggle);

        bar.add(sep());
        JButton clear = new JButton("Clear");
        clear.setToolTipText("Clear the matrix AND forget tested endpoints so they can be scanned again");
        clear.addActionListener(e -> { engine.clear(); model.clearRows(); detailMap.clear(); detailCombo.removeAllItems(); updateCounters(); });
        bar.add(clear);

        JButton retestSel = new JButton("Retest selected");
        retestSel.addActionListener(e -> selectedEntries().forEach(engine::retest));
        bar.add(retestSel);

        JButton retestAll = new JButton("Retest all");
        retestAll.addActionListener(e -> new ArrayList<>(model.rows()).forEach(engine::retest));
        bar.add(retestAll);

        JButton export = new JButton("Export CSV");
        export.addActionListener(e -> exportCsv());
        bar.add(export);

        bar.add(sep());
        bar.add(new JLabel("Filter:"));
        filterField.setToolTipText("Filter rows by URL, method, or time (HH:mm:ss)");
        filterField.getDocument().addDocumentListener((SimpleDoc) this::applyFilter);
        bar.add(filterField);

        // clickable count chips = filter by verdict (Rows chip clears the filter)
        countsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        wireChip(cRows, null);
        wireChip(cBypass, Verdict.BYPASSED);
        wireChip(cNoAuth, Verdict.PUBLIC_NOAUTH);
        wireChip(cReview, Verdict.AMBIGUOUS);
        wireChip(cEnf, Verdict.ENFORCED);
        wireChip(cWaf, Verdict.INFRA_BLOCK);
        for (Chip c : new Chip[]{cRows, cBypass, cNoAuth, cReview, cEnf, cWaf}) countsRow.add(c);
        cRows.setToolTipText("Show all rows");

        Box north = Box.createVerticalBox();
        bar.setAlignmentX(LEFT_ALIGNMENT);
        countsRow.setAlignmentX(LEFT_ALIGNMENT);
        north.add(bar);
        north.add(countsRow);
        north.setBorder(BorderFactory.createEmptyBorder(2, 4, 4, 4));
        updateChipActive();
        return north;
    }

    private void wireChip(Chip chip, Verdict v) {
        if (v != null) chip.setToolTipText("Show only rows with a " + v.label + " result (click again to clear)");
        chip.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                verdictFilter = (v != null && verdictFilter == v) ? null : v;
                updateChipActive();
                applyFilter();
            }
        });
    }

    private void updateChipActive() {
        cRows.setActive(verdictFilter == null);
        cBypass.setActive(verdictFilter == Verdict.BYPASSED);
        cNoAuth.setActive(verdictFilter == Verdict.PUBLIC_NOAUTH);
        cReview.setActive(verdictFilter == Verdict.AMBIGUOUS);
        cEnf.setActive(verdictFilter == Verdict.ENFORCED);
        cWaf.setActive(verdictFilter == Verdict.INFRA_BLOCK);
    }

    private static JComponent sep() {
        JSeparator s = new JSeparator(SwingConstants.VERTICAL);
        s.setPreferredSize(new Dimension(8, 24));
        return s;
    }

    private void importHistory() {
        boolean anyEnabled = state.identitiesSnapshot().stream().anyMatch(i -> i.enabled);
        if (!anyEnabled) {
            JOptionPane.showMessageDialog(this,
                "Add at least one enabled identity (Identities tab) first.", "Import Proxy History",
                JOptionPane.WARNING_MESSAGE);
            return;
        }
        importBtn.setEnabled(false);
        importBtn.setText("Importing...");
        new Thread(() -> {
            int[] res;
            try { res = engine.importProxyHistory(); }
            catch (Throwable t) { res = new int[]{-1, 0}; api.logging().logToError("import: " + t); }
            final int added = res[0], skipped = res[1];
            SwingUtilities.invokeLater(() -> {
                importBtn.setEnabled(true);
                importBtn.setText("Import Proxy History");
                String msg;
                if (added < 0) {
                    msg = "Import failed — see the extension error log.";
                } else if (added == 0 && skipped == 0) {
                    msg = "No in-scope testable requests found.\n\nCheck: Target → Scope is set, and the "
                        + "Config filters (methods / 'only requests that carry auth').";
                } else if (added == 0) {
                    msg = "Nothing new — all " + skipped + " matching request(s) were already tested "
                        + "or were your identities' own browsing.\n"
                        + "Press Clear to reset the tested memory and re-scan.";
                } else {
                    msg = "Queued " + added + " new endpoint(s)"
                        + (skipped > 0 ? " (skipped " + skipped + " already tested / identity's own traffic)" : "")
                        + ".\nTesting as each identity now — watch the matrix fill in.";
                }
                JOptionPane.showMessageDialog(this, msg, "Import Proxy History", JOptionPane.INFORMATION_MESSAGE);
            });
        }, "authz-matrix-import").start();
    }

    private void syncLiveToggle() {
        liveToggle.setSelected(state.scan.liveEnabled);
        liveToggle.setText(state.scan.liveEnabled ? "LIVE: ON" : "LIVE: OFF");
        liveToggle.setForeground(state.scan.liveEnabled ? new Color(40, 150, 70) : Color.GRAY);
    }

    // ---------------- detail viewer ----------------

    private JComponent buildDetail() {
        JPanel p = new JPanel(new BorderLayout());
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        top.add(new JLabel("View request/response:"));
        detailCombo.addActionListener(e -> showSelectedDetail());
        top.add(detailCombo);
        p.add(top, BorderLayout.NORTH);

        JSplitPane rr = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                wrap("Request", requestEditor.uiComponent()),
                wrap("Response", responseEditor.uiComponent()));
        rr.setResizeWeight(0.5);
        p.add(rr, BorderLayout.CENTER);
        return p;
    }

    private static JComponent wrap(String title, Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JLabel(" " + title), BorderLayout.NORTH);
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private void onSelectRow() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return;
        MatrixEntry e = model.entryAt(table.convertRowIndexToModel(viewRow));
        selectedEntry = e;
        rebuildDetailMap(e);
    }

    private void rebuildDetailMap(MatrixEntry e) {
        String prev = (String) detailCombo.getSelectedItem();
        detailMap.clear();
        if (e == null) { detailCombo.removeAllItems(); return; }
        detailMap.put("A: Base (privileged)", e.baseReqResp);
        if (e.unauthResult != null && e.unauthResult.reqResp != null)
            detailMap.put("C: Unauthenticated", e.unauthResult.reqResp);
        for (Identity id : model.identities()) {
            TestResult tr = e.result(id.id);
            if (tr != null && tr.reqResp != null) detailMap.put("B: " + id.name, tr.reqResp);
        }
        detailCombo.removeAllItems();
        for (String k : detailMap.keySet()) detailCombo.addItem(k);
        if (prev != null && detailMap.containsKey(prev)) detailCombo.setSelectedItem(prev);
        else if (detailCombo.getItemCount() > 0) detailCombo.setSelectedIndex(0);
        showSelectedDetail();
    }

    private void showSelectedDetail() {
        String key = (String) detailCombo.getSelectedItem();
        if (key == null) return;
        HttpRequestResponse rr = detailMap.get(key);
        if (rr == null) return;
        try {
            requestEditor.setRequest(rr.request());
            if (rr.hasResponse()) responseEditor.setResponse(rr.response());
        } catch (Exception ignore) {}
    }

    // ---------------- listener + EDT batching ----------------

    @Override public void onEntryAdded(MatrixEntry e) { pendingAdds.add(e); }
    @Override public void onEntryUpdated(MatrixEntry e) { pendingUpdates.add(e); }

    private void drain() {
        boolean changed = false;
        for (MatrixEntry e; (e = pendingAdds.poll()) != null; ) { model.addEntry(e); changed = true; }
        Set<MatrixEntry> ups = new HashSet<>();
        for (MatrixEntry e; (e = pendingUpdates.poll()) != null; ) ups.add(e);
        for (MatrixEntry e : ups) {
            int r = model.rowIndexOf(e);
            if (r >= 0) { model.fireTableRowsUpdated(r, r); changed = true; }
        }
        if (changed) {
            updateCounters();
            if (selectedEntry != null && ups.contains(selectedEntry)) rebuildDetailMap(selectedEntry);
        }
    }

    private void refreshColumns() {
        model.setIdentities(state.identitiesSnapshot());
        sizeColumns();
    }

    private void sizeColumns() {
        if (table.getColumnCount() < MatrixTableModel.FIXED) return;
        // # , Time, Method, Host, Path, A(base)
        int[] w = {46, 80, 78, 260, 380, 100};
        for (int i = 0; i < w.length && i < table.getColumnCount(); i++)
            table.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
        for (int i = MatrixTableModel.FIXED; i < table.getColumnCount(); i++)
            table.getColumnModel().getColumn(i).setPreferredWidth(230); // identity verdict pills
    }

    // ---------------- filter + counters + export ----------------

    private void applyFilter() {
        final String text = filterField.getText().trim().toLowerCase();
        final Verdict vf = verdictFilter;
        if (text.isEmpty() && vf == null) { sorter.setRowFilter(null); return; }
        sorter.setRowFilter(new javax.swing.RowFilter<MatrixTableModel, Integer>() {
            @Override public boolean include(Entry<? extends MatrixTableModel, ? extends Integer> entry) {
                MatrixEntry me = model.entryAt(entry.getIdentifier());
                if (me == null) return false;
                if (!text.isEmpty()) {
                    boolean m = me.url.toLowerCase().contains(text)
                            || me.method.toLowerCase().contains(text)
                            || me.timeText.contains(text);
                    if (!m) return false;
                }
                if (vf != null) {
                    boolean has = me.unauthResult != null && me.unauthResult.verdict == vf;
                    if (!has) {
                        for (Identity id : model.identities()) {
                            TestResult tr = me.result(id.id);
                            if (tr != null && tr.verdict == vf) { has = true; break; }
                        }
                    }
                    if (!has) return false;
                }
                return true;
            }
        });
    }

    private void updateCounters() {
        int bypass = 0, pub = 0, review = 0, enf = 0, infra = 0, err = 0;
        for (MatrixEntry e : model.rows()) {
            for (Identity id : model.identities()) {
                TestResult tr = e.result(id.id);
                if (tr == null) continue;
                switch (tr.verdict) {
                    case BYPASSED: bypass++; break;
                    case PUBLIC_NOAUTH: pub++; break;
                    case AMBIGUOUS: review++; break;
                    case ENFORCED: enf++; break;
                    case INFRA_BLOCK: infra++; break;
                    case ERROR: err++; break;
                    default: break;
                }
            }
        }
        cRows.setText("Rows " + model.getRowCount());
        cBypass.setText("BYPASSED " + bypass);
        cNoAuth.setText("NO-AUTH " + pub);
        cReview.setText("REVIEW " + review);
        cEnf.setText("ENFORCED " + enf);
        cWaf.setText("WAF " + infra);
        if (countsRow != null) { countsRow.revalidate(); countsRow.repaint(); }
    }

    private List<MatrixEntry> selectedEntries() {
        List<MatrixEntry> out = new ArrayList<>();
        for (int viewRow : table.getSelectedRows()) {
            MatrixEntry e = model.entryAt(table.convertRowIndexToModel(viewRow));
            if (e != null) out.add(e);
        }
        return out;
    }

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("authz-matrix.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        List<Identity> ids = model.identities();
        try (FileWriter w = new FileWriter(fc.getSelectedFile())) {
            StringBuilder h = new StringBuilder("index,method,host,path,base_status,unauth");
            for (Identity id : ids) h.append(',').append(csv(id.name));
            w.write(h + "\n");
            for (MatrixEntry e : model.rows()) {
                StringBuilder row = new StringBuilder();
                row.append(e.index).append(',').append(csv(e.method)).append(',').append(csv(e.host))
                   .append(',').append(csv(safePath(e))).append(',').append(e.baseStatus).append(',')
                   .append(csv(cell(e.unauthResult)));
                for (Identity id : ids) row.append(',').append(csv(cell(e.result(id.id))));
                w.write(row + "\n");
            }
            api.logging().logToOutput("Authz-ExeC exported to " + fc.getSelectedFile());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage());
        }
    }

    private static String cell(TestResult tr) {
        if (tr == null) return "";
        String s = tr.verdict.label + (tr.statusCode >= 0 ? " " + tr.statusCode : "");
        if (tr.note != null && !tr.note.isEmpty()) s += " — " + tr.note;
        return s;
    }
    private static String safePath(MatrixEntry e) {
        try { return e.baseRequest.path(); } catch (Exception ex) { return e.url; }
    }
    private static String csv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n"))
            return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }

    /** Tiny DocumentListener adapter so we can pass a lambda. */
    private interface SimpleDoc extends javax.swing.event.DocumentListener {
        void update();
        @Override default void insertUpdate(javax.swing.event.DocumentEvent e) { update(); }
        @Override default void removeUpdate(javax.swing.event.DocumentEvent e) { update(); }
        @Override default void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
    }
}
