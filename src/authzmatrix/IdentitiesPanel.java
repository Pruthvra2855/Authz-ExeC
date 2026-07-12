package authzmatrix;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

/** Add / edit tester identities: cookies, JWTs, custom headers, ID-rewrite rules, canary markers. */
public class IdentitiesPanel extends JPanel {

    private final MontoyaApi api;
    private final AppState state;
    private final AuthEngine engine;

    private final DefaultListModel<Identity> listModel = new DefaultListModel<>();
    private final JList<Identity> list = new JList<>(listModel);

    private final JTextField nameField = new JTextField();
    private final JTextField tenantField = new JTextField();
    private final JCheckBox enabledBox = new JCheckBox("Enabled");
    private final JCheckBox unauthBox = new JCheckBox("Unauthenticated (strip all auth)");
    private final JTextArea cookieArea = new JTextArea(3, 40);
    private final JTextArea authArea = new JTextArea(2, 40);
    private final JTextArea setHeadersArea = new JTextArea(3, 40);
    private final JTextArea removeHeadersArea = new JTextArea(2, 40);
    private final JTextArea rewriteArea = new JTextArea(3, 40);
    private final JTextArea markersArea = new JTextArea(2, 40);
    private final JTextField sanityField = new JTextField();

    private boolean loading = false;

    public IdentitiesPanel(MontoyaApi api, AppState state, AuthEngine engine) {
        super(new BorderLayout(10, 0));
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        this.api = api;
        this.state = state;
        this.engine = engine;

        reloadList();
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new IdentityRenderer());
        list.addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) loadSelected(); });

        add(buildLeft(), BorderLayout.WEST);
        add(buildForm(), BorderLayout.CENTER);

        if (!listModel.isEmpty()) list.setSelectedIndex(0);
    }

    // ---------------- left: list + buttons ----------------

    private JComponent buildLeft() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder("Identities (matrix columns)"));
        JScrollPane sp = new JScrollPane(list);
        sp.setPreferredSize(new Dimension(240, 400));
        p.add(sp, BorderLayout.CENTER);

        JPanel btns = new JPanel(new GridLayout(0, 2, 4, 4));
        btns.add(button("Add", e -> add(new Identity("New Identity"))));
        btns.add(button("Add unauth", e -> { Identity i = new Identity("Unauthenticated"); i.unauth = true; add(i); }));
        btns.add(button("Duplicate", e -> { Identity s = list.getSelectedValue(); if (s != null) add(s.copy()); }));
        btns.add(button("Remove", e -> remove()));
        btns.add(button("Up", e -> move(-1)));
        btns.add(button("Down", e -> move(1)));
        btns.add(button("Check sessions", e -> checkSessions()));
        btns.add(button("Save + apply", e -> saveAndApply()));
        btns.add(button("Save preset", e -> savePreset()));
        btns.add(button("Load preset", e -> loadPreset()));
        p.add(btns, BorderLayout.SOUTH);
        return p;
    }

    private void savePreset() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("authz-matrix-preset.properties"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            saveAndApply(); // flush any pending edits first
            PresetIO.save(fc.getSelectedFile(), state);
            JOptionPane.showMessageDialog(this, "Preset saved:\n" + fc.getSelectedFile());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Save failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadPreset() {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            PresetIO.load(fc.getSelectedFile(), state);
            reloadList();
            if (!listModel.isEmpty()) list.setSelectedIndex(0);
            loadSelected();
            state.save();
            state.fireReload();          // refresh the Config tab
            state.fireIdentitiesChanged(); // refresh the matrix columns
            engine.rebuildPool();
            JOptionPane.showMessageDialog(this, "Preset loaded (" + state.identities.size() + " identities).");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Load failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // ---------------- right: editor form ----------------

    private JComponent buildForm() {
        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        for (JTextArea a : new JTextArea[]{cookieArea, authArea, setHeadersArea, removeHeadersArea, rewriteArea, markersArea})
            a.setFont(mono);

        Box box = Box.createVerticalBox();
        box.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 2, 2, 2);
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.gridx = 0; g.gridy = 0; top.add(new JLabel("Name"), g);
        g.gridx = 1; g.weightx = 1; top.add(nameField, g);
        g.gridx = 2; g.weightx = 0; top.add(new JLabel("Tenant/Group"), g);
        g.gridx = 3; g.weightx = 1; top.add(tenantField, g);
        g.gridx = 1; g.gridy = 1; g.weightx = 0; top.add(enabledBox, g);
        g.gridx = 3; top.add(unauthBox, g);
        box.add(top);

        box.add(labeled("Cookie header value", cookieArea));
        JPanel authRow = new JPanel(new BorderLayout());
        authRow.add(labeled("Authorization header value (e.g. Bearer <JWT>)", authArea), BorderLayout.CENTER);
        authRow.add(button("Decode JWT", e -> decodeJwt()), BorderLayout.EAST);
        box.add(authRow);
        box.add(labeled("Set headers (Name: Value, one per line — X-Tenant-Id, X-Api-Key, ...)", setHeadersArea));
        box.add(labeled("Remove headers (one name per line)", removeHeadersArea));
        box.add(labeled("ID rewrite rules for BOLA/cross-tenant (regex => replacement, one per line)", rewriteArea));
        box.add(labeled("Canary markers unique to this identity's data (one per line)", markersArea));
        box.add(labeled("Sanity URL (returns 200 while this session is live)", sanityField));

        bindText(nameField, v -> cur().name = v);
        bindText(tenantField, v -> cur().tenant = v);
        bindText(cookieArea, v -> cur().cookie = v);
        bindText(authArea, v -> cur().authorization = v);
        bindText(setHeadersArea, v -> cur().setHeaders = v);
        bindText(removeHeadersArea, v -> cur().removeHeaders = v);
        bindText(rewriteArea, v -> cur().rewriteRules = v);
        bindText(markersArea, v -> cur().markers = v);
        bindText(sanityField, v -> cur().sanityUrl = v);
        enabledBox.addActionListener(e -> { if (!loading && cur() != null) cur().enabled = enabledBox.isSelected(); });
        unauthBox.addActionListener(e -> { if (!loading && cur() != null) cur().unauth = unauthBox.isSelected(); });

        JScrollPane sp = new JScrollPane(box);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    private JComponent labeled(String title, JComponent field) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        p.add(new JLabel(title), BorderLayout.NORTH);
        if (field instanceof JTextArea) {
            ((JTextArea) field).setLineWrap(true);
            p.add(new JScrollPane(field), BorderLayout.CENTER);
        } else {
            p.add(field, BorderLayout.CENTER);
        }
        return p;
    }

    // ---------------- binding ----------------

    private Identity cur() { return list.getSelectedValue(); }

    private void loadSelected() {
        Identity id = cur();
        loading = true;
        try {
            boolean has = id != null;
            for (Component c : new Component[]{nameField, tenantField, cookieArea, authArea, setHeadersArea,
                    removeHeadersArea, rewriteArea, markersArea, sanityField, enabledBox, unauthBox})
                c.setEnabled(has);
            nameField.setText(has ? id.name : "");
            tenantField.setText(has ? id.tenant : "");
            cookieArea.setText(has ? id.cookie : "");
            authArea.setText(has ? id.authorization : "");
            setHeadersArea.setText(has ? id.setHeaders : "");
            removeHeadersArea.setText(has ? id.removeHeaders : "");
            rewriteArea.setText(has ? id.rewriteRules : "");
            markersArea.setText(has ? id.markers : "");
            sanityField.setText(has ? id.sanityUrl : "");
            enabledBox.setSelected(has && id.enabled);
            unauthBox.setSelected(has && id.unauth);
        } finally {
            loading = false;
        }
    }

    private void bindText(javax.swing.text.JTextComponent field, java.util.function.Consumer<String> setter) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            void go() { if (!loading && cur() != null) { setter.accept(field.getText()); list.repaint(); } }
            public void insertUpdate(DocumentEvent e) { go(); }
            public void removeUpdate(DocumentEvent e) { go(); }
            public void changedUpdate(DocumentEvent e) { go(); }
        });
    }

    // ---------------- actions ----------------

    private void add(Identity id) {
        state.identities.add(id);
        listModel.addElement(id);
        list.setSelectedValue(id, true);
        saveAndApply();
    }

    private void remove() {
        Identity id = cur();
        if (id == null) return;
        int idx = list.getSelectedIndex();
        state.identities.remove(id);
        listModel.removeElement(id);
        if (!listModel.isEmpty()) list.setSelectedIndex(Math.max(0, Math.min(idx, listModel.size() - 1)));
        saveAndApply();
    }

    private void move(int delta) {
        int i = list.getSelectedIndex();
        int j = i + delta;
        if (i < 0 || j < 0 || j >= listModel.size()) return;
        Identity a = state.identities.remove(i);
        state.identities.add(j, a);
        reloadList();
        list.setSelectedIndex(j);
        saveAndApply();
    }

    private void reloadList() {
        listModel.clear();
        for (Identity id : state.identities) listModel.addElement(id);
    }

    private void saveAndApply() {
        state.save();
        state.fireIdentitiesChanged();
        list.repaint();
    }

    private void decodeJwt() {
        Identity id = cur();
        if (id == null) return;
        String tok = id.authorization == null ? "" : id.authorization;
        if (!JwtUtil.looksLikeJwt(tok)) { tok = id.cookie; }
        String out = JwtUtil.looksLikeJwt(tok) ? JwtUtil.decodePretty(tok)
                : "No JWT found in Authorization or Cookie for this identity.";
        JTextArea ta = new JTextArea(out, 20, 60);
        ta.setEditable(false);
        JOptionPane.showMessageDialog(this, new JScrollPane(ta), "JWT — " + id.name, JOptionPane.INFORMATION_MESSAGE);
    }

    private void checkSessions() {
        StringBuilder sb = new StringBuilder();
        for (Identity id : state.identitiesSnapshot()) {
            sb.append("- ").append(id.name).append(": ");
            String jwt = id.authorization;
            if (JwtUtil.looksLikeJwt(jwt) && JwtUtil.isExpired(jwt)) sb.append("[JWT EXPIRED] ");
            if (id.sanityUrl == null || id.sanityUrl.isBlank()) {
                sb.append("no sanity URL set");
            } else {
                try {
                    HttpRequest base = HttpRequest.httpRequestFromUrl(id.sanityUrl.trim());
                    HttpResponse r = engine.probe(id, base);
                    if (r == null) sb.append("no response / error");
                    else sb.append("HTTP ").append(r.statusCode()).append(" (").append(r.body().length()).append(" bytes)")
                           .append(r.statusCode() >= 200 && r.statusCode() < 300 ? "  OK (live)" : "  likely dead");
                } catch (Exception ex) {
                    sb.append("bad URL: ").append(ex.getMessage());
                }
            }
            sb.append('\n');
        }
        JTextArea ta = new JTextArea(sb.toString(), 12, 60);
        ta.setEditable(false);
        JOptionPane.showMessageDialog(this, new JScrollPane(ta), "Session check", JOptionPane.INFORMATION_MESSAGE);
    }

    private static JButton button(String text, java.awt.event.ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    // ---------------- list renderer ----------------

    private static class IdentityRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> l, Object value, int index,
                                                      boolean sel, boolean focus) {
            super.getListCellRendererComponent(l, value, index, sel, focus);
            if (value instanceof Identity) {
                Identity id = (Identity) value;
                String tag = id.unauth ? " (unauth)" : "";
                String tenant = id.tenant == null || id.tenant.isBlank() ? "" : "  -  " + id.tenant;
                setText((id.enabled ? "[x] " : "[ ] ") + id.name + tag + tenant);
                if (!sel) setForeground(id.enabled ? l.getForeground() : Color.GRAY);
            }
            return this;
        }
    }
}
