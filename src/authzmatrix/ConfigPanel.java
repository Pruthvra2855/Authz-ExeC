package authzmatrix;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashSet;
import java.util.Set;

/** Scan filtering, throttling, and detector-tuning settings. */
public class ConfigPanel extends JPanel {

    private final AppState state;
    private final AuthEngine engine;

    private final JCheckBox dryRun = new JCheckBox("Dry run (capture candidates but do not send replays)");
    private final JCheckBox onlyInScope = new JCheckBox("Only test in-scope URLs");
    private final JCheckBox requireAuth = new JCheckBox("Only test requests that carry auth (Cookie/Authorization/...)");
    private final JCheckBox onlyJson = new JCheckBox("API mode: skip rendered HTML pages (test JSON, files, XML, empty & header-based API responses)");
    private final JCheckBox skipIdentity = new JCheckBox("Skip a configured identity's own traffic (don't test requests you made while browsing AS that identity)");

    private final JCheckBox srcProxy = new JCheckBox("Proxy");
    private final JCheckBox srcRepeater = new JCheckBox("Repeater");
    private final JCheckBox srcTarget = new JCheckBox("Target");

    private final JCheckBox mGet = new JCheckBox("GET");
    private final JCheckBox mPost = new JCheckBox("POST");
    private final JCheckBox mPut = new JCheckBox("PUT");
    private final JCheckBox mPatch = new JCheckBox("PATCH");
    private final JCheckBox mDelete = new JCheckBox("DELETE");
    private final JCheckBox allMethods = new JCheckBox("Test ALL methods except OPTIONS/HEAD (overrides the boxes above — replays real PUT/PATCH/DELETE)");

    private final JCheckBox testGraphQL = new JCheckBox("Auto-test GraphQL POST queries (mutations still need a write method enabled)");
    private final JTextField includeRegex = new JTextField(30);
    private final JTextField excludeRegex = new JTextField(30);
    private final JTextField skipExt = new JTextField(30);

    private final JSpinner threads = spinner(4, 1, 32);
    private final JSpinner minInterval = spinner(250, 0, 60000);
    private final JSpinner maxRows = spinner(2000, 10, 100000);

    private final JCheckBox unauthBaseline = new JCheckBox("Send unauthenticated baseline (state C) — kills public-endpoint false positives");
    private final JCheckBox onlySuccessBase = new JCheckBox("Only test endpoints the privileged base could access");
    private final JCheckBox doubleSend = new JCheckBox("Double-send to detect volatile endpoints");
    private final JSpinner lenTol = spinner(5, 0, 100);
    private final JSpinner simSame = spinner(90, 0, 100);
    private final JSpinner simDiff = spinner(60, 0, 100);
    private final JSpinner jsonKeyset = spinner(80, 0, 100);
    private final JSpinner confidence = spinner(70, 0, 100);
    private final JTextField enforcedCodes = new JTextField(20);
    private final JTextArea fingerprints = new JTextArea(6, 40);

    public ConfigPanel(MontoyaApi api, AppState state, AuthEngine engine) {
        super(new BorderLayout());
        this.state = state;
        this.engine = engine;

        Box box = Box.createVerticalBox();
        box.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        box.add(section("Capture"));
        box.add(row(dryRun));
        box.add(row(onlyInScope, requireAuth));
        box.add(row(onlyJson));
        box.add(row(skipIdentity));
        box.add(row(new JLabel("Test traffic from: "), srcProxy, srcRepeater, srcTarget));
        JLabel warn = new JLabel("Methods to auto-replay. GET+POST are tested by default; PUT/PATCH/DELETE are destructive (modify/delete data) — enable only when safe:");
        warn.setForeground(new Color(180, 90, 20));
        box.add(row(warn));
        box.add(row(mGet, mPost, mPut, mPatch, mDelete));
        allMethods.setForeground(new Color(180, 90, 20));
        allMethods.addActionListener(e -> updateMethodBoxes());
        box.add(row(allMethods));
        box.add(row(testGraphQL));
        box.add(labeled("Include URL regex (optional)", includeRegex));
        box.add(labeled("Exclude URL regex (optional)", excludeRegex));
        box.add(labeled("Skip file extensions (comma separated)", skipExt));
        JLabel dedupeInfo = new JLabel("De-dup is automatic: identical requests are never re-sent, but different param VALUES / GraphQL queries are each tested.");
        dedupeInfo.setForeground(new Color(90, 120, 90));
        box.add(row(dedupeInfo));
        box.add(row(new JLabel("Threads:"), threads, new JLabel("  Min interval ms (rate limit):"), minInterval,
                new JLabel("  Max rows:"), maxRows));

        box.add(Box.createVerticalStrut(10));
        box.add(section("Detector"));
        box.add(row(unauthBaseline));
        box.add(row(onlySuccessBase, doubleSend));
        box.add(row(new JLabel("Length tol %:"), lenTol, new JLabel("  Sim-same %:"), simSame,
                new JLabel("  Sim-diff %:"), simDiff));
        box.add(row(new JLabel("JSON key-set same %:"), jsonKeyset, new JLabel("  Min bypass confidence:"), confidence));
        box.add(labeled("Denied status codes (comma separated)", enforcedCodes));
        box.add(labeled("Denial fingerprints (one per line, lowercase substring match)", fingerprints));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton apply = new JButton("Apply");
        apply.addActionListener(e -> apply());
        JButton reset = new JButton("Reset defaults");
        reset.addActionListener(e -> { resetDefaults(); });
        buttons.add(apply);
        buttons.add(reset);
        box.add(Box.createVerticalStrut(8));
        box.add(buttons);

        JScrollPane sp = new JScrollPane(box);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        add(sp, BorderLayout.CENTER);

        loadFromState();
        state.addReloadListener(this::loadFromState);
    }

    private void loadFromState() {
        ScanConfig s = state.scan;
        DetectorConfig d = state.detector;
        dryRun.setSelected(s.dryRun);
        onlyInScope.setSelected(s.onlyInScope);
        requireAuth.setSelected(s.requireAuthHeader);
        onlyJson.setSelected(s.onlyJsonResponses);
        skipIdentity.setSelected(s.skipIdentityOwnTraffic);
        srcProxy.setSelected(s.sources.contains(ToolType.PROXY));
        srcRepeater.setSelected(s.sources.contains(ToolType.REPEATER));
        srcTarget.setSelected(s.sources.contains(ToolType.TARGET));
        mGet.setSelected(s.methods.contains("GET"));
        mPost.setSelected(s.methods.contains("POST"));
        mPut.setSelected(s.methods.contains("PUT"));
        mPatch.setSelected(s.methods.contains("PATCH"));
        mDelete.setSelected(s.methods.contains("DELETE"));
        allMethods.setSelected(s.allMethodsExceptOptions);
        updateMethodBoxes();
        testGraphQL.setSelected(s.testGraphQL);
        includeRegex.setText(s.includeRegex);
        excludeRegex.setText(s.excludeRegex);
        skipExt.setText(String.join(",", s.skipExtensions));
        threads.setValue(s.threads);
        minInterval.setValue(s.minIntervalMs);
        maxRows.setValue(s.maxRows);

        unauthBaseline.setSelected(d.sendUnauthBaseline);
        onlySuccessBase.setSelected(d.onlyTestSuccessfulBase);
        doubleSend.setSelected(d.doubleSendVolatile);
        lenTol.setValue(d.lengthTolerancePct);
        simSame.setValue(d.simSame);
        simDiff.setValue(d.simDiff);
        jsonKeyset.setValue(d.jsonKeysetSame);
        confidence.setValue(d.confidenceReport);
        enforcedCodes.setText(AppState.joinInts(d.enforcedStatusCodes));
        fingerprints.setText(String.join("\n", d.fingerprints));
    }

    private void apply() {
        ScanConfig s = state.scan;
        DetectorConfig d = state.detector;
        s.dryRun = dryRun.isSelected();
        s.onlyInScope = onlyInScope.isSelected();
        s.requireAuthHeader = requireAuth.isSelected();
        s.onlyJsonResponses = onlyJson.isSelected();
        s.skipIdentityOwnTraffic = skipIdentity.isSelected();
        Set<ToolType> src = new LinkedHashSet<>();
        if (srcProxy.isSelected()) src.add(ToolType.PROXY);
        if (srcRepeater.isSelected()) src.add(ToolType.REPEATER);
        if (srcTarget.isSelected()) src.add(ToolType.TARGET);
        if (src.isEmpty()) src.add(ToolType.PROXY);
        s.sources = src;
        Set<String> m = new LinkedHashSet<>();
        if (mGet.isSelected()) m.add("GET");
        if (mPost.isSelected()) m.add("POST");
        if (mPut.isSelected()) m.add("PUT");
        if (mPatch.isSelected()) m.add("PATCH");
        if (mDelete.isSelected()) m.add("DELETE");
        if (m.isEmpty()) m.add("GET");
        s.methods = m;
        // "writes" = the clearly-destructive verbs; also gates GraphQL mutations. POST alone is treated as an API read.
        s.allowWriteMethods = mPut.isSelected() || mPatch.isSelected() || mDelete.isSelected();
        s.allMethodsExceptOptions = allMethods.isSelected();
        s.testGraphQL = testGraphQL.isSelected();
        s.includeRegex = includeRegex.getText().trim();
        s.excludeRegex = excludeRegex.getText().trim();
        s.skipExtensions = AppState.parseCsvSet(skipExt.getText(), s.skipExtensions);
        s.dedupe = true; // de-dup always on; value-aware key differentiates GraphQL / different IDs
        s.threads = (Integer) threads.getValue();
        s.minIntervalMs = (Integer) minInterval.getValue();
        s.maxRows = (Integer) maxRows.getValue();

        d.sendUnauthBaseline = unauthBaseline.isSelected();
        d.onlyTestSuccessfulBase = onlySuccessBase.isSelected();
        d.doubleSendVolatile = doubleSend.isSelected();
        d.lengthTolerancePct = (Integer) lenTol.getValue();
        d.simSame = (Integer) simSame.getValue();
        d.simDiff = (Integer) simDiff.getValue();
        d.jsonKeysetSame = (Integer) jsonKeyset.getValue();
        d.confidenceReport = (Integer) confidence.getValue();
        d.enforcedStatusCodes = AppState.parseInts(enforcedCodes.getText(), d.enforcedStatusCodes);
        d.fingerprints = AppState.parseLines(fingerprints.getText(), d.fingerprints);

        engine.rebuildPool();
        state.save();
        JOptionPane.showMessageDialog(this, "Settings applied.");
    }

    private void resetDefaults() {
        ScanConfig ns = new ScanConfig();
        DetectorConfig nd = new DetectorConfig();
        // preserve the live arm switch
        ns.liveEnabled = state.scan.liveEnabled;
        copyScan(ns, state.scan);
        copyDetector(nd, state.detector);
        loadFromState();
    }

    private static void copyScan(ScanConfig from, ScanConfig to) {
        to.dryRun = from.dryRun; to.sources = from.sources; to.onlyInScope = from.onlyInScope;
        to.requireAuthHeader = from.requireAuthHeader; to.onlyJsonResponses = from.onlyJsonResponses;
        to.skipIdentityOwnTraffic = from.skipIdentityOwnTraffic;
        to.includeRegex = from.includeRegex;
        to.excludeRegex = from.excludeRegex; to.methods = from.methods; to.allowWriteMethods = from.allowWriteMethods;
        to.testGraphQL = from.testGraphQL; to.allMethodsExceptOptions = from.allMethodsExceptOptions;
        to.skipExtensions = from.skipExtensions; to.dedupe = from.dedupe;
        to.threads = from.threads;
        to.minIntervalMs = from.minIntervalMs; to.maxRows = from.maxRows;
    }

    private static void copyDetector(DetectorConfig from, DetectorConfig to) {
        to.lengthTolerancePct = from.lengthTolerancePct; to.simSame = from.simSame; to.simDiff = from.simDiff;
        to.jsonKeysetSame = from.jsonKeysetSame; to.confidenceReport = from.confidenceReport;
        to.sendUnauthBaseline = from.sendUnauthBaseline; to.onlyTestSuccessfulBase = from.onlyTestSuccessfulBase;
        to.doubleSendVolatile = from.doubleSendVolatile; to.enforcedStatusCodes = from.enforcedStatusCodes;
        to.fingerprints = from.fingerprints;
    }

    // ---- layout helpers ----

    private static JComponent section(String title) {
        JLabel l = new JLabel(title);
        l.setFont(l.getFont().deriveFont(Font.BOLD, l.getFont().getSize() + 2f));
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        p.add(l);
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    private static JComponent row(JComponent... cs) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        for (JComponent c : cs) p.add(c);
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getPreferredSize().height));
        return p;
    }

    private JComponent labeled(String title, JComponent field) {
        JPanel p = new JPanel(new BorderLayout(6, 0));
        p.add(new JLabel(title), BorderLayout.NORTH);
        if (field instanceof JTextArea) p.add(new JScrollPane(field), BorderLayout.CENTER);
        else p.add(field, BorderLayout.CENTER);
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setBorder(BorderFactory.createEmptyBorder(3, 0, 3, 0));
        return p;
    }

    private void updateMethodBoxes() {
        boolean per = !allMethods.isSelected();
        for (JCheckBox b : new JCheckBox[]{mGet, mPost, mPut, mPatch, mDelete}) b.setEnabled(per);
    }

    private static JSpinner spinner(int val, int min, int max) {
        return new JSpinner(new SpinnerNumberModel(val, min, max, 1));
    }
}
