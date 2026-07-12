package authzmatrix;

import burp.api.montoya.MontoyaApi;

import javax.swing.JTabbedPane;
import java.awt.Component;

/** Assembles the extension's suite tab. */
public class MainTab {

    private final JTabbedPane tabs = new JTabbedPane();
    public final MatrixPanel matrixPanel;
    public final IdentitiesPanel identitiesPanel;
    public final ConfigPanel configPanel;

    public MainTab(MontoyaApi api, AppState state, AuthEngine engine) {
        matrixPanel = new MatrixPanel(api, state, engine);
        identitiesPanel = new IdentitiesPanel(api, state, engine);
        configPanel = new ConfigPanel(api, state, engine);

        tabs.addTab("Results Matrix", matrixPanel);
        tabs.addTab("Identities", identitiesPanel);
        tabs.addTab("Config", configPanel);
        tabs.addTab("JWT Tools", new JwtPanel(api));
    }

    public Component getUi() { return tabs; }
}
