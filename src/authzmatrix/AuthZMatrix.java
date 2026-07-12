package authzmatrix;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * Entry point. Wires the suite tab, the HTTP observer (Proxy/Repeater only, so our own replays
 * never loop), the context-menu action, and clean teardown on unload.
 */
public class AuthZMatrix implements BurpExtension {

    private MontoyaApi api;
    private AppState state;
    private AuthEngine engine;
    private MainTab mainTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Authz-ExeC — Cross-Identity / Cross-Tenant Access Control Tester");

        state = new AppState();
        state.init(api);
        engine = new AuthEngine(api, state);

        buildUiOnEdt();
        engine.setListener(mainTab.matrixPanel);

        api.userInterface().registerSuiteTab("Authz-ExeC", mainTab.getUi());
        api.http().registerHttpHandler(new Handler());
        api.userInterface().registerContextMenuItemsProvider(new Menu());

        api.extension().registerUnloadingHandler(() -> {
            try { engine.shutdown(); } catch (Exception ignore) {}
            try { mainTab.matrixPanel.stop(); } catch (Exception ignore) {}
            state.save();
        });

        api.logging().logToOutput(
            "Authz-ExeC loaded. 1) add identities  2) set Burp scope  3) arm LIVE on the Results Matrix "
          + "4) browse the target as the privileged user. See the Help tab.");
    }

    private void buildUiOnEdt() {
        Runnable build = () -> mainTab = new MainTab(api, state, engine);
        if (SwingUtilities.isEventDispatchThread()) {
            build.run();
        } else {
            try { SwingUtilities.invokeAndWait(build); }
            catch (Exception e) { build.run(); }
        }
    }

    /** Observes traffic; enqueues candidates. Does no network work here (stays off the proxy thread). */
    private class Handler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            return RequestToBeSentAction.continueWith(request);
        }
        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            try { engine.consider(response); }
            catch (Throwable t) { api.logging().logToError("Authz-ExeC consider: " + t); }
            return ResponseReceivedAction.continueWith(response);
        }
    }

    /** Right-click -> Send to Authz-ExeC (runs sends off the EDT). */
    private class Menu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> items = new ArrayList<>();
            JMenuItem mi = new JMenuItem("Send to Authz-ExeC");
            mi.addActionListener(e -> {
                final List<HttpRequestResponse> sel = new ArrayList<>(event.selectedRequestResponses());
                event.messageEditorRequestResponse().ifPresent(m -> sel.add(m.requestResponse()));
                new Thread(() -> {
                    for (HttpRequestResponse rr : sel) {
                        try { engine.manualAdd(rr); }
                        catch (Throwable t) { api.logging().logToError("manualAdd: " + t); }
                    }
                }, "authz-matrix-manual").start();
            });
            items.add(mi);
            return items;
        }
    }
}
