package authzmatrix;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds identities + configuration, notifies the UI on identity changes, and persists everything.
 * Config lives in preferences() (global, cross-project); identities live in extensionData()
 * (per-project, since session cookies/tokens are engagement-specific).
 */
public class AppState {

    public final List<Identity> identities = new ArrayList<>();
    public final DetectorConfig detector = new DetectorConfig();
    public final ScanConfig scan = new ScanConfig();

    /** Dedup keys of every endpoint already queued/tested — never re-sent. Persists per project. */
    public final Set<String> testedKeys = ConcurrentHashMap.newKeySet();
    private static final int MAX_PERSISTED_KEYS = 20000;

    private MontoyaApi api;

    public interface IdentitiesListener { void identitiesChanged(); }
    private final List<IdentitiesListener> listeners = new ArrayList<>();
    public void addIdentitiesListener(IdentitiesListener l) { listeners.add(l); }
    public void fireIdentitiesChanged() {
        for (IdentitiesListener l : new ArrayList<>(listeners)) {
            try { l.identitiesChanged(); } catch (Exception ignore) {}
        }
    }

    /** Fired after a full state replacement (e.g. loading a preset) so panels reload their fields. */
    private final List<Runnable> reloadListeners = new ArrayList<>();
    public void addReloadListener(Runnable r) { reloadListeners.add(r); }
    public void fireReload() {
        for (Runnable r : new ArrayList<>(reloadListeners)) {
            try { r.run(); } catch (Exception ignore) {}
        }
    }

    public synchronized List<Identity> identitiesSnapshot() { return new ArrayList<>(identities); }

    public void init(MontoyaApi api) {
        this.api = api;
        load();
    }

    // ---------------- persistence ----------------

    public void save() {
        if (api == null) return;
        try {
            Preferences p = api.persistence().preferences();
            p.setInteger("lengthTolerancePct", detector.lengthTolerancePct);
            p.setInteger("simSame", detector.simSame);
            p.setInteger("simDiff", detector.simDiff);
            p.setInteger("jsonKeysetSame", detector.jsonKeysetSame);
            p.setInteger("confidenceReport", detector.confidenceReport);
            p.setBoolean("sendUnauthBaseline", detector.sendUnauthBaseline);
            p.setBoolean("onlyTestSuccessfulBase", detector.onlyTestSuccessfulBase);
            p.setBoolean("doubleSendVolatile", detector.doubleSendVolatile);
            p.setString("enforcedStatusCodes", joinInts(detector.enforcedStatusCodes));
            p.setString("fingerprints", String.join("\n", detector.fingerprints));

            p.setBoolean("liveEnabled", scan.liveEnabled);
            p.setBoolean("dryRun", scan.dryRun);
            p.setString("sources", joinTools(scan.sources));
            p.setBoolean("onlyInScope", scan.onlyInScope);
            p.setBoolean("requireAuthHeader", scan.requireAuthHeader);
            p.setBoolean("onlyJsonResponses", scan.onlyJsonResponses);
            p.setBoolean("skipIdentityOwnTraffic", scan.skipIdentityOwnTraffic);
            p.setString("includeRegex", scan.includeRegex);
            p.setString("excludeRegex", scan.excludeRegex);
            p.setString("methods", String.join(",", scan.methods));
            p.setBoolean("allowWriteMethods", scan.allowWriteMethods);
            p.setBoolean("testGraphQL", scan.testGraphQL);
            p.setBoolean("allMethodsExceptOptions", scan.allMethodsExceptOptions);
            p.setString("skipExtensions", String.join(",", scan.skipExtensions));
            p.setBoolean("dedupe", scan.dedupe);
            p.setInteger("threads", scan.threads);
            p.setInteger("minIntervalMs", scan.minIntervalMs);
            p.setInteger("maxRows", scan.maxRows);

            PersistedObject root = api.persistence().extensionData();
            root.setInteger("identityCount", identities.size());
            int i = 0;
            for (Identity id : identities) {
                PersistedObject o = PersistedObject.persistedObject();
                o.setString("name", nz(id.name));
                o.setString("tenant", nz(id.tenant));
                o.setBoolean("enabled", id.enabled);
                o.setBoolean("unauth", id.unauth);
                o.setString("cookie", nz(id.cookie));
                o.setString("authorization", nz(id.authorization));
                o.setString("setHeaders", nz(id.setHeaders));
                o.setString("removeHeaders", nz(id.removeHeaders));
                o.setString("rewriteRules", nz(id.rewriteRules));
                o.setString("markers", nz(id.markers));
                o.setString("sanityUrl", nz(id.sanityUrl));
                root.setChildObject("identity_" + i, o);
                i++;
            }

            // remember which endpoints have already been tested so they are never re-sent
            PersistedList<String> tk = PersistedList.persistedStringList();
            int cap = 0;
            for (String k : testedKeys) { tk.add(k); if (++cap >= MAX_PERSISTED_KEYS) break; }
            root.setStringList("testedKeys", tk);
        } catch (Exception ex) {
            if (api != null) api.logging().logToError("Authz-ExeC save failed: " + ex);
        }
    }

    public void load() {
        try {
            Preferences p = api.persistence().preferences();
            detector.lengthTolerancePct = getInt(p, "lengthTolerancePct", detector.lengthTolerancePct);
            detector.simSame = getInt(p, "simSame", detector.simSame);
            detector.simDiff = getInt(p, "simDiff", detector.simDiff);
            detector.jsonKeysetSame = getInt(p, "jsonKeysetSame", detector.jsonKeysetSame);
            detector.confidenceReport = getInt(p, "confidenceReport", detector.confidenceReport);
            detector.sendUnauthBaseline = getBool(p, "sendUnauthBaseline", detector.sendUnauthBaseline);
            detector.onlyTestSuccessfulBase = getBool(p, "onlyTestSuccessfulBase", detector.onlyTestSuccessfulBase);
            detector.doubleSendVolatile = getBool(p, "doubleSendVolatile", detector.doubleSendVolatile);
            detector.enforcedStatusCodes = parseInts(p.getString("enforcedStatusCodes"), detector.enforcedStatusCodes);
            detector.fingerprints = parseLines(p.getString("fingerprints"), detector.fingerprints);

            scan.liveEnabled = getBool(p, "liveEnabled", scan.liveEnabled);
            scan.dryRun = getBool(p, "dryRun", scan.dryRun);
            scan.sources = parseTools(p.getString("sources"), scan.sources);
            scan.onlyInScope = getBool(p, "onlyInScope", scan.onlyInScope);
            scan.requireAuthHeader = getBool(p, "requireAuthHeader", scan.requireAuthHeader);
            scan.onlyJsonResponses = getBool(p, "onlyJsonResponses", scan.onlyJsonResponses);
            scan.skipIdentityOwnTraffic = getBool(p, "skipIdentityOwnTraffic", scan.skipIdentityOwnTraffic);
            scan.includeRegex = nz(p.getString("includeRegex"));
            scan.excludeRegex = nz(p.getString("excludeRegex"));
            scan.methods = parseCsvSet(p.getString("methods"), scan.methods);
            scan.allowWriteMethods = getBool(p, "allowWriteMethods", scan.allowWriteMethods);
            scan.testGraphQL = getBool(p, "testGraphQL", scan.testGraphQL);
            scan.allMethodsExceptOptions = getBool(p, "allMethodsExceptOptions", scan.allMethodsExceptOptions);
            scan.skipExtensions = parseCsvSet(p.getString("skipExtensions"), scan.skipExtensions);
            scan.skipExtensions.removeAll(ScanConfig.FILE_EXT); // never skip files/images — they may be IDOR objects
            scan.dedupe = getBool(p, "dedupe", scan.dedupe);
            scan.threads = getInt(p, "threads", scan.threads);
            scan.minIntervalMs = getInt(p, "minIntervalMs", scan.minIntervalMs);
            scan.maxRows = getInt(p, "maxRows", scan.maxRows);

            PersistedObject root = api.persistence().extensionData();
            Integer cnt = root.getInteger("identityCount");
            identities.clear();
            if (cnt != null) {
                for (int i = 0; i < cnt; i++) {
                    PersistedObject o = root.getChildObject("identity_" + i);
                    if (o == null) continue;
                    Identity id = new Identity();
                    id.name = nz(o.getString("name"));
                    id.tenant = nz(o.getString("tenant"));
                    id.enabled = getBool(o, "enabled", true);
                    id.unauth = getBool(o, "unauth", false);
                    id.cookie = nz(o.getString("cookie"));
                    id.authorization = nz(o.getString("authorization"));
                    id.setHeaders = nz(o.getString("setHeaders"));
                    id.removeHeaders = nz(o.getString("removeHeaders"));
                    id.rewriteRules = nz(o.getString("rewriteRules"));
                    id.markers = nz(o.getString("markers"));
                    id.sanityUrl = nz(o.getString("sanityUrl"));
                    identities.add(id);
                }
            }
            if (identities.isEmpty()) seedDefaults();

            testedKeys.clear();
            PersistedList<String> tk = root.getStringList("testedKeys");
            if (tk != null) testedKeys.addAll(tk);
        } catch (Exception ex) {
            if (api != null) api.logging().logToError("Authz-ExeC load failed: " + ex);
            if (identities.isEmpty()) seedDefaults();
        }
    }

    private void seedDefaults() {
        Identity low = new Identity("Low-Priv User");
        low.tenant = "Tenant A";
        identities.add(low);
        Identity unauth = new Identity("Unauthenticated");
        unauth.unauth = true;
        identities.add(unauth);
    }

    // ---------------- helpers ----------------

    static String nz(String s) { return s == null ? "" : s; }

    static int getInt(Preferences p, String k, int def) { Integer v = p.getInteger(k); return v == null ? def : v; }
    static boolean getBool(Preferences p, String k, boolean def) { Boolean v = p.getBoolean(k); return v == null ? def : v; }
    static boolean getBool(PersistedObject o, String k, boolean def) { Boolean v = o.getBoolean(k); return v == null ? def : v; }

    static String joinInts(Set<Integer> s) {
        StringBuilder b = new StringBuilder();
        for (Integer i : s) { if (b.length() > 0) b.append(','); b.append(i); }
        return b.toString();
    }
    static String joinTools(Set<ToolType> s) {
        StringBuilder b = new StringBuilder();
        for (ToolType t : s) { if (b.length() > 0) b.append(','); b.append(t.name()); }
        return b.toString();
    }
    static Set<Integer> parseInts(String s, Set<Integer> def) {
        if (s == null || s.isBlank()) return def;
        Set<Integer> out = new LinkedHashSet<>();
        for (String p : s.split(",")) { try { out.add(Integer.parseInt(p.trim())); } catch (Exception ignore) {} }
        return out.isEmpty() ? def : out;
    }
    static List<String> parseLines(String s, List<String> def) {
        if (s == null) return def;
        List<String> out = new ArrayList<>();
        for (String l : s.split("\\r?\\n")) if (!l.trim().isEmpty()) out.add(l.trim());
        return out.isEmpty() ? def : out;
    }
    static Set<String> parseCsvSet(String s, Set<String> def) {
        if (s == null) return def;
        Set<String> out = new LinkedHashSet<>();
        for (String p : s.split(",")) if (!p.trim().isEmpty()) out.add(p.trim());
        return out.isEmpty() ? def : out;
    }
    static Set<ToolType> parseTools(String s, Set<ToolType> def) {
        if (s == null || s.isBlank()) return def;
        Set<ToolType> out = new LinkedHashSet<>();
        for (String p : s.split(",")) { try { out.add(ToolType.valueOf(p.trim())); } catch (Exception ignore) {} }
        return out.isEmpty() ? def : out;
    }
}
