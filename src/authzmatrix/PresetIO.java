package authzmatrix;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Save / load a "preset" (all identities + config) to a plain UTF-8 .properties file.
 * Uses java.util.Properties so multi-line values (cookies, headers, rules) round-trip safely
 * without a hand-rolled parser. The live arm switch is intentionally NOT saved.
 */
public final class PresetIO {

    private PresetIO() {}

    public static void save(File f, AppState s) throws IOException {
        Properties p = new Properties();
        ScanConfig sc = s.scan;
        DetectorConfig d = s.detector;
        p.setProperty("version", "1");
        p.setProperty("scan.dryRun", b(sc.dryRun));
        p.setProperty("scan.sources", AppState.joinTools(sc.sources));
        p.setProperty("scan.onlyInScope", b(sc.onlyInScope));
        p.setProperty("scan.requireAuthHeader", b(sc.requireAuthHeader));
        p.setProperty("scan.onlyJsonResponses", b(sc.onlyJsonResponses));
        p.setProperty("scan.skipIdentityOwnTraffic", b(sc.skipIdentityOwnTraffic));
        p.setProperty("scan.includeRegex", nz(sc.includeRegex));
        p.setProperty("scan.excludeRegex", nz(sc.excludeRegex));
        p.setProperty("scan.methods", String.join(",", sc.methods));
        p.setProperty("scan.allowWriteMethods", b(sc.allowWriteMethods));
        p.setProperty("scan.testGraphQL", b(sc.testGraphQL));
        p.setProperty("scan.allMethodsExceptOptions", b(sc.allMethodsExceptOptions));
        p.setProperty("scan.skipExtensions", String.join(",", sc.skipExtensions));
        p.setProperty("scan.threads", String.valueOf(sc.threads));
        p.setProperty("scan.minIntervalMs", String.valueOf(sc.minIntervalMs));
        p.setProperty("scan.maxRows", String.valueOf(sc.maxRows));
        p.setProperty("det.lengthTolerancePct", String.valueOf(d.lengthTolerancePct));
        p.setProperty("det.simSame", String.valueOf(d.simSame));
        p.setProperty("det.simDiff", String.valueOf(d.simDiff));
        p.setProperty("det.jsonKeysetSame", String.valueOf(d.jsonKeysetSame));
        p.setProperty("det.confidenceReport", String.valueOf(d.confidenceReport));
        p.setProperty("det.sendUnauthBaseline", b(d.sendUnauthBaseline));
        p.setProperty("det.onlyTestSuccessfulBase", b(d.onlyTestSuccessfulBase));
        p.setProperty("det.doubleSendVolatile", b(d.doubleSendVolatile));
        p.setProperty("det.enforcedStatusCodes", AppState.joinInts(d.enforcedStatusCodes));
        p.setProperty("det.fingerprints", String.join("\n", d.fingerprints));

        p.setProperty("identity.count", String.valueOf(s.identities.size()));
        int i = 0;
        for (Identity id : s.identities) {
            String k = "identity." + i + ".";
            p.setProperty(k + "name", nz(id.name));
            p.setProperty(k + "tenant", nz(id.tenant));
            p.setProperty(k + "enabled", b(id.enabled));
            p.setProperty(k + "unauth", b(id.unauth));
            p.setProperty(k + "cookie", nz(id.cookie));
            p.setProperty(k + "authorization", nz(id.authorization));
            p.setProperty(k + "setHeaders", nz(id.setHeaders));
            p.setProperty(k + "removeHeaders", nz(id.removeHeaders));
            p.setProperty(k + "rewriteRules", nz(id.rewriteRules));
            p.setProperty(k + "markers", nz(id.markers));
            p.setProperty(k + "sanityUrl", nz(id.sanityUrl));
            i++;
        }
        try (Writer w = new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8)) {
            p.store(w, "Authz-ExeC preset - identities + config");
        }
    }

    public static void load(File f, AppState s) throws IOException {
        Properties p = new Properties();
        try (Reader r = new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8)) {
            p.load(r);
        }
        ScanConfig sc = s.scan;
        DetectorConfig d = s.detector;
        sc.dryRun = gb(p, "scan.dryRun", sc.dryRun);
        sc.sources = AppState.parseTools(p.getProperty("scan.sources"), sc.sources);
        sc.onlyInScope = gb(p, "scan.onlyInScope", sc.onlyInScope);
        sc.requireAuthHeader = gb(p, "scan.requireAuthHeader", sc.requireAuthHeader);
        sc.onlyJsonResponses = gb(p, "scan.onlyJsonResponses", sc.onlyJsonResponses);
        sc.skipIdentityOwnTraffic = gb(p, "scan.skipIdentityOwnTraffic", sc.skipIdentityOwnTraffic);
        sc.includeRegex = p.getProperty("scan.includeRegex", sc.includeRegex);
        sc.excludeRegex = p.getProperty("scan.excludeRegex", sc.excludeRegex);
        sc.methods = AppState.parseCsvSet(p.getProperty("scan.methods"), sc.methods);
        sc.allowWriteMethods = gb(p, "scan.allowWriteMethods", sc.allowWriteMethods);
        sc.testGraphQL = gb(p, "scan.testGraphQL", sc.testGraphQL);
        sc.allMethodsExceptOptions = gb(p, "scan.allMethodsExceptOptions", sc.allMethodsExceptOptions);
        sc.skipExtensions = AppState.parseCsvSet(p.getProperty("scan.skipExtensions"), sc.skipExtensions);
        sc.skipExtensions.removeAll(ScanConfig.FILE_EXT);
        sc.threads = gi(p, "scan.threads", sc.threads);
        sc.minIntervalMs = gi(p, "scan.minIntervalMs", sc.minIntervalMs);
        sc.maxRows = gi(p, "scan.maxRows", sc.maxRows);
        d.lengthTolerancePct = gi(p, "det.lengthTolerancePct", d.lengthTolerancePct);
        d.simSame = gi(p, "det.simSame", d.simSame);
        d.simDiff = gi(p, "det.simDiff", d.simDiff);
        d.jsonKeysetSame = gi(p, "det.jsonKeysetSame", d.jsonKeysetSame);
        d.confidenceReport = gi(p, "det.confidenceReport", d.confidenceReport);
        d.sendUnauthBaseline = gb(p, "det.sendUnauthBaseline", d.sendUnauthBaseline);
        d.onlyTestSuccessfulBase = gb(p, "det.onlyTestSuccessfulBase", d.onlyTestSuccessfulBase);
        d.doubleSendVolatile = gb(p, "det.doubleSendVolatile", d.doubleSendVolatile);
        d.enforcedStatusCodes = AppState.parseInts(p.getProperty("det.enforcedStatusCodes"), d.enforcedStatusCodes);
        d.fingerprints = AppState.parseLines(p.getProperty("det.fingerprints"), d.fingerprints);

        int cnt = gi(p, "identity.count", -1);
        if (cnt >= 0) {
            List<Identity> list = new ArrayList<>();
            for (int i = 0; i < cnt; i++) {
                String k = "identity." + i + ".";
                if (p.getProperty(k + "name") == null && p.getProperty(k + "cookie") == null) continue;
                Identity id = new Identity();
                id.name = p.getProperty(k + "name", "Identity");
                id.tenant = p.getProperty(k + "tenant", "");
                id.enabled = gb(p, k + "enabled", true);
                id.unauth = gb(p, k + "unauth", false);
                id.cookie = p.getProperty(k + "cookie", "");
                id.authorization = p.getProperty(k + "authorization", "");
                id.setHeaders = p.getProperty(k + "setHeaders", "");
                id.removeHeaders = p.getProperty(k + "removeHeaders", "");
                id.rewriteRules = p.getProperty(k + "rewriteRules", "");
                id.markers = p.getProperty(k + "markers", "");
                id.sanityUrl = p.getProperty(k + "sanityUrl", "");
                list.add(id);
            }
            s.identities.clear();
            s.identities.addAll(list);
        }
    }

    private static String b(boolean v) { return v ? "true" : "false"; }
    private static boolean gb(Properties p, String k, boolean def) {
        String v = p.getProperty(k);
        return v == null ? def : Boolean.parseBoolean(v.trim());
    }
    private static int gi(Properties p, String k, int def) {
        String v = p.getProperty(k);
        if (v == null) return def;
        try { return Integer.parseInt(v.trim()); } catch (Exception e) { return def; }
    }
    private static String nz(String s) { return s == null ? "" : s; }
}
