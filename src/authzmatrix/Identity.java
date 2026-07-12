package authzmatrix;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * One tester identity (a column in the matrix). Defines how a captured request is
 * rewritten to "become" this identity: swap Cookie / Authorization / custom headers,
 * remove headers, or strip all auth (unauthenticated). Optional regex rewrite rules let
 * you substitute object/tenant IDs for BOLA / cross-tenant testing.
 */
public class Identity {

    public String id;
    public String name = "Identity";
    public String tenant = "";           // free-text grouping label (e.g. "Tenant B")
    public boolean enabled = true;
    public boolean unauth = false;        // if true: strip all auth instead of setting it

    public String cookie = "";            // whole Cookie header value
    public String authorization = "";     // whole Authorization header value (e.g. "Bearer eyJ...")
    public String setHeaders = "";        // extra headers, "Name: Value" per line (X-Tenant-Id, X-Api-Key, ...)
    public String removeHeaders = "";     // header names to strip, one per line
    public String rewriteRules = "";      // "regex => replacement" per line, applied to path + body
    public String markers = "";           // canary strings unique to THIS identity's data, one per line
    public String sanityUrl = "";         // a URL that returns 200 while this identity's session is live

    public Identity() {
        this.id = "id-" + System.nanoTime() + "-" + System.identityHashCode(this);
    }

    public Identity(String name) {
        this();
        this.name = name;
    }

    /** Produce the request as it would be sent by this identity. */
    public HttpRequest apply(HttpRequest base) {
        HttpRequest r = base;
        if (unauth) {
            r = stripCommonAuth(r);
        } else {
            if (isSet(cookie))        r = r.withUpdatedHeader("Cookie", cookie.trim());
            if (isSet(authorization)) r = r.withUpdatedHeader("Authorization", authorization.trim());
        }
        for (String line : splitLines(setHeaders)) {
            int idx = line.indexOf(':');
            if (idx <= 0) continue;
            String n = line.substring(0, idx).trim();
            String v = line.substring(idx + 1).trim();
            if (!n.isEmpty()) r = r.withUpdatedHeader(n, v);
        }
        for (String line : splitLines(removeHeaders)) {
            String n = line.trim();
            if (!n.isEmpty() && r.hasHeader(n)) r = r.withRemovedHeader(n);
        }
        List<String[]> rules = parseRules(rewriteRules);
        if (!rules.isEmpty()) r = applyRewrites(r, rules);
        return r;
    }

    private HttpRequest stripCommonAuth(HttpRequest r) {
        String[] common = {
            "Cookie", "Authorization", "X-Api-Key", "Api-Key", "X-Auth-Token", "X-Access-Token",
            "X-Session-Token", "X-Session-Id", "X-Csrf-Token", "X-Xsrf-Token"
        };
        for (String h : common) if (r.hasHeader(h)) r = r.withRemovedHeader(h);
        for (String line : splitLines(removeHeaders)) {
            String n = line.trim();
            if (!n.isEmpty() && r.hasHeader(n)) r = r.withRemovedHeader(n);
        }
        return r;
    }

    private static HttpRequest applyRewrites(HttpRequest r, List<String[]> rules) {
        String path = r.path();
        String body = r.bodyToString();
        boolean pathChanged = false, bodyChanged = false;
        for (String[] rule : rules) {
            try {
                String np = path.replaceAll(rule[0], rule[1]);
                if (!np.equals(path)) { path = np; pathChanged = true; }
                if (body != null && !body.isEmpty()) {
                    String nb = body.replaceAll(rule[0], rule[1]);
                    if (!nb.equals(body)) { body = nb; bodyChanged = true; }
                }
            } catch (Exception ignore) { /* bad regex -> skip that rule */ }
        }
        if (pathChanged) r = r.withPath(path);
        if (bodyChanged) r = r.withBody(body);
        return r;
    }

    public List<String> markerList() {
        List<String> out = new ArrayList<>();
        for (String l : splitLines(markers)) {
            String t = l.trim();
            if (t.length() >= 3) out.add(t);   // ignore too-short markers (noise)
        }
        return out;
    }

    public Identity copy() {
        Identity c = new Identity();
        c.name = name + " (copy)";
        c.tenant = tenant; c.enabled = enabled; c.unauth = unauth;
        c.cookie = cookie; c.authorization = authorization; c.setHeaders = setHeaders;
        c.removeHeaders = removeHeaders; c.rewriteRules = rewriteRules; c.markers = markers;
        c.sanityUrl = sanityUrl;
        return c;
    }

    private static boolean isSet(String s) { return s != null && !s.isBlank(); }

    static List<String> splitLines(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) return out;
        for (String l : s.split("\\r?\\n")) {
            String t = l.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            out.add(l);
        }
        return out;
    }

    static List<String[]> parseRules(String s) {
        List<String[]> out = new ArrayList<>();
        for (String l : splitLines(s)) {
            int idx = l.indexOf("=>");
            if (idx < 0) continue;
            String find = l.substring(0, idx).trim();
            String rep = l.substring(idx + 2).trim();
            if (!find.isEmpty()) out.add(new String[]{find, rep});
        }
        return out;
    }
}
