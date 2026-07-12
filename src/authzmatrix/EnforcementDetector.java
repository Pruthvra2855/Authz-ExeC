package authzmatrix;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The response-comparison engine. Implements the three-state model:
 *   A = privileged base response (MatrixEntry)
 *   B = the identity under test
 *   C = fully unauthenticated baseline
 * A real bypass requires B looks like A AND C does NOT (unauth was refused). Bodies are
 * normalised (volatile tokens stripped) before comparison, and tenant canary markers give
 * near-proof of cross-tenant leaks.
 */
public class EnforcementDetector {

    public final DetectorConfig cfg;
    public EnforcementDetector(DetectorConfig cfg) { this.cfg = cfg; }

    // ---------- result of a classification ----------
    public static class Outcome {
        public final Verdict verdict;
        public final int confidence;
        public final String note;
        public Outcome(Verdict v, int c, String n) { verdict = v; confidence = c; note = n == null ? "" : n; }
    }

    // ---------- a comparable view of a response ----------
    static final class View {
        final int status;
        final String rawLower;
        final String norm;
        final int lenNorm;
        final Set<String> keys;
        final String location;

        View(int status, String raw, String norm, Set<String> keys, String location) {
            this.status = status;
            this.rawLower = raw == null ? "" : raw.toLowerCase(Locale.ROOT);
            this.norm = norm;
            this.lenNorm = norm.length();
            this.keys = keys;
            this.location = location == null ? "" : location.toLowerCase(Locale.ROOT);
        }
    }

    View view(HttpResponse r) {
        String raw = r.bodyToString();
        return new View(r.statusCode(), raw, normalize(raw), jsonKeys(raw), r.headerValue("Location"));
    }

    View baseView(MatrixEntry e) {
        return new View(e.baseStatus, e.baseBodyRaw, e.baseNorm, e.baseKeys,
                e.baseResponse != null ? e.baseResponse.headerValue("Location") : null);
    }

    // ================= public classification =================

    /** Classify identity response B against base A, using unauth C and canary markers. */
    public Outcome classify(HttpResponse identityResp, MatrixEntry e, HttpResponse unauthResp,
                            Identity underTest, List<Identity> allIdentities) {
        if (identityResp == null) return new Outcome(Verdict.ERROR, -1, "no response");
        View b = view(identityResp);
        View base = baseView(e);
        View c = unauthResp != null ? view(unauthResp) : null;

        if (isWaf(b)) return new Outcome(Verdict.INFRA_BLOCK, -1, "WAF / rate-limit — not app authz");

        // public-endpoint guard: if unauthenticated already gets the privileged result, there is no control
        if (c != null && same(c, base) && !isDenied(c))
            return new Outcome(Verdict.PUBLIC_NOAUTH, -1, "unauthenticated request also succeeds");

        // canary marker leak = near proof of cross-tenant / horizontal BAC
        String foreign = foreignMarkerHit(identityResp.bodyToString(), underTest, allIdentities);
        if (foreign != null)
            return new Outcome(Verdict.BYPASSED, 95, "leaked another identity's marker: " + foreign);

        if (isDenied(b)) return new Outcome(Verdict.ENFORCED, -1, "denied (" + b.status + ")");

        if (isEmptySuccess(b) && !isEmptySuccess(base))
            return new Outcome(Verdict.ENFORCED, -1, "2xx but empty — row/object-level filtered");

        boolean sameBA = same(b, base);
        boolean sameBC = c != null && same(b, c);

        if (sameBA && !sameBC) {
            int conf = score(b, base, c);
            if (conf >= cfg.confidenceReport)
                return new Outcome(Verdict.BYPASSED, conf, "B matches privileged A, unauth refused");
            return new Outcome(Verdict.AMBIGUOUS, conf, "looks like bypass but low confidence (" + conf + ")");
        }
        if (sameBC && !sameBA)
            return new Outcome(Verdict.ENFORCED, -1, "matches unauthenticated/denied template");

        // returns the identity's OWN data (rescoped to self) => enforced
        if (ownMarkerHit(identityResp.bodyToString(), underTest) && !sameBA)
            return new Outcome(Verdict.ENFORCED, -1, "rescoped to own data");

        return new Outcome(Verdict.AMBIGUOUS, -1, "B resembles neither A nor C clearly");
    }

    /** Verdict for the unauthenticated baseline cell itself. */
    public Outcome classifyUnauth(HttpResponse unauthResp, MatrixEntry e) {
        if (unauthResp == null) return new Outcome(Verdict.ERROR, -1, "no response");
        View c = view(unauthResp);
        View base = baseView(e);
        if (isWaf(c)) return new Outcome(Verdict.INFRA_BLOCK, -1, "WAF / rate-limit");
        if (same(c, base) && !isDenied(c))
            return new Outcome(Verdict.PUBLIC_NOAUTH, -1, "endpoint served without auth");
        if (isDenied(c)) return new Outcome(Verdict.ENFORCED, -1, "unauth denied (" + c.status + ")");
        return new Outcome(Verdict.AMBIGUOUS, -1, "unauth differs from A");
    }

    // ================= predicates =================

    boolean isDenied(View v) {
        if (cfg.enforcedStatusCodes.contains(v.status)) return true;
        boolean denialWord = containsAny(v.rawLower, cfg.fingerprints);
        if (denialWord && (v.rawLower.length() < cfg.denialFpMaxLen || looksLikeJsonError(v.rawLower)))
            return true;
        if (v.status >= 300 && v.status < 400 && containsAny(v.location, cfg.redirectLoginMarkers))
            return true;
        return false;
    }

    boolean isWaf(View v) {
        if (v.status == 429) return true;
        return containsAny(v.rawLower, cfg.wafFingerprints);
    }

    boolean isEmptySuccess(View v) {
        if (v.status < 200 || v.status >= 300) return false;
        String t = v.rawLower.trim();
        if (t.equals("[]") || t.equals("{}") || t.isEmpty()) return true;
        return containsAny(t, cfg.emptyResultMarkers);
    }

    private static boolean looksLikeJsonError(String lower) {
        return lower.length() < 4096
                && (lower.contains("\"error\"") || lower.contains("\"errors\"") || lower.contains("\"message\""));
    }

    // ================= comparison =================

    boolean same(View x, View y) {
        if (x.status != y.status) return false;
        double sim = similarity(x.norm, y.norm);
        if (sim * 100 >= cfg.simSame) return true;
        if (!x.keys.isEmpty() && jaccard(x.keys, y.keys) * 100 >= cfg.jsonKeysetSame) return true;
        if (lenClose(x.lenNorm, y.lenNorm) && sim * 100 >= cfg.simDiff) return true;
        return false;
    }

    boolean diff(View x, View y) {
        return !same(x, y) && similarity(x.norm, y.norm) * 100 < cfg.simDiff;
    }

    boolean lenClose(int a, int b) {
        int tol = Math.max((int) (Math.max(a, b) * (cfg.lengthTolerancePct / 100.0)), cfg.lengthToleranceFloor);
        return Math.abs(a - b) <= tol;
    }

    int score(View b, View base, View c) {
        int s = 0;
        if (b.status == base.status && b.status >= 200 && b.status < 300) s += 40;
        double sim = similarity(b.norm, base.norm);
        if (sim * 100 >= cfg.simSame) s += 25;
        if (!b.keys.isEmpty() && jaccard(b.keys, base.keys) * 100 >= cfg.jsonKeysetSame) s += 15;
        if (lenClose(b.lenNorm, base.lenNorm)) s += 10;
        if (c != null && diff(b, c)) s += 10;
        return s;
    }

    // ================= markers =================

    /** Any marker belonging to a DIFFERENT identity present in the body => cross-tenant leak. */
    private String foreignMarkerHit(String body, Identity underTest, List<Identity> all) {
        if (body == null || body.isEmpty() || all == null) return null;
        String lower = body.toLowerCase(Locale.ROOT);
        Set<String> own = new HashSet<>();
        for (String m : underTest.markerList()) own.add(m.toLowerCase(Locale.ROOT));
        for (Identity o : all) {
            if (o == underTest || !o.enabled) continue;
            for (String m : o.markerList()) {
                String ml = m.toLowerCase(Locale.ROOT);
                if (!own.contains(ml) && lower.contains(ml)) return m;
            }
        }
        return null;
    }

    private boolean ownMarkerHit(String body, Identity underTest) {
        if (body == null || body.isEmpty()) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        for (String m : underTest.markerList()) if (lower.contains(m.toLowerCase(Locale.ROOT))) return true;
        return false;
    }

    private static boolean containsAny(String haystackLower, List<String> needles) {
        if (haystackLower == null || haystackLower.isEmpty()) return false;
        for (String n : needles) {
            if (n == null || n.isEmpty()) continue;
            if (haystackLower.contains(n.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    // ================= static normalisation / similarity =================

    private static final Pattern[] VOLATILE = {
        Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\d{4}-\\d{2}-\\d{2}[t ]\\d{2}:\\d{2}:\\d{2}\\S*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b\\d{10,13}\\b"),
        Pattern.compile("(?i)(csrf|xsrf|authenticity_token|__requestverificationtoken|_token|nonce)[\"'=:\\s]+[\\w\\-+/=]{8,}"),
        Pattern.compile("(?i)(__viewstate|__eventvalidation|__viewstategenerator)[\"'=:\\s]+[\\w\\-+/=]+"),
        Pattern.compile("(?i)(request[-_ ]?id|trace[-_ ]?id|correlation[-_ ]?id|x-amz-request-id|x-request-id)[\"'=:\\s]+[\\w\\-]+"),
        Pattern.compile("\\b[0-9a-fA-F]{32,}\\b")
    };
    private static final Pattern COMMENT = Pattern.compile("<!--.*?-->", Pattern.DOTALL);
    private static final Pattern WS = Pattern.compile("\\s+");
    private static final Pattern KEY = Pattern.compile("\"([A-Za-z0-9_\\-.]{1,64})\"\\s*:");

    /** Strip volatile content and collapse whitespace so unrelated per-request jitter does not skew diffs. */
    public static String normalize(String body) {
        if (body == null || body.isEmpty()) return "";
        String s = body.toLowerCase(Locale.ROOT);
        s = COMMENT.matcher(s).replaceAll(" ");
        for (Pattern p : VOLATILE) s = p.matcher(s).replaceAll("#");
        s = WS.matcher(s).replaceAll(" ").trim();
        return s;
    }

    public static Set<String> jsonKeys(String body) {
        Set<String> out = new HashSet<>();
        if (body == null || body.isEmpty()) return out;
        Matcher m = KEY.matcher(body);
        int cap = 0;
        while (m.find() && cap++ < 4000) out.add(m.group(1).toLowerCase(Locale.ROOT));
        return out;
    }

    /** Weighted token overlap in [0,1] (1 = identical). Bounded for large bodies. */
    public static double similarity(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        if (a.equals(b)) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        Map<String, Integer> ma = tokens(a), mb = tokens(b);
        if (ma.isEmpty() && mb.isEmpty()) return 1.0;
        Set<String> keys = new HashSet<>(ma.keySet());
        keys.addAll(mb.keySet());
        long inter = 0, total = 0;
        for (String k : keys) {
            int x = ma.getOrDefault(k, 0), y = mb.getOrDefault(k, 0);
            inter += Math.min(x, y);
            total += Math.max(x, y);
        }
        return total == 0 ? 1.0 : (double) inter / total;
    }

    public static double jaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        Set<String> inter = new HashSet<>(a);
        inter.retainAll(b);
        Set<String> uni = new HashSet<>(a);
        uni.addAll(b);
        return (double) inter.size() / uni.size();
    }

    private static Map<String, Integer> tokens(String s) {
        Map<String, Integer> m = new HashMap<>();
        int count = 0;
        for (String t : s.split("[^a-z0-9]+")) {
            if (t.isEmpty()) continue;
            m.merge(t, 1, Integer::sum);
            if (++count > 8000) break;
        }
        return m;
    }
}
