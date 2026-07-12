package authzmatrix;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Decides whether a piece of traffic is worth replaying, and computes value-aware dedup keys. */
public class RequestClassifier {

    private final MontoyaApi api;
    private final ScanConfig cfg;

    public RequestClassifier(MontoyaApi api, ScanConfig cfg) {
        this.api = api;
        this.cfg = cfg;
    }

    /** Live-traffic entry point: applies the tool allowlist, then the shared checks. */
    public boolean accept(HttpResponseReceived resp) {
        // tool allowlist — our own EXTENSIONS replays are excluded here, so no loop is possible
        if (!cfg.sources.contains(resp.toolSource().toolType())) return false;
        return accept(resp.initiatingRequest(), resp);
    }

    /** Shared checks, reused by live traffic and by "Import Proxy History". */
    public boolean accept(HttpRequest req, HttpResponse resp) {
        if (req == null || resp == null) return false;

        String method = req.method() == null ? "" : req.method().toUpperCase(Locale.ROOT);
        // never replayed: OPTIONS/HEAD (no useful body) and CONNECT/TRACE (not app requests)
        if (ScanConfig.SKIP_METHODS.contains(method)) return false;
        if (!cfg.allMethodsExceptOptions) {
            if (cfg.testGraphQL && isGraphQLRequest(req)) {
                // GraphQL queries are safe reads (allowed even if POST is off); mutations need writes enabled
                if (isMutationBody(req.bodyToString()) && !cfg.allowWriteMethods) return false;
            } else if (!cfg.methods.contains(method)) {
                return false;
            }
        }
        // else (allMethodsExceptOptions): test every other method (incl. PUT/PATCH/DELETE and GraphQL mutations)

        String url = req.url();
        if (cfg.onlyInScope && !api.scope().isInScope(url)) return false;

        try {
            if (ScanConfig.WEB_CHROME_MIME.contains(resp.inferredMimeType().name())) return false;
        } catch (Exception ignore) {}
        String ext = req.fileExtension();
        if (ext != null && !ext.isEmpty() && cfg.skipExtensions.contains(ext.toLowerCase(Locale.ROOT))) return false;

        if (cfg.requireAuthHeader && !hasAnyAuth(req)) return false;

        // API mode: skip only rendered HTML pages (website chrome). Everything else is tested — JSON,
        // files/images (IDOR objects), XML, empty API responses (a 200/204 POST), header-based responses.
        if (cfg.onlyJsonResponses && isHtmlPage(resp)) return false;

        if (excludeBlocks(cfg.excludeRegex, url)) return false;
        if (!includeAllows(cfg.includeRegex, url)) return false;

        return true;
    }

    // ---------------- auth / content helpers ----------------

    private static final List<String> AUTH_HEADERS = Arrays.asList(
        "Authorization", "Cookie", "X-Api-Key", "Api-Key", "X-Auth-Token", "X-Access-Token",
        "X-Session-Token", "X-Session-Id");

    private static boolean hasAnyAuth(HttpRequest req) {
        for (String h : AUTH_HEADERS) if (req.hasHeader(h)) return true;
        return false;
    }

    /** A rendered HTML page (website chrome), by Content-Type or inferred MIME. */
    static boolean isHtmlPage(HttpResponse resp) {
        String ct = resp.headerValue("Content-Type");
        if (ct != null) {
            String c = ct.toLowerCase(Locale.ROOT);
            if (c.contains("text/html") || c.contains("xhtml")) return true;
        }
        try { if ("HTML".equals(resp.inferredMimeType().name())) return true; } catch (Exception ignore) {}
        return false;
    }

    /** Exclude filter: block only when the pattern is valid AND matches (invalid/blank => don't block). */
    private static boolean excludeBlocks(String regex, String url) {
        if (regex == null || regex.isBlank()) return false;
        try { return Pattern.compile(regex).matcher(url).find(); }
        catch (Exception e) { return false; }
    }

    /** Include filter: allow when blank, matches, OR the pattern is invalid (fail open — never silently kill the scan). */
    private static boolean includeAllows(String regex, String url) {
        if (regex == null || regex.isBlank()) return true;
        try { return Pattern.compile(regex).matcher(url).find(); }
        catch (Exception e) { return true; }
    }

    // ---------------- GraphQL detection (pure helpers, unit-tested) ----------------

    static boolean isGraphQLRequest(HttpRequest req) {
        String path = req.pathWithoutQuery();
        if (path != null) {
            String pl = path.toLowerCase(Locale.ROOT);
            if (pl.contains("graphql") || pl.endsWith("/gql")) return true;
        }
        String ct = req.headerValue("Content-Type");
        if (ct != null && ct.toLowerCase(Locale.ROOT).contains("graphql")) return true;
        if ("POST".equalsIgnoreCase(req.method())) return isGraphQLBody(req.bodyToString());
        return false;
    }

    /** A GraphQL operation body: JSON with a "query" field, or raw query/mutation/fragment text. */
    public static boolean isGraphQLBody(String body) {
        if (body == null) return false;
        String b = body.trim();
        if (b.isEmpty()) return false;
        if (b.charAt(0) == '[' || b.charAt(0) == '{') return b.contains("\"query\"");
        return b.startsWith("query") || b.startsWith("mutation")
                || b.startsWith("fragment") || b.startsWith("subscription");
    }

    private static final Pattern MUTATION =
            Pattern.compile("(?is)(\"query\"\\s*:\\s*\"\\s*mutation\\b)|(^\\s*mutation\\b)");

    /** True if the GraphQL body's operation is a mutation (state-changing). */
    public static boolean isMutationBody(String body) {
        if (body == null) return false;
        return MUTATION.matcher(body).find();
    }

    // ---------------- value-aware de-duplication ----------------

    // query params that change per-request without changing the resource (never key on these)
    private static final Set<String> VOLATILE_PARAM = new HashSet<>(Arrays.asList(
        "_", "cb", "_cb", "cachebuster", "cache_bust", "nocache", "_t",
        "csrf", "xsrf", "_csrf", "csrf_token", "xsrf_token", "csrftoken", "_token",
        "authenticity_token", "__requestverificationtoken", "nonce", "_nonce"));

    private static final Pattern DEDUP_STRIP = Pattern.compile(
        "(?i)(csrf|xsrf|authenticity_token|__requestverificationtoken|_token|nonce)[\"'=:\\s]+[\\w\\-+/=]{6,}");
    private static final Pattern DEDUP_TIME = Pattern.compile(
        "\\d{4}-\\d{2}-\\d{2}[t ]\\d{2}:\\d{2}:\\d{2}\\S*", Pattern.CASE_INSENSITIVE);

    /** Strip volatile tokens/timestamps but KEEP ids/uuids so different objects stay distinct. */
    public static String dedupBodyNorm(String b) {
        if (b == null) return "";
        b = DEDUP_STRIP.matcher(b).replaceAll("");
        b = DEDUP_TIME.matcher(b).replaceAll("");
        return b;
    }

    /**
     * Key = method + host + path + (sorted non-cookie, non-volatile params with VALUES) + body signature.
     * So different query/param VALUES and different GraphQL queries are each tested, while identical
     * requests (and volatile-only differences) are de-duplicated.
     */
    public String dedupeKey(HttpRequest req) {
        StringBuilder sb = new StringBuilder(req.method()).append(' ')
                .append(req.httpService() != null ? req.httpService().host() : "")
                .append(req.pathWithoutQuery());
        List<String> parts = new ArrayList<>();
        try {
            for (ParsedHttpParameter p : req.parameters()) {
                if (p.type() == HttpParameterType.COOKIE) continue;
                if (VOLATILE_PARAM.contains(p.name().toLowerCase(Locale.ROOT))) continue;
                parts.add(p.type().name() + ":" + p.name() + "=" + p.value());
            }
        } catch (Exception ignore) {}
        Collections.sort(parts);
        sb.append('|').append(String.join("&", parts));
        String body = req.bodyToString();
        if (body != null && !body.isEmpty()) sb.append('#').append(dedupBodyNorm(body).hashCode());
        return sb.toString();
    }
}
