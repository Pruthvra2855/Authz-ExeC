package authzmatrix;

import burp.api.montoya.core.ToolType;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Which live traffic gets picked up and how replays are throttled.
 * Defaults: live testing OFF until armed, in-scope only, rate-limited. NOTE: allMethodsExceptOptions
 * defaults ON, so the tool replays ALL methods except OPTIONS/HEAD/CONNECT/TRACE — including
 * PUT/PATCH/DELETE and GraphQL mutations. Untick it (or use Dry run) for read-only testing.
 */
public class ScanConfig {

    public boolean liveEnabled = false;   // master arm switch - nothing is replayed until true
    public boolean dryRun = false;        // if true: log candidates but never send replays

    // tools whose traffic we test (EXTENSIONS is intentionally excluded => our own replays never loop)
    public Set<ToolType> sources = new LinkedHashSet<>(Arrays.asList(ToolType.PROXY, ToolType.REPEATER));

    public boolean onlyInScope = true;        // enforced unconditionally by RequestClassifier as well
    public boolean requireAuthHeader = true;  // only test requests that actually carry auth to swap
    public boolean onlyJsonResponses = true;  // API mode: only test responses with a JSON body
    public boolean skipIdentityOwnTraffic = true; // skip requests made BY a configured identity (its own browsing)
    public String includeRegex = "";          // optional URL allow regex
    public String excludeRegex = "";          // optional URL deny regex

    // methods we auto-replay when allMethodsExceptOptions is OFF. GET+POST by default.
    public Set<String> methods = new LinkedHashSet<>(Arrays.asList("GET", "POST"));
    public boolean allowWriteMethods = false; // true only when PUT/PATCH/DELETE enabled; also gates GraphQL mutations
    public boolean testGraphQL = true;        // auto-test GraphQL POST *queries* even when POST is off (safe reads)
    // when true, test EVERY method except the SKIP_METHODS (OPTIONS/HEAD/CONNECT/TRACE) — overrides the set above.
    // WARNING: replays real PUT/PATCH/DELETE (and GraphQL mutations) as every identity.
    public boolean allMethodsExceptOptions = true;

    // never tested regardless
    public static final Set<String> SKIP_METHODS =
            new HashSet<>(Arrays.asList("OPTIONS", "HEAD", "CONNECT", "TRACE"));

    // website chrome to skip (suffix match on path) — NOT images/pdf/media (those can be IDOR objects)
    public Set<String> skipExtensions = new LinkedHashSet<>(Arrays.asList(
        "js", "mjs", "css", "map", "woff", "woff2", "ttf", "otf", "eot", "ico", "wasm", "svg"));

    // content types that are never an access-control target (matched against inferredMimeType().name())
    public static final Set<String> WEB_CHROME_MIME = new HashSet<>(Arrays.asList(
        "SCRIPT", "CSS", "FONT_WOFF", "FONT_WOFF2", "IMAGE_SVG_XML"));

    // downloadable objects worth testing for IDOR even in JSON/API mode (PDF, images, media, docs, archives)
    public static final Set<String> FILE_EXT = new HashSet<>(Arrays.asList(
        "pdf", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "avif", "mp4", "webm",
        "mp3", "wav", "zip", "gz", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "bin", "dat"));

    // dedup so N identical proxied hits don't each spawn a replay batch
    public boolean dedupe = true; // de-dup is always on; the key is value-aware (see RequestClassifier.dedupeKey)

    // throttling / concurrency
    public int threads = 4;
    public int minIntervalMs = 250;  // global min gap between replays (~4 req/s); 0 = unthrottled
    public int maxRows = 2000;       // stop capturing new endpoints past this
    public static final Set<String> UNSAFE =
            new HashSet<>(Arrays.asList("POST", "PUT", "PATCH", "DELETE"));
}
