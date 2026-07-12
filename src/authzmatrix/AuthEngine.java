package authzmatrix;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Observes candidate traffic and, on its own bounded thread pool, replays each request as the
 * unauthenticated baseline (C) and as every enabled identity (B), classifying each against the
 * captured privileged response (A). Never does network work on Burp's proxy thread.
 */
public class AuthEngine {

    public interface Listener {
        void onEntryAdded(MatrixEntry e);
        void onEntryUpdated(MatrixEntry e);
    }

    private final MontoyaApi api;
    private final AppState state;

    private final List<MatrixEntry> entries = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger counter = new AtomicInteger(0);

    private volatile ThreadPoolExecutor pool;
    private volatile Listener listener;

    // global rate gate
    private final Object rateLock = new Object();
    private long nextAllowed = 0;

    public AuthEngine(MontoyaApi api, AppState state) {
        this.api = api;
        this.state = state;
        rebuildPool();
    }

    public void setListener(Listener l) { this.listener = l; }
    public List<MatrixEntry> entries() { return entries; }

    public synchronized void rebuildPool() {
        int n = Math.max(1, state.scan.threads);
        ThreadPoolExecutor old = pool;
        pool = new ThreadPoolExecutor(
                n, n, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(2000),
                r -> { Thread t = new Thread(r, "authz-matrix-worker"); t.setDaemon(true); return t; },
                new ThreadPoolExecutor.DiscardPolicy());
        pool.allowCoreThreadTimeOut(true);
        if (old != null) old.shutdownNow();
    }

    public void shutdown() {
        ThreadPoolExecutor p = pool;
        if (p != null) p.shutdownNow();
    }

    /** Wipe the matrix AND the tested-endpoint memory so everything can be scanned fresh. */
    public void clear() {
        state.testedKeys.clear();
        synchronized (entries) { entries.clear(); }
        state.save();
    }

    /** Re-run all replays for one already-captured entry (used by the Retest button). */
    public void retest(MatrixEntry e) {
        if (e == null) return;
        synchronized (e) { e.results.clear(); }
        e.unauthResult = null;
        if (listener != null) listener.onEntryUpdated(e);
        try { pool.submit(() -> runEntry(e)); }
        catch (Exception ignore) {}
    }

    // ---------------- capture (runs on Burp proxy/repeater thread — must be fast) ----------------

    public void consider(HttpResponseReceived resp) {
        if (!state.scan.liveEnabled) return;
        if (!new RequestClassifier(api, state.scan).accept(resp)) return;

        HttpRequest baseReq = resp.initiatingRequest();
        if (matchesConfiguredIdentity(baseReq)) return; // this is one of your identities browsing — skip

        HttpResponse baseCopy;
        try { baseCopy = HttpResponse.httpResponse(resp.toByteArray()); }
        catch (Exception ex) { return; }

        if (state.detector.onlyTestSuccessfulBase) {
            int sc = resp.statusCode();
            EnforcementDetector det = new EnforcementDetector(state.detector);
            if (sc >= 400 || det.isDenied(det.view(baseCopy))) return;
        }
        if (entries.size() >= state.scan.maxRows) return;
        // never re-test an endpoint already queued/tested (persists across reloads; reset with Clear)
        String key = new RequestClassifier(api, state.scan).dedupeKey(baseReq);
        if (!state.testedKeys.add(key)) return;
        enqueue(baseReq, baseCopy);
    }

    /**
     * Pull everything already in Burp's proxy history, filter to in-scope testable requests,
     * and queue them for replay. Runs off-EDT (caller wraps in a thread). Returns count queued.
     */
    public int[] importProxyHistory() {
        int added = 0, skipped = 0;
        RequestClassifier rc = new RequestClassifier(api, state.scan);
        EnforcementDetector det = new EnforcementDetector(state.detector);
        List<ProxyHttpRequestResponse> history;
        try { history = api.proxy().history(); }
        catch (Exception e) { api.logging().logToError("proxy history read failed: " + e); return new int[]{-1, 0}; }

        for (ProxyHttpRequestResponse h : history) {
            if (entries.size() >= state.scan.maxRows) break;
            if (!h.hasResponse()) continue;
            HttpRequest req = h.finalRequest();
            HttpResponse resp = h.response();
            if (req == null || resp == null) continue;
            if (!rc.accept(req, resp)) continue;
            if (matchesConfiguredIdentity(req)) { skipped++; continue; } // an identity's own browsing
            if (state.detector.onlyTestSuccessfulBase
                    && (resp.statusCode() >= 400 || det.isDenied(det.view(resp)))) continue;
            // skip anything already queued/tested (this session or a previous one)
            if (!state.testedKeys.add(rc.dedupeKey(req))) { skipped++; continue; }
            enqueue(req, resp);
            added++;
        }
        if (added > 0) state.save(); // persist the newly-tested keys
        return new int[]{added, skipped};
    }

    /** Manually push a request/response (from the context menu) — runs off-EDT by the caller. */
    public void manualAdd(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) return;
        HttpRequest req = rr.request();
        // honour the documented invariants even for context-menu adds: never-replay methods + scope
        String method = req.method() == null ? "" : req.method().toUpperCase(Locale.ROOT);
        if (ScanConfig.SKIP_METHODS.contains(method)) {
            api.logging().logToOutput("Authz-ExeC: skipped " + method + " (never replayed): " + req.url());
            return;
        }
        if (state.scan.onlyInScope && !req.isInScope()) {
            api.logging().logToOutput("Authz-ExeC: skipped out-of-scope request: " + req.url());
            return;
        }
        // don't add a duplicate row for an endpoint already tested (use Retest to re-run it)
        String key = new RequestClassifier(api, state.scan).dedupeKey(req);
        if (!state.testedKeys.add(key)) {
            api.logging().logToOutput("Authz-ExeC: already tested, skipped (use Retest): " + req.url());
            return;
        }
        HttpResponse resp;
        if (rr.hasResponse()) resp = rr.response();
        else {
            HttpRequestResponse sent = send(req);
            resp = sent != null ? sent.response() : null;
        }
        if (resp == null) return;
        enqueue(req, resp);
    }

    private void enqueue(HttpRequest baseReq, HttpResponse baseResp) {
        MatrixEntry e = new MatrixEntry(counter.incrementAndGet(), baseReq, baseResp);
        e.baseReqResp = HttpRequestResponse.httpRequestResponse(baseReq, baseResp);
        entries.add(e);
        if (listener != null) listener.onEntryAdded(e);
        try { pool.submit(() -> runEntry(e)); }
        catch (Exception ignore) { /* pool shutting down */ }
    }

    // ---------------- replay (runs on worker thread) ----------------

    private void runEntry(MatrixEntry e) {
        try {
            EnforcementDetector det = new EnforcementDetector(state.detector);
            List<Identity> ids = state.identitiesSnapshot();

            if (state.scan.dryRun) {
                e.unauthResult = skipped("dry-run");
                for (Identity id : ids) e.putResult(id.id, skipped("dry-run"));
                notifyUpdated(e);
                return;
            }

            HttpResponse unauthResp = null;
            // defence-in-depth: never send the auth-stripped baseline to an out-of-scope host
            boolean baseInScope = !state.scan.onlyInScope || e.baseRequest.isInScope();
            if (state.detector.sendUnauthBaseline && baseInScope) {
                HttpRequestResponse urr = send(stripAuth(e.baseRequest));
                TestResult tr = new TestResult();
                tr.reqResp = urr;
                if (urr == null || urr.response() == null) {
                    tr.verdict = Verdict.ERROR;
                } else {
                    unauthResp = urr.response();
                    EnforcementDetector.Outcome o = det.classifyUnauth(unauthResp, e);
                    tr.verdict = o.verdict; tr.note = o.note;
                    tr.statusCode = unauthResp.statusCode();
                    tr.length = unauthResp.body().length();
                }
                e.unauthResult = tr;
                notifyUpdated(e);
            }

            for (Identity id : ids) {
                TestResult tr;
                if (!id.enabled) {
                    tr = skipped("disabled");
                } else {
                    HttpRequest mod = id.apply(e.baseRequest);
                    if (state.scan.onlyInScope && !mod.isInScope()) {
                        tr = new TestResult();
                        tr.verdict = Verdict.ERROR;
                        tr.note = "out of scope after rewrite";
                    } else {
                        tr = replayIdentity(det, e, id, mod, unauthResp, ids);
                    }
                }
                e.putResult(id.id, tr);
                notifyUpdated(e);
            }
        } catch (Throwable t) {
            api.logging().logToError("Authz-ExeC runEntry error: " + t);
        }
    }

    private TestResult replayIdentity(EnforcementDetector det, MatrixEntry e, Identity id,
                                      HttpRequest mod, HttpResponse unauthResp, List<Identity> ids) {
        HttpRequestResponse rr = send(mod);
        TestResult tr = new TestResult();
        tr.reqResp = rr;
        if (rr == null || rr.response() == null) {
            tr.verdict = Verdict.ERROR;
            return tr;
        }
        // optional volatility check: send twice — but NEVER double-send a state-changing request
        if (state.detector.doubleSendVolatile && !isStateChanging(mod)) {
            HttpRequestResponse rr2 = send(mod);
            if (rr2 != null && rr2.response() != null
                    && !det.same(det.view(rr.response()), det.view(rr2.response()))) {
                tr.verdict = Verdict.AMBIGUOUS;
                tr.note = "volatile endpoint (double-send disagreed)";
                tr.statusCode = rr.response().statusCode();
                tr.length = rr.response().body().length();
                return tr;
            }
        }
        EnforcementDetector.Outcome o = det.classify(rr.response(), e, unauthResp, id, ids);
        tr.verdict = o.verdict;
        tr.confidence = o.confidence;
        tr.note = o.note;
        tr.statusCode = rr.response().statusCode();
        tr.length = rr.response().body().length();
        return tr;
    }

    private HttpRequest stripAuth(HttpRequest base) {
        HttpRequest r = base;
        for (String h : state.detector.baselineStripHeaders) if (r.hasHeader(h)) r = r.withRemovedHeader(h);
        return r;
    }

    private HttpRequestResponse send(HttpRequest req) {
        rateGate();
        try { return api.http().sendRequest(req); }
        catch (Throwable t) { api.logging().logToError("Authz-ExeC send failed: " + t.getMessage()); return null; }
    }

    private void rateGate() {
        int interval = state.scan.minIntervalMs;
        if (interval <= 0) return;
        long wait;
        synchronized (rateLock) {
            long now = System.currentTimeMillis();
            long start = Math.max(now, nextAllowed);
            wait = start - now;
            nextAllowed = start + interval;
        }
        if (wait > 0) {
            try { Thread.sleep(wait); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
        }
    }

    /** Fire a request as one identity and return the raw response (used by the "Check sessions" button). */
    public HttpResponse probe(Identity id, HttpRequest base) {
        HttpRequestResponse rr = send(id.apply(base));
        return rr != null ? rr.response() : null;
    }

    private void notifyUpdated(MatrixEntry e) {
        if (listener != null) listener.onEntryUpdated(e);
    }

    private static TestResult skipped(String note) {
        TestResult tr = new TestResult();
        tr.verdict = Verdict.SKIPPED;
        tr.note = note;
        return tr;
    }

    /** A state-changing request (PUT/PATCH/DELETE/POST or a GraphQL mutation) — never double-send it. */
    private static boolean isStateChanging(HttpRequest req) {
        String m = req.method() == null ? "" : req.method().toUpperCase(Locale.ROOT);
        if (ScanConfig.UNSAFE.contains(m)) return true;
        return RequestClassifier.isMutationBody(req.bodyToString());
    }

    // ---------------- identity-own-traffic detection ----------------

    /** True if this request was made by one of the configured identities (matches its cookie/token). */
    boolean matchesConfiguredIdentity(HttpRequest req) {
        if (!state.scan.skipIdentityOwnTraffic || req == null) return false;
        String cookie = req.headerValue("Cookie");
        String auth = req.headerValue("Authorization");
        if ((cookie == null || cookie.isBlank()) && (auth == null || auth.isBlank())) return false;
        for (Identity id : state.identitiesSnapshot()) {
            if (id.unauth) continue;
            if (authEquals(auth, id.authorization)) return true;
            if (cookieShares(cookie, id.cookie)) return true;
        }
        return false;
    }

    /** Same bearer/opaque token (ignoring the "Bearer " prefix), long enough to be real. */
    public static boolean authEquals(String reqAuth, String idAuth) {
        if (reqAuth == null || reqAuth.isBlank() || idAuth == null || idAuth.isBlank()) return false;
        String a = JwtUtil.stripBearer(reqAuth), b = JwtUtil.stripBearer(idAuth);
        return a.length() >= 12 && a.equals(b);
    }

    /** True if the two Cookie headers share a name=value pair whose value is long enough to be a session token. */
    public static boolean cookieShares(String reqCookie, String idCookie) {
        if (reqCookie == null || reqCookie.isBlank() || idCookie == null || idCookie.isBlank()) return false;
        Set<String> a = cookiePairs(reqCookie), b = cookiePairs(idCookie);
        for (String pair : b) {
            if (!a.contains(pair)) continue;
            int eq = pair.indexOf('=');
            if (eq >= 0 && pair.length() - eq - 1 >= 16) return true;
        }
        return false;
    }

    private static Set<String> cookiePairs(String header) {
        Set<String> out = new HashSet<>();
        for (String part : header.split(";")) {
            String t = part.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }
}
