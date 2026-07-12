package authzmatrix;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * One row of the matrix: the captured privileged request/response (state A) plus the
 * per-identity results (state B for each identity) and the unauthenticated baseline (state C).
 * The base body is normalised once up front for fast, repeated comparison.
 */
public class MatrixEntry {

    public final int index;
    public final HttpRequest baseRequest;
    public final HttpResponse baseResponse;
    public HttpRequestResponse baseReqResp;

    public final long time;
    public final String timeText;
    public final String method;
    public final String host;
    public final String url;

    public final int baseStatus;
    public final int baseLenRaw;
    public final String baseBodyRaw;

    // pre-normalised views for comparison
    public final String baseNorm;
    public final int baseLenNorm;
    public final Set<String> baseKeys;

    public volatile TestResult unauthResult;                       // state C (baseline)
    public final Map<String, TestResult> results = new LinkedHashMap<>(); // identityId -> result

    public MatrixEntry(int index, HttpRequest req, HttpResponse resp) {
        this.index = index;
        this.baseRequest = req;
        this.baseResponse = resp;
        this.time = System.currentTimeMillis();
        this.timeText = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date(this.time));
        this.method = req.method();
        this.host = req.httpService() != null ? req.httpService().host() : "";
        this.url = req.url();
        this.baseStatus = resp != null ? resp.statusCode() : -1;
        this.baseBodyRaw = resp != null ? resp.bodyToString() : "";
        this.baseLenRaw = baseBodyRaw.length();
        this.baseNorm = EnforcementDetector.normalize(baseBodyRaw);
        this.baseLenNorm = baseNorm.length();
        this.baseKeys = EnforcementDetector.jsonKeys(baseBodyRaw);
    }

    public synchronized TestResult result(String identityId) { return results.get(identityId); }
    public synchronized void putResult(String identityId, TestResult r) { results.put(identityId, r); }
}
