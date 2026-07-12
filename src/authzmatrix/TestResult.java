package authzmatrix;

import burp.api.montoya.http.message.HttpRequestResponse;

/** Result of replaying one base request as one identity (a single matrix cell). */
public class TestResult {
    public Verdict verdict = Verdict.PENDING;
    public int statusCode = -1;
    public int length = -1;
    public int confidence = -1;          // 0..100 for BYPASSED verdicts
    public String note = "";             // e.g. "leaked marker: acme-guid" / "conf=90"
    public HttpRequestResponse reqResp;  // for the request/response viewer

    public String cellText() {
        if (verdict == Verdict.PENDING) return "";
        if (verdict == Verdict.SKIPPED) return "-";
        StringBuilder sb = new StringBuilder(verdict.label);
        if (statusCode >= 0) sb.append(' ').append(statusCode);
        if (length >= 0) sb.append(" (").append(length).append(')');
        if (verdict == Verdict.BYPASSED && confidence >= 0) sb.append(" c").append(confidence);
        return sb.toString();
    }
}
