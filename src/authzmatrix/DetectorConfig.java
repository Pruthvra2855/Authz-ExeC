package authzmatrix;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Tunable settings for the enforcement detector (the response-comparison engine).
 * Defaults are derived from Autorize/AuthMatrix-style heuristics hardened against the
 * common false-positive traps (public endpoints, soft errors, WAF blocks, volatile bodies).
 */
public class DetectorConfig {

    // ---- numeric thresholds ----
    public int lengthTolerancePct = 5;    // normalized body length "close" if within this %
    public int lengthToleranceFloor = 48; // ...or this many absolute bytes, whichever is larger
    public int simSame = 90;              // similarity >= this % => "same content"
    public int simDiff = 60;              // similarity <  this % => "clearly different"
    public int jsonKeysetSame = 80;       // JSON key-set Jaccard >= this % => same schema/shape
    public int confidenceReport = 70;     // a BYPASSED below this confidence is downgraded to REVIEW
    public int denialFpMaxLen = 2048;     // a denial word in a 2xx only counts if body < this (or JSON error)

    // ---- behaviour ----
    public boolean sendUnauthBaseline = true;    // the 3rd state (C) - essential to kill public-endpoint FPs
    public boolean onlyTestSuccessfulBase = true;// skip endpoints the privileged user itself could not access
    public boolean doubleSendVolatile = false;   // send each identity twice; disagreement => VOLATILE/REVIEW

    // ---- status codes that mean "denied" ----
    public Set<Integer> enforcedStatusCodes =
            new LinkedHashSet<>(Arrays.asList(401, 403, 405, 407, 419));

    // ---- body substrings that indicate an auth/authz denial (lowercase match) ----
    public List<String> fingerprints = new ArrayList<>(Arrays.asList(
        "access denied", "access is denied", "permission denied", "you do not have permission",
        "you don't have permission", "you are not authorized", "you are not allowed", "not authorized",
        "unauthorized", "authorization required", "authorization has been denied", "authentication required",
        "authentication failed", "authentication credentials were not provided", "login required",
        "please log in", "please login", "please sign in", "sign in to continue", "you must be logged in",
        "you need to sign in", "you need to be logged in", "session expired", "your session has expired",
        "invalid session", "insufficient privileges", "insufficient permissions", "insufficient scope",
        "not permitted", "operation not permitted", "this action is unauthorized", "403 forbidden",
        "401 unauthorized", "forbidden", "full authentication is required", "requires authentication",
        "missing authentication token", "the security token included in the request is invalid",
        "\"error\":\"unauthorized\"", "\"error\":\"access_denied\"", "\"error\":\"forbidden\"",
        "\"error\":\"invalid_token\"", "\"error\":\"insufficient_scope\"", "\"message\":\"unauthorized\"",
        "\"message\":\"forbidden\"", "\"message\":\"access denied\"", "\"message\":\"permission denied\"",
        "not_authenticated", "not_authorized", "permission_denied", "accessdenied", "accessdeniedexception",
        "notauthorizedexception", "unauthorizedexception", "forbiddenexception",
        "user is not authorized to perform", "not authorized to access", "you don't have access",
        "no permission", "missing_scope", "token_expired", "invalid or expired token", "does not belong"));

    // ---- Location header markers that indicate a login redirect (=> enforced) ----
    public List<String> redirectLoginMarkers = new ArrayList<>(Arrays.asList(
        "/login", "/signin", "/sign-in", "/sign_in", "/account/login", "/accounts/login",
        "/users/sign_in", "/session/new", "/auth/", "/oauth", "/authorize", "/sso", "/saml", "/idp/",
        "/openid", "returnurl=", "return_url=", "redirect_uri=", "next=", "samlrequest=", "id_token"));

    // ---- 2xx-but-empty markers => row/object-level filtering => enforced ----
    public List<String> emptyResultMarkers = new ArrayList<>(Arrays.asList(
        "\"data\":null", "\"data\":[]", "\"data\":{}", "\"result\":null", "\"results\":[]", "\"items\":[]",
        "\"records\":[]", "\"rows\":[]", "\"content\":[]", "\"list\":[]", "\"edges\":[]", "\"nodes\":[]",
        "\"total\":0", "\"totalcount\":0", "\"count\":0", "\"totalelements\":0"));

    // ---- WAF / rate-limit fingerprints => INFRA_BLOCK, never treated as app enforcement ----
    public List<String> wafFingerprints = new ArrayList<>(Arrays.asList(
        "attention required", "cloudflare", "cf-ray", "error 1020", "please enable cookies and reload",
        "akamaighost", "incapsula incident id", "_incapsula_resource", "powered by incapsula",
        "the requested url was rejected", "your support id is", "support id:", "sucuri website firewall",
        "access denied - sucuri", "mod_security", "this error was generated by mod_security",
        "request blocked", "too many requests", "rate limit", "aws waf"));

    // ---- headers stripped to build the fully-unauthenticated baseline (state C) ----
    public List<String> baselineStripHeaders = new ArrayList<>(Arrays.asList(
        "Cookie", "Authorization", "X-Api-Key", "Api-Key", "X-Auth-Token", "X-Access-Token",
        "X-Session-Token", "X-Session-Id", "X-Csrf-Token", "X-Xsrf-Token", "X-Amz-Security-Token"));
}
