package authzmatrix;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Small helpers for decoding JWTs (identity tokens) and detecting expiry. */
public final class JwtUtil {

    private static final Pattern JWT = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");
    private static final Pattern EXP = Pattern.compile("\"exp\"\\s*:\\s*(\\d+)");
    private static final Pattern NBF = Pattern.compile("\"nbf\"\\s*:\\s*(\\d+)");

    private JwtUtil() {}

    public static String stripBearer(String s) {
        if (s == null) return "";
        s = s.trim();
        if (s.regionMatches(true, 0, "Bearer ", 0, 7)) s = s.substring(7).trim();
        return s;
    }

    public static boolean looksLikeJwt(String s) {
        s = stripBearer(s);
        return !s.isEmpty() && JWT.matcher(s).matches();
    }

    public static String decodePretty(String token) {
        token = stripBearer(token);
        String[] parts = token.split("\\.");
        if (parts.length < 2) return "Not a JWT (need header.payload.signature).";
        StringBuilder sb = new StringBuilder();
        sb.append("=== HEADER ===\n").append(decodePart(parts[0])).append("\n\n");
        sb.append("=== PAYLOAD ===\n").append(decodePart(parts[1])).append('\n');
        Long exp = claimEpoch(token, EXP);
        Long nbf = claimEpoch(token, NBF);
        long now = System.currentTimeMillis() / 1000;
        if (nbf != null && nbf > now) sb.append("\nnbf=").append(nbf).append("  *** NOT YET VALID ***");
        if (exp != null) {
            sb.append("\nexp=").append(exp);
            sb.append(now > exp ? "  *** EXPIRED ***" : "  (valid, " + (exp - now) + "s left)");
        } else {
            sb.append("\n(no exp claim — opaque or non-expiring token)");
        }
        return sb.toString();
    }

    /** exp epoch-seconds, normalising ms->s; null if none/opaque. */
    public static Long claimEpoch(String token, Pattern claim) {
        try {
            token = stripBearer(token);
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;
            String payload = new String(Base64.getUrlDecoder().decode(pad(parts[1])));
            Matcher m = claim.matcher(payload);
            if (m.find()) {
                long v = Long.parseLong(m.group(1));
                if (v > 1_000_000_000_000L) v /= 1000; // ms -> s
                return v;
            }
        } catch (Exception ignore) {}
        return null;
    }

    public static boolean isExpired(String token) {
        Long exp = claimEpoch(token, EXP);
        return exp != null && System.currentTimeMillis() / 1000 > exp;
    }

    private static String decodePart(String p) {
        try { return new String(Base64.getUrlDecoder().decode(pad(p))); }
        catch (Exception e) { return "<decode error>"; }
    }

    private static String pad(String s) {
        switch (s.length() % 4) {
            case 2:  return s + "==";
            case 3:  return s + "=";
            case 1:  return s + "===";
            default: return s;
        }
    }
}
