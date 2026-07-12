import authzmatrix.AuthEngine;
import authzmatrix.EnforcementDetector;
import authzmatrix.Identity;
import authzmatrix.JwtUtil;
import authzmatrix.RequestClassifier;

import java.util.Base64;
import java.util.Set;
import java.util.regex.Pattern;

/** Standalone sanity checks for the pure-logic parts of the detector (no Burp runtime needed). */
public class DetectorSelfTest {
    static int pass = 0, fail = 0;

    static void check(String name, boolean cond) {
        if (cond) { pass++; System.out.println("  PASS  " + name); }
        else       { fail++; System.out.println("  FAIL  " + name); }
    }

    static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes());
    }

    public static void main(String[] args) {
        System.out.println("== normalize ==");
        String raw = "Hello  2024-01-02T03:04:05Z <!--secret--> id=550e8400-e29b-41d4-a716-446655440000 ts=1712345678901 world";
        String n = EnforcementDetector.normalize(raw);
        check("strips iso timestamp", !n.contains("2024-01-02t03"));
        check("strips uuid", !n.contains("550e8400"));
        check("strips epoch", !n.contains("1712345678901"));
        check("strips html comment", !n.contains("secret"));
        check("collapses whitespace", !n.contains("  "));
        check("keeps stable words", n.contains("hello") && n.contains("world"));

        System.out.println("== similarity ==");
        check("identical == 1.0", EnforcementDetector.similarity("the quick brown fox", "the quick brown fox") == 1.0);
        // weighted Jaccard: 7 shared of 9 union tokens = 0.777 (one differing field). Deliberately strict.
        check("near-identical partial", EnforcementDetector.similarity(
                "user profile name email phone address city country",
                "user profile name email phone address city state") >= 0.75);
        // a real bypass: same 20-field body with only the reflected username differing -> ~same
        check("one-token-diff in large body ~same", EnforcementDetector.similarity(
                "id name email role dept phone addr city zip country plan status created active admin owner team org region tier alice",
                "id name email role dept phone addr city zip country plan status created active admin owner team org region tier bob") >= 0.90);
        check("different low", EnforcementDetector.similarity(
                "access denied you are not authorized",
                "here is the full admin dashboard with every user record listed") < 0.30);
        check("empty vs nonempty 0", EnforcementDetector.similarity("", "something here") == 0.0);

        System.out.println("== jsonKeys / jaccard ==");
        Set<String> k1 = EnforcementDetector.jsonKeys("{\"id\":1,\"name\":\"a\",\"nested\":{\"role\":\"admin\"}}");
        check("extracts keys", k1.contains("id") && k1.contains("name") && k1.contains("nested") && k1.contains("role"));
        Set<String> k2 = EnforcementDetector.jsonKeys("{\"id\":2,\"name\":\"b\",\"nested\":{\"role\":\"user\"}}");
        check("same schema jaccard == 1.0", EnforcementDetector.jaccard(k1, k2) == 1.0);
        Set<String> k3 = EnforcementDetector.jsonKeys("{\"error\":\"forbidden\"}");
        check("different schema low jaccard", EnforcementDetector.jaccard(k1, k3) < 0.3);

        System.out.println("== JWT ==");
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String expired = header + "." + b64("{\"sub\":\"42\",\"exp\":1000000000}") + ".sig";
        String valid   = header + "." + b64("{\"sub\":\"42\",\"exp\":9999999999}") + ".sig";
        check("looksLikeJwt", JwtUtil.looksLikeJwt(valid));
        check("looksLikeJwt bearer", JwtUtil.looksLikeJwt("Bearer " + valid));
        check("expired detected", JwtUtil.isExpired(expired));
        check("valid not expired", !JwtUtil.isExpired(valid));
        check("decode shows sub", JwtUtil.decodePretty(valid).contains("\"sub\""));
        check("decode flags EXPIRED", JwtUtil.decodePretty(expired).contains("EXPIRED"));
        // ms-epoch normalisation
        String msExp = header + "." + b64("{\"exp\":9999999999000}") + ".sig";
        check("ms epoch not falsely expired", !JwtUtil.isExpired(msExp));

        System.out.println("== Identity rule parsing ==");
        Identity id = new Identity("t");
        id.markers = "acme-corp-guid-123\nx\nprivate@victim.com";
        check("markers ignore too-short", id.markerList().size() == 2);

        System.out.println("== GraphQL detection ==");
        check("json query is graphql", RequestClassifier.isGraphQLBody("{\"query\":\"query { me { id } }\"}"));
        check("json mutation is graphql", RequestClassifier.isGraphQLBody("{\"query\":\"mutation { del(id:1) }\"}"));
        check("raw query is graphql", RequestClassifier.isGraphQLBody("query Me { me { id } }"));
        check("plain json is NOT graphql", !RequestClassifier.isGraphQLBody("{\"name\":\"bob\",\"id\":5}"));
        check("empty not graphql", !RequestClassifier.isGraphQLBody(""));
        check("mutation detected", RequestClassifier.isMutationBody("{\"query\":\"mutation Del($id:ID!){ delete(id:$id){ ok } }\"}"));
        check("query not a mutation", !RequestClassifier.isMutationBody("{\"query\":\"query { users { id } }\"}"));
        check("raw mutation detected", RequestClassifier.isMutationBody("mutation { logout }"));

        System.out.println("== dedup body normalisation (keeps ids, strips tokens) ==");
        String q1 = "{\"query\":\"query{c(id:\\\"AAA\\\"){n}}\",\"csrf\":\"tok_11111111\"}";
        String q2 = "{\"query\":\"query{c(id:\\\"AAA\\\"){n}}\",\"csrf\":\"tok_99999999\"}"; // same op, diff csrf
        String q3 = "{\"query\":\"query{c(id:\\\"BBB\\\"){n}}\",\"csrf\":\"tok_11111111\"}"; // diff id
        check("same op diff csrf -> same norm", RequestClassifier.dedupBodyNorm(q1).equals(RequestClassifier.dedupBodyNorm(q2)));
        check("diff id -> different norm", !RequestClassifier.dedupBodyNorm(q1).equals(RequestClassifier.dedupBodyNorm(q3)));

        System.out.println("== identity-own-traffic matching ==");
        String idCookie = "ControlPoint.Shared=CfDJ8NTqAbCdEf0123456789wLongSessionValue; foo=bar";
        String reqSame = "AMP_MKTG=x; ControlPoint.Shared=CfDJ8NTqAbCdEf0123456789wLongSessionValue; other=1";
        String reqDiff = "AMP_MKTG=x; ControlPoint.Shared=DIFFERENTvalue999999999999; other=1";
        check("shares long session cookie -> match", AuthEngine.cookieShares(reqSame, idCookie));
        check("different session value -> no match", !AuthEngine.cookieShares(reqDiff, idCookie));
        check("short shared pair not enough", !AuthEngine.cookieShares("a=1; foo=bar", "foo=bar"));
        check("same bearer token -> match", AuthEngine.authEquals("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9.payload.sig"));
        check("different bearer -> no match", !AuthEngine.authEquals("Bearer aaaaaaaaaaaa", "Bearer bbbbbbbbbbbb"));
        check("blank auth -> no match", !AuthEngine.authEquals("", "Bearer x"));

        System.out.println();
        System.out.println("RESULT: " + pass + " passed, " + fail + " failed");
        if (fail > 0) System.exit(1);
    }
}
