import authzmatrix.AppState;
import authzmatrix.Identity;
import authzmatrix.PresetIO;

import java.io.File;

/** Verifies preset save/load round-trips identities + config, incl. multi-line values. */
public class PresetRoundTripTest {
    static int pass = 0, fail = 0;
    static void check(String n, boolean c) { if (c) { pass++; System.out.println("  PASS " + n); } else { fail++; System.out.println("  FAIL " + n); } }

    public static void main(String[] args) throws Exception {
        AppState a = new AppState();
        a.identities.clear();
        Identity admin = new Identity("Admin");
        admin.tenant = "Tenant A";
        admin.cookie = "session=abc123;\nextra=deadbeef";                 // multi-line
        admin.authorization = "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig";
        admin.setHeaders = "X-Tenant-Id: A-guid\nX-Api-Key: k-123";       // multi-line
        admin.markers = "acme-corp-guid\nprivate@a.com";
        admin.enabled = true;
        a.identities.add(admin);
        Identity low = new Identity("Low");
        low.unauth = true;
        low.enabled = false;
        a.identities.add(low);

        a.scan.onlyJsonResponses = false;
        a.scan.threads = 7;
        a.scan.minIntervalMs = 500;
        a.scan.methods.add("POST");
        a.scan.skipExtensions.add("pdf");   // should be stripped on load (files are IDOR candidates)
        a.detector.confidenceReport = 55;
        a.detector.simSame = 88;

        File f = File.createTempFile("authz-preset", ".properties");
        f.deleteOnExit();
        PresetIO.save(f, a);

        AppState b = new AppState();
        b.identities.clear();
        PresetIO.load(f, b);

        check("identity count", b.identities.size() == 2);
        Identity ba = b.identities.get(0);
        check("name", ba.name.equals("Admin"));
        check("tenant", ba.tenant.equals("Tenant A"));
        check("multi-line cookie survives", ba.cookie.equals("session=abc123;\nextra=deadbeef"));
        check("authorization survives", ba.authorization.equals("Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"));
        check("multi-line headers survive", ba.setHeaders.equals("X-Tenant-Id: A-guid\nX-Api-Key: k-123"));
        check("multi-line markers survive", ba.markers.equals("acme-corp-guid\nprivate@a.com"));
        check("second identity unauth+disabled", b.identities.get(1).unauth && !b.identities.get(1).enabled);

        check("scan.onlyJsonResponses", !b.scan.onlyJsonResponses);
        check("scan.threads", b.scan.threads == 7);
        check("scan.minIntervalMs", b.scan.minIntervalMs == 500);
        check("scan.methods has POST", b.scan.methods.contains("POST"));
        check("pdf stripped from skipExtensions", !b.scan.skipExtensions.contains("pdf"));
        check("detector.confidenceReport", b.detector.confidenceReport == 55);
        check("detector.simSame", b.detector.simSame == 88);

        System.out.println("RESULT: " + pass + " passed, " + fail + " failed");
        if (fail > 0) System.exit(1);
    }
}
