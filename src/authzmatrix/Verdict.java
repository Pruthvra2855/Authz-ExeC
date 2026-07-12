package authzmatrix;

import java.awt.Color;

/**
 * Classification of a single (request x identity) access-control test.
 * Colours are chosen to be legible on both Burp's light and dark themes (white text).
 */
public enum Verdict {
    PENDING      ("",          new Color(120, 120, 120)),
    BYPASSED     ("BYPASSED",  new Color(202,  52,  52)),   // red   - identity got access it should not have
    ENFORCED     ("ENFORCED",  new Color( 40, 150,  70)),   // green - properly denied / rescoped
    AMBIGUOUS    ("REVIEW",    new Color(226, 146,  24)),   // orange- manual review needed
    PUBLIC_NOAUTH("NO-AUTH",   new Color( 58, 110, 206)),   // blue  - endpoint requires no auth at all
    INFRA_BLOCK  ("WAF/RL",    new Color(150,  90, 190)),   // purple- WAF / rate-limit, not app authz
    EXPIRED      ("EXPIRED",   new Color(120,  80, 160)),   // identity session looks dead
    ERROR        ("ERROR",     new Color(110, 110, 110)),   // request failed / no response
    SKIPPED      ("-",         new Color( 90,  90,  90));   // identity disabled / not applicable

    public final String label;
    public final Color color;

    Verdict(String label, Color color) {
        this.label = label;
        this.color = color;
    }

    /** True for verdicts that represent an actual or possible access-control weakness. */
    public boolean isFinding() {
        return this == BYPASSED || this == PUBLIC_NOAUTH;
    }
}
