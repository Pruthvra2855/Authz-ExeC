package authzmatrix;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Standalone JWT decoder + a couple of quick tamper helpers (for authorized testing). */
public class JwtPanel extends JPanel {

    private final JTextArea input = new JTextArea(4, 60);
    private final JTextArea output = new JTextArea(20, 60);

    public JwtPanel(MontoyaApi api) {
        super(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        input.setLineWrap(true);
        output.setEditable(false);
        output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JPanel top = new JPanel(new BorderLayout(4, 4));
        top.add(new JLabel("Paste a JWT (or 'Bearer <jwt>'):"), BorderLayout.NORTH);
        top.add(new JScrollPane(input), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton decode = new JButton("Decode");
        decode.addActionListener(e -> output.setText(JwtUtil.decodePretty(input.getText())));
        JButton none = new JButton("Forge alg:none");
        none.addActionListener(e -> output.setText(algNone(input.getText())));
        JButton strip = new JButton("Strip signature");
        strip.addActionListener(e -> output.setText(stripSig(input.getText())));
        buttons.add(decode);
        buttons.add(none);
        buttons.add(strip);
        top.add(buttons, BorderLayout.SOUTH);

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(output), BorderLayout.CENTER);
    }

    private static String algNone(String token) {
        String t = JwtUtil.stripBearer(token);
        String[] parts = t.split("\\.");
        if (parts.length < 2) return "Not a JWT.";
        String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        return "alg:none variants (empty signature) — try each:\n\n"
                + header + "." + parts[1] + ".\n\n"
                + header + "." + parts[1] + "\n";
    }

    private static String stripSig(String token) {
        String t = JwtUtil.stripBearer(token);
        String[] parts = t.split("\\.");
        if (parts.length < 2) return "Not a JWT.";
        return "Signature stripped:\n\n" + parts[0] + "." + parts[1] + ".\n";
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
