package authzmatrix;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Shape;

/** Paints TestResult cells as rounded colour pills; other cells get subtle row striping. */
public class VerdictCellRenderer extends DefaultTableCellRenderer {

    private boolean pill;
    private Color pillColor;

    public VerdictCellRenderer() { setOpaque(false); }

    @Override
    public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                   boolean focus, int row, int col) {
        pill = v instanceof TestResult;
        if (pill) {
            TestResult tr = (TestResult) v;
            pillColor = tr.verdict.color;
            super.getTableCellRendererComponent(t, tr.cellText(), sel, focus, row, col);
            setHorizontalAlignment(CENTER);
            setForeground(Color.WHITE);
            setToolTipText(tr.note == null || tr.note.isEmpty() ? tr.verdict.label
                    : tr.verdict.label + " - " + tr.note);
        } else {
            super.getTableCellRendererComponent(t, v == null ? "" : v, sel, focus, row, col);
            setHorizontalAlignment(col == 0 ? CENTER : LEFT);
            setForeground(sel ? t.getSelectionForeground() : t.getForeground());
            setToolTipText(v == null ? null : String.valueOf(v));
        }
        setBackground(sel ? t.getSelectionBackground() : rowBg(t, row));
        setOpaque(false);
        return this;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setColor(getBackground());
        g2.fillRect(0, 0, getWidth(), getHeight());
        if (pill) {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int pad = 3, arc = 14, w = getWidth() - 2 * pad, h = getHeight() - 2 * pad;
            g2.setColor(pillColor);
            g2.fillRoundRect(pad, pad, w, h, arc, arc);
            g2.setColor(Color.WHITE);
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            String s = getText();
            int tw = fm.stringWidth(s);
            int x = Math.max(pad + 6, (getWidth() - tw) / 2);
            int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
            Shape clip = g2.getClip();
            g2.setClip(pad, pad, w, h);
            g2.drawString(s, x, y);
            g2.setClip(clip);
            g2.dispose();
            return;
        }
        g2.dispose();
        super.paintComponent(g);
    }

    private static Color rowBg(JTable t, int row) {
        Color b = t.getBackground();
        return row % 2 == 0 ? b : shade(b);
    }

    private static Color shade(Color c) {
        double lum = (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue()) / 255.0;
        int d = lum > 0.5 ? -12 : 14;
        return new Color(clamp(c.getRed() + d), clamp(c.getGreen() + d), clamp(c.getBlue() + d));
    }

    private static int clamp(int v) { return v < 0 ? 0 : Math.min(v, 255); }
}
