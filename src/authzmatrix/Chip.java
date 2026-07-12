package authzmatrix;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/** A small rounded, colour-filled pill used for the clickable count/filter badges. */
public class Chip extends JLabel {

    private Color color;
    private boolean active;

    public Chip(String text, Color color) {
        super(text);
        this.color = color;
        setForeground(Color.WHITE);
        setOpaque(false);
        setHorizontalAlignment(CENTER);
        setFont(getFont().deriveFont(Font.BOLD));
        setBorder(BorderFactory.createEmptyBorder(3, 12, 3, 12));
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
    }

    public void setColor(Color c) { this.color = c; repaint(); }
    public void setActive(boolean a) { if (active != a) { active = a; repaint(); } }
    public boolean isActive() { return active; }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int r = getHeight();
        g2.setColor(active ? color.brighter() : color);
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), r, r);
        if (active) {
            g2.setStroke(new BasicStroke(2f));
            g2.setColor(new Color(255, 255, 255, 235));
            g2.drawRoundRect(1, 1, getWidth() - 3, getHeight() - 3, r - 2, r - 2);
        }
        g2.dispose();
        super.paintComponent(g);
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension d = super.getPreferredSize();
        d.height = Math.max(d.height, 22);
        return d;
    }
}
