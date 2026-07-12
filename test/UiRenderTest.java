import authzmatrix.Chip;
import authzmatrix.TestResult;
import authzmatrix.Verdict;
import authzmatrix.VerdictCellRenderer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.image.BufferedImage;

/** Offscreen render check for the custom pill renderer and Chip (no Burp runtime needed). */
public class UiRenderTest {
    public static void main(String[] args) throws Exception {
        int ok = 0, fail = 0;

        // build a table with mixed values: Integer, String, and TestResult verdict cells
        DefaultTableModel m = new DefaultTableModel(new Object[]{"#", "Path", "B"}, 0);
        for (Verdict v : Verdict.values()) {
            TestResult tr = new TestResult();
            tr.verdict = v; tr.statusCode = 200; tr.length = 1234; tr.confidence = 88; tr.note = "n";
            m.addRow(new Object[]{1, "/api/users/1", tr});
        }
        JTable table = new JTable(m);
        table.setRowHeight(26);
        VerdictCellRenderer r = new VerdictCellRenderer();

        BufferedImage img = new BufferedImage(160, 26, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        for (int row = 0; row < m.getRowCount(); row++) {
            for (int col = 0; col < m.getColumnCount(); col++) {
                for (boolean sel : new boolean[]{false, true}) {
                    try {
                        Component c = r.getTableCellRendererComponent(table, m.getValueAt(row, col), sel, false, row, col);
                        c.setSize(160, 26);
                        c.paint(g);
                        ok++;
                    } catch (Throwable t) {
                        fail++;
                        System.out.println("  FAIL render r" + row + " c" + col + " sel=" + sel + ": " + t);
                    }
                }
            }
        }
        // null cell (pending)
        try { r.getTableCellRendererComponent(table, null, false, false, 0, 2).paint(g); ok++; }
        catch (Throwable t) { fail++; System.out.println("  FAIL null cell: " + t); }

        // Chip paint (inactive + active highlight)
        for (boolean active : new boolean[]{false, true}) {
            try {
                Chip chip = new Chip("BYPASSED 3", Verdict.BYPASSED.color);
                chip.setActive(active);
                chip.setSize(chip.getPreferredSize());
                chip.paint(g);
                ok++;
            } catch (Throwable t) { fail++; System.out.println("  FAIL chip active=" + active + ": " + t); }
        }
        g.dispose();

        System.out.println("UI render: " + ok + " painted ok, " + fail + " failed");
        if (fail > 0) System.exit(1);
    }
}
