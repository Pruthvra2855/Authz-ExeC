package authzmatrix;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Columns = [#, Method, Host, Path, A(base), C(unauth)] + one per identity.
 * Cell values for verdict columns are TestResult objects (rendered by VerdictCellRenderer).
 */
public class MatrixTableModel extends AbstractTableModel {

    static final int FIXED = 6;
    private final List<MatrixEntry> rows = new ArrayList<>();
    private List<Identity> identities = new ArrayList<>();

    public void setIdentities(List<Identity> ids) {
        this.identities = new ArrayList<>(ids);
        fireTableStructureChanged();
    }

    public List<Identity> identities() { return identities; }

    public void addEntry(MatrixEntry e) {
        rows.add(e);
        int r = rows.size() - 1;
        fireTableRowsInserted(r, r);
    }

    public void clearRows() {
        int n = rows.size();
        rows.clear();
        if (n > 0) fireTableRowsDeleted(0, n - 1);
    }

    public MatrixEntry entryAt(int row) { return row >= 0 && row < rows.size() ? rows.get(row) : null; }
    public int rowIndexOf(MatrixEntry e) { return rows.indexOf(e); }
    public List<MatrixEntry> rows() { return rows; }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return FIXED + identities.size(); }

    @Override
    public String getColumnName(int col) {
        switch (col) {
            case 0: return "#";
            case 1: return "Time";
            case 2: return "Method";
            case 3: return "Host";
            case 4: return "Path";
            case 5: return "A (base)";
            default:
                Identity id = identities.get(col - FIXED);
                String t = id.tenant == null || id.tenant.isBlank() ? "" : " [" + id.tenant + "]";
                return id.name + t;
        }
    }

    @Override
    public Object getValueAt(int row, int col) {
        MatrixEntry e = rows.get(row);
        switch (col) {
            case 0: return e.index;
            case 1: return e.timeText;
            case 2: return e.method;
            case 3: return e.host;
            case 4: return safePath(e);
            case 5: return e.baseStatus + " (" + e.baseLenRaw + ")";
            default:
                Identity id = identities.get(col - FIXED);
                return e.result(id.id);       // TestResult or null
        }
    }

    private static String safePath(MatrixEntry e) {
        try { return e.baseRequest.path(); } catch (Exception ex) { return e.url; }
    }

    @Override public boolean isCellEditable(int r, int c) { return false; }
}
