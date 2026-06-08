// CWE-89: SQL Injection Java（含漏洞）
import java.sql.*;

public class SqlBuilder {
    private Connection conn;

    public ResultSet getUser(String username) throws SQLException {
        // 字串拼接 SQL，未使用 PreparedStatement
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }
}
