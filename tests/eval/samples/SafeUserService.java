// 無漏洞：安全的 User Service（Java）
import java.sql.*;

public class SafeUserService {
    private Connection conn;

    public User getUser(String username) throws SQLException {
        // 使用 PreparedStatement 防止 SQL Injection
        PreparedStatement ps = conn.prepareStatement(
            "SELECT id, username, email FROM users WHERE username = ?");
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();
        if (rs.next()) {
            return new User(rs.getLong("id"), rs.getString("username"), rs.getString("email"));
        }
        return null;
    }
}
