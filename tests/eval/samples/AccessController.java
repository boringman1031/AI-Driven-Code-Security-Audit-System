// CWE-862: Missing Authorization Java（含漏洞）
import javax.servlet.http.*;

public class AccessController extends HttpServlet {
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String userId = req.getParameter("userId");
        // 無任何授權檢查，任何人都可刪除任意使用者
        userService.deleteUser(userId);
        resp.setStatus(200);
    }
}
