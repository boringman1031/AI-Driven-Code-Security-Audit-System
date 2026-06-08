// CWE-22: Path Traversal Java（含漏洞）
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        // 未驗證路徑，存在路徑穿越風險
        File file = new File("/app/files/" + filename);
        byte[] data = new FileInputStream(file).readAllBytes();
        resp.getOutputStream().write(data);
    }
}
