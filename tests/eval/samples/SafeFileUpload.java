// 無漏洞：安全的檔案上傳（Java）
import javax.servlet.http.*;
import java.nio.file.*;
import java.util.Set;

public class SafeFileUpload extends HttpServlet {
    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "image/gif");
    private static final long MAX_SIZE = 5 * 1024 * 1024; // 5MB

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Part filePart = req.getPart("file");
        String contentType = filePart.getContentType();

        if (!ALLOWED_TYPES.contains(contentType)) {
            resp.sendError(400, "不支援的檔案類型");
            return;
        }
        if (filePart.getSize() > MAX_SIZE) {
            resp.sendError(400, "檔案大小超過限制");
            return;
        }

        // 使用隨機 UUID 作為檔案名稱，防止路徑穿越
        String safeFilename = java.util.UUID.randomUUID() + ".bin";
        Path dest = Paths.get("/app/uploads").resolve(safeFilename).normalize();
        filePart.write(dest.toString());
        resp.setStatus(200);
    }
}
