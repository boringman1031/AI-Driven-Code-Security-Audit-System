// CWE-611: XXE Java（含漏洞）
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XmlParser {
    public void parse(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 未禁用 XXE，攻擊者可讀取任意系統檔案
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
