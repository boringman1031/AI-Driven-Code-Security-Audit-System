// CWE-502: Unsafe Deserialization Java（含漏洞）
import java.io.*;

public class DeserializeEndpoint {
    public Object deserialize(byte[] data) throws Exception {
        // 直接對使用者輸入進行反序列化，可執行任意程式碼
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
