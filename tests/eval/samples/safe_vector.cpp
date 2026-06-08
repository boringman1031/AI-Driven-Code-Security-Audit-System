// 無漏洞：使用標準容器的 C++（無手動記憶體管理）
#include <vector>
#include <string>
#include <stdexcept>

std::string get_element(const std::vector<std::string>& vec, size_t index) {
    // 使用 at() 進行邊界檢查，超出範圍會拋出 std::out_of_range
    return vec.at(index);
}
