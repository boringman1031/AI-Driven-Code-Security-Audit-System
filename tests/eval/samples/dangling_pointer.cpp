// CWE-416: Dangling Pointer C++（含漏洞）
#include <iostream>
#include <string>

class Resource {
public:
    std::string* data;
    Resource() { data = new std::string("hello"); }
    ~Resource() { delete data; }
};

void dangerous() {
    Resource r;
    std::string* ptr = r.data;  // 取得指標
    // r 在此結束生命週期，data 被 delete
    // ptr 成為懸掛指標
    std::cout << *ptr << std::endl;  // 存取已釋放的記憶體
}
