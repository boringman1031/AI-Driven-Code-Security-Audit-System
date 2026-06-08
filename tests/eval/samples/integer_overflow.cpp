// CWE-190: Integer Overflow C++（含漏洞）
#include <cstdlib>
#include <cstring>
#include <stdint.h>

void* safe_alloc(uint32_t width, uint32_t height) {
    // 整數乘法可能溢位，導致分配過小的緩衝區
    uint32_t size = width * height * 4;
    return malloc(size);
}
