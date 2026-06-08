/* CWE-125: Out-of-bounds Read C（含漏洞） */
#include <stdio.h>

int get_element(int *arr, int size, int index) {
    /* 未檢查 index 範圍，可能越界讀取 */
    return arr[index];
}

int main() {
    int data[10] = {0};
    /* 傳入超出範圍的 index */
    printf("%d\n", get_element(data, 10, 100));
    return 0;
}
