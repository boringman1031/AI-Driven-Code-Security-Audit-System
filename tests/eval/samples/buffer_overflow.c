/* CWE-787: Buffer Overflow C（含漏洞） */
#include <string.h>
#include <stdio.h>

void process_input(char *user_input) {
    char buffer[64];
    /* 使用 strcpy 不檢查長度，存在緩衝區溢位 */
    strcpy(buffer, user_input);
    printf("Input: %s\n", buffer);
}
