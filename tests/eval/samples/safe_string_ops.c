/* 無漏洞：安全的字串操作 C */
#include <string.h>
#include <stdio.h>

void process_input(const char *user_input) {
    char buffer[64];
    /* 使用 strncpy 並確保 null 終止 */
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Input: %s\n", buffer);
}
