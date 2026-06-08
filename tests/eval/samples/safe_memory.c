/* 無漏洞：安全的記憶體管理 C */
#include <stdlib.h>
#include <string.h>

char* safe_dup(const char *src, size_t max_len) {
    if (!src || max_len == 0) return NULL;
    size_t len = strnlen(src, max_len);
    char *buf = malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;  /* 呼叫者負責 free */
}
