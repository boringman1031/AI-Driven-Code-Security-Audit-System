/* CWE-416: Use-After-Free C（含漏洞） */
#include <stdlib.h>
#include <string.h>

void process() {
    char *buf = malloc(128);
    strncpy(buf, "data", 4);

    free(buf);  /* 釋放記憶體 */

    /* 釋放後仍使用，存在 Use-After-Free */
    printf("%s\n", buf);
}
