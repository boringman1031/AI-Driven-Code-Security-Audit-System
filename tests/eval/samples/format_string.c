/* CWE-134: Format String Attack C（含漏洞） */
#include <stdio.h>

void log_message(char *user_input) {
    /* 直接將使用者輸入作為格式字串，存在格式字串攻擊 */
    printf(user_input);
}
