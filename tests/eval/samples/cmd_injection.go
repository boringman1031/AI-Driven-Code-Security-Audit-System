// CWE-78: Command Injection Go（含漏洞）
package main

import (
	"net/http"
	"os/exec"
)

func runCommand(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// 直接將使用者輸入傳入 shell，存在命令注入
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}
