// CWE-89: SQL Injection Go（含漏洞）
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func getUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// 字串格式化拼接 SQL，存在 SQL Injection
	query := fmt.Sprintf("SELECT id, email FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
}
