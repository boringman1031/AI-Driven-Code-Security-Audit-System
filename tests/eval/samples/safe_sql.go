// 無漏洞：安全的 SQL 查詢 Go
package main

import (
	"database/sql"
	"net/http"
)

func getUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// 使用參數化查詢，防止 SQL Injection
	row := db.QueryRow("SELECT id, email FROM users WHERE username = $1", username)
	var id int
	var email string
	if err := row.Scan(&id, &email); err != nil {
		http.Error(w, "User not found", 404)
	}
}
