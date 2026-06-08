// CWE-306: Missing Authentication（含漏洞）TypeScript
import { Request, Response } from 'express';

// 管理員路由完全未驗證身份
export function deleteUser(req: Request, res: Response) {
  const userId = req.params.id;
  // 直接執行刪除，無任何身份驗證或授權檢查
  db.query('DELETE FROM users WHERE id = ?', [userId]);
  res.json({ success: true });
}
