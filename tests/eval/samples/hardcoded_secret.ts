// CWE-798: Hardcoded Secret TypeScript（含漏洞）
import jwt from 'jsonwebtoken';

// 硬編碼的 JWT 秘鑰
const JWT_SECRET = 'super_secret_key_123';

export function generateToken(userId: string): string {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '24h' });
}
