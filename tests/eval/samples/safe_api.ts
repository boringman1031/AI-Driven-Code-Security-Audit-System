// 無漏洞：安全的 API TypeScript
import { Request, Response, NextFunction } from 'express';
import { verifyJwt } from './auth';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = verifyJwt(token);
    req.user = payload;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid token' });
  }
}
