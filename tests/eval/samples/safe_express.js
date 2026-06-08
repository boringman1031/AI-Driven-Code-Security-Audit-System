// 無漏洞：安全的 Express 路由
const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

router.post('/users',
  body('email').isEmail().normalizeEmail(),
  body('name').trim().isLength({ min: 1, max: 100 }).escape(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // 使用參數化查詢
    db.query('INSERT INTO users (email, name) VALUES (?, ?)',
      [req.body.email, req.body.name]);
    res.json({ success: true });
  }
);
