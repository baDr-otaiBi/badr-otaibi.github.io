require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// === Middleware ===
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

// === Database Setup ===
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const db = new Database(path.join(dataDir, 'database.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT,
    price REAL NOT NULL,
    file_path TEXT,
    is_available INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL,
    customer_name TEXT,
    customer_email TEXT,
    customer_phone TEXT,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    payment_id TEXT,
    payment_method TEXT,
    download_token TEXT,
    download_count INTEGER DEFAULT 0,
    token_expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS download_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL,
    ip_address TEXT,
    downloaded_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (order_id) REFERENCES orders(id)
  );
`);

// Seed default products if empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (productCount.count === 0) {
  const insert = db.prepare('INSERT INTO products (id, name, description, category, price, file_path, is_available) VALUES (?, ?, ?, ?, ?, ?, ?)');
  insert.run('nafs-1000', 'تجميعات اختبار نافس — 1000 سؤال', 'تجميعة شاملة تضم 1000 سؤال من اختبارات نافس مع الإجابات النموذجية لكل سؤال', 'اختبار نافس', 49, 'nafs-1000.pdf', 1);
  insert.run('science-summary', 'ملخص مادة العلوم', 'ملخص شامل ومنظّم لمادة العلوم يغطي أهم المفاهيم والمواضيع الأساسية', 'ملخصات', 29, 'science-summary.pdf', 1);
  insert.run('qudrat-bank', 'بنك أسئلة القدرات', 'أسئلة محلولة للقسم الكمي واللفظي', 'اختبارات', 0, null, 0);
  insert.run('tahsili-pack', 'حقيبة التحصيلي', 'ملخصات وتجميعات لاختبار التحصيلي', 'اختبارات', 0, null, 0);
}

// === Helpers ===
function generateDownloadToken() {
  return crypto.randomBytes(32).toString('hex');
}

function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'جلسة منتهية' });
  }
}

// === API Routes ===

// Get all products
app.get('/api/products', (req, res) => {
  const products = db.prepare('SELECT id, name, description, category, price, is_available FROM products').all();
  res.json(products);
});

// Get single product
app.get('/api/products/:id', (req, res) => {
  const product = db.prepare('SELECT id, name, description, category, price, is_available FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'المنتج غير موجود' });
  res.json(product);
});

// Create order (initiate payment)
app.post('/api/orders', (req, res) => {
  const { product_id, customer_name, customer_phone, customer_email } = req.body;

  const product = db.prepare('SELECT * FROM products WHERE id = ? AND is_available = 1').get(product_id);
  if (!product) return res.status(400).json({ error: 'المنتج غير متاح' });

  if (!customer_name || !customer_phone) {
    return res.status(400).json({ error: 'الاسم ورقم الجوال مطلوبان' });
  }

  const orderId = uuidv4();
  db.prepare(`
    INSERT INTO orders (id, product_id, customer_name, customer_email, customer_phone, amount)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(orderId, product_id, customer_name, customer_email || null, customer_phone, product.price);

  res.json({
    order_id: orderId,
    amount: product.price * 100, // Moyasar expects amount in halalas
    product_name: product.name,
    moyasar_key: process.env.MOYASAR_PUBLISHABLE_KEY || ''
  });
});

// Payment callback from Moyasar
app.post('/api/payment/callback', (req, res) => {
  const { id: paymentId, status, metadata } = req.body;
  const orderId = metadata?.order_id;

  if (!orderId) return res.status(400).json({ error: 'معرّف الطلب مفقود' });

  if (status === 'paid') {
    const token = generateDownloadToken();
    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString(); // 72 hours

    db.prepare(`
      UPDATE orders SET status = 'paid', payment_id = ?, download_token = ?, token_expires_at = ?
      WHERE id = ?
    `).run(paymentId, token, expiresAt, orderId);

    return res.json({ success: true, download_token: token });
  }

  db.prepare('UPDATE orders SET status = ?, payment_id = ? WHERE id = ?')
    .run(status === 'failed' ? 'failed' : status, paymentId, orderId);

  res.json({ success: true });
});

// Moyasar redirect callback (GET)
app.get('/api/payment/callback', (req, res) => {
  const { id: paymentId, status, message } = req.query;

  if (status === 'paid' && paymentId) {
    // Find the order by payment_id
    const order = db.prepare('SELECT * FROM orders WHERE payment_id = ?').get(paymentId);
    if (order && order.download_token) {
      return res.redirect(`/download.html?token=${order.download_token}`);
    }
  }

  res.redirect('/?payment=failed');
});

// Verify payment and get download link (called after Moyasar form success)
app.post('/api/payment/verify', (req, res) => {
  const { order_id, payment_id } = req.body;

  if (!order_id || !payment_id) {
    return res.status(400).json({ error: 'بيانات غير مكتملة' });
  }

  // Verify payment with Moyasar API
  const moyasarKey = process.env.MOYASAR_API_KEY;
  if (moyasarKey && moyasarKey !== 'sk_test_xxxxxxxxxxxx') {
    // In production, verify with Moyasar API
    const https = require('https');
    const options = {
      hostname: 'api.moyasar.com',
      path: `/v1/payments/${payment_id}`,
      headers: { 'Authorization': 'Basic ' + Buffer.from(moyasarKey + ':').toString('base64') }
    };

    https.get(options, (apiRes) => {
      let data = '';
      apiRes.on('data', chunk => data += chunk);
      apiRes.on('end', () => {
        try {
          const payment = JSON.parse(data);
          if (payment.status === 'paid') {
            const token = generateDownloadToken();
            const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString();

            db.prepare(`
              UPDATE orders SET status = 'paid', payment_id = ?, download_token = ?, token_expires_at = ?
              WHERE id = ?
            `).run(payment_id, token, expiresAt, order_id);

            return res.json({ success: true, download_token: token });
          }
          res.status(400).json({ error: 'الدفع لم يكتمل' });
        } catch {
          res.status(500).json({ error: 'خطأ في التحقق' });
        }
      });
    }).on('error', () => {
      res.status(500).json({ error: 'خطأ في الاتصال' });
    });
  } else {
    // Test mode: auto-approve
    const token = generateDownloadToken();
    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString();

    db.prepare(`
      UPDATE orders SET status = 'paid', payment_id = ?, download_token = ?, token_expires_at = ?
      WHERE id = ?
    `).run(payment_id || 'test_' + Date.now(), token, expiresAt, order_id);

    res.json({ success: true, download_token: token });
  }
});

// Download file
app.get('/api/download/:token', (req, res) => {
  const order = db.prepare(`
    SELECT o.*, p.file_path, p.name as product_name
    FROM orders o JOIN products p ON o.product_id = p.id
    WHERE o.download_token = ? AND o.status = 'paid'
  `).get(req.params.token);

  if (!order) return res.status(404).json({ error: 'رابط التحميل غير صالح' });

  if (new Date(order.token_expires_at) < new Date()) {
    return res.status(410).json({ error: 'رابط التحميل منتهي الصلاحية' });
  }

  if (order.download_count >= 5) {
    return res.status(403).json({ error: 'تم تجاوز الحد الأقصى للتحميل' });
  }

  const filePath = path.join(__dirname, 'products', order.file_path);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'الملف غير موجود حالياً' });
  }

  // Update download count and log
  db.prepare('UPDATE orders SET download_count = download_count + 1 WHERE id = ?').run(order.id);
  db.prepare('INSERT INTO download_logs (order_id, ip_address) VALUES (?, ?)').run(order.id, req.ip);

  res.download(filePath, `${order.product_name}.pdf`);
});

// Check download token validity
app.get('/api/download/:token/info', (req, res) => {
  const order = db.prepare(`
    SELECT o.id, o.download_count, o.token_expires_at, o.status, p.name as product_name
    FROM orders o JOIN products p ON o.product_id = p.id
    WHERE o.download_token = ? AND o.status = 'paid'
  `).get(req.params.token);

  if (!order) return res.status(404).json({ error: 'رابط غير صالح' });

  res.json({
    product_name: order.product_name,
    downloads_remaining: Math.max(0, 5 - order.download_count),
    expires_at: order.token_expires_at,
    expired: new Date(order.token_expires_at) < new Date()
  });
});

// === Admin Routes ===

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';

  if (username === adminUser && password === adminPass) {
    const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET || 'default-secret', { expiresIn: '24h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
});

// Get all orders
app.get('/api/admin/orders', authenticateAdmin, (req, res) => {
  const orders = db.prepare(`
    SELECT o.*, p.name as product_name
    FROM orders o JOIN products p ON o.product_id = p.id
    ORDER BY o.created_at DESC
  `).all();
  res.json(orders);
});

// Get dashboard stats
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  const totalOrders = db.prepare("SELECT COUNT(*) as count FROM orders WHERE status = 'paid'").get();
  const totalRevenue = db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM orders WHERE status = 'paid'").get();
  const todayOrders = db.prepare("SELECT COUNT(*) as count FROM orders WHERE status = 'paid' AND date(created_at) = date('now')").get();
  const todayRevenue = db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM orders WHERE status = 'paid' AND date(created_at) = date('now')").get();

  res.json({
    total_orders: totalOrders.count,
    total_revenue: totalRevenue.total,
    today_orders: todayOrders.count,
    today_revenue: todayRevenue.total
  });
});

// Update product
app.put('/api/admin/products/:id', authenticateAdmin, (req, res) => {
  const { name, description, price, is_available } = req.body;
  db.prepare('UPDATE products SET name = ?, description = ?, price = ?, is_available = ? WHERE id = ?')
    .run(name, description, price, is_available ? 1 : 0, req.params.id);
  res.json({ success: true });
});

// Manual order approval (for bank transfers)
app.post('/api/admin/orders/:id/approve', authenticateAdmin, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'الطلب غير موجود' });

  const token = generateDownloadToken();
  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    UPDATE orders SET status = 'paid', download_token = ?, token_expires_at = ?, payment_method = 'manual'
    WHERE id = ?
  `).run(token, expiresAt, order.id);

  res.json({ success: true, download_token: token });
});

// === Serve Pages ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/download.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'download.html')));

// === Start Server ===
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📁 Admin panel: http://localhost:${PORT}/admin`);

  // Ensure products directory exists
  const productsDir = path.join(__dirname, 'products');
  if (!fs.existsSync(productsDir)) {
    fs.mkdirSync(productsDir);
    console.log('📂 Created products/ directory — add your PDF files there');
  }
});
