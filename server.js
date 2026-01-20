const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================
// DATABASE CONNECTION (Neon PostgreSQL)
// ========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack);
  } else {
    console.log('✅ Database connected successfully');
    release();
  }
});

// ========================================
// MIDDLEWARE
// ========================================
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:5501',
      'http://127.0.0.1:5501',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all in development
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'wearenfeel-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true only in production with HTTPS
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: 'lax'
  }
}));

// ========================================
// OTP STORAGE (In-memory for demo)
// ========================================
const otpStore = new Map();

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendOTP(identifier, otp) {
  // DEMO: Just log to console
  console.log(`\n📧 =======================================`);
  console.log(`📧 OTP for ${identifier}: ${otp}`);
  console.log(`📧 =======================================\n`);
  console.log(`⚠️  DEMO MODE: In production, send via SMS/Email service`);
  return true;
}

// ========================================
// AUTHENTICATION ENDPOINTS
// ========================================

// Sign Up
app.post('/signup', async (req, res) => {
  try {
    const { identifier, password, name, address } = req.body;

    if (!identifier || !password) {
      return res.status(400).send('Identifier and password required');
    }

    // Check if user exists
    const existing = await pool.query(
      'SELECT id FROM users WHERE identifier = $1',
      [identifier]
    );

    if (existing.rows.length > 0) {
      return res.status(400).send('User already exists. Please login.');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user (not verified yet)
    const result = await pool.query(
      `INSERT INTO users (identifier, password, name, email, phone, address, verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, identifier`,
      [
        identifier,
        hashedPassword,
        name || null,
        identifier.includes('@') ? identifier : null,
        !identifier.includes('@') ? identifier : null,
        address ? JSON.stringify(address) : null,
        false
      ]
    );

    // Generate and store OTP
    const otp = generateOTP();
    otpStore.set(identifier, {
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
      userId: result.rows[0].id
    });

    // Send OTP
    sendOTP(identifier, otp);

    res.status(200).json({ 
      message: 'OTP sent successfully',
      identifier 
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).send('Server error during signup');
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  try {
    const { identifier, otp } = req.body;

    if (!identifier || !otp) {
      return res.status(400).send('Identifier and OTP required');
    }

    const storedData = otpStore.get(identifier);

    if (!storedData) {
      return res.status(400).send('OTP not found or expired');
    }

    if (Date.now() > storedData.expiresAt) {
      otpStore.delete(identifier);
      return res.status(400).send('OTP expired');
    }

    if (storedData.otp !== otp) {
      return res.status(400).send('Invalid OTP');
    }

    // Mark user as verified
    await pool.query(
      'UPDATE users SET verified = true WHERE id = $1',
      [storedData.userId]
    );

    // Clean up OTP
    otpStore.delete(identifier);

    res.status(200).json({ 
      message: 'Account verified successfully' 
    });

  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).send('Server error during verification');
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).send('Identifier and password required');
    }

    // Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE identifier = $1',
      [identifier]
    );

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = result.rows[0];

    // Check if verified
    if (!user.verified) {
      return res.status(403).send('Account not verified. Please complete OTP verification.');
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).send('Invalid credentials');
    }

    // Create session
    req.session.userId = user.id;
    req.session.identifier = user.identifier;

    // Return user data (without password)
    const userData = {
      id: user.id,
      identifier: user.identifier,
      name: user.name,
      email: user.email,
      phone: user.phone,
      address: user.address ? JSON.parse(user.address) : null,
      photo: user.photo
    };

    res.status(200).json(userData);

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Server error during login');
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.clearCookie('connect.sid');
    res.status(200).send('Logged out successfully');
  });
});

// Get current user (restore session)
app.get('/me', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).send('Not authenticated');
    }

    const result = await pool.query(
      'SELECT id, identifier, name, email, phone, address, photo FROM users WHERE id = $1',
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    const user = result.rows[0];
    user.address = user.address ? JSON.parse(user.address) : null;

    res.status(200).json(user);

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).send('Server error');
  }
});

// ========================================
// PRODUCTS ENDPOINTS
// ========================================

// Get all products
app.get('/products', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM products ORDER BY created_at DESC'
    );

    const products = result.rows.map(p => ({
      ...p,
      images: p.images || [],
      sizes: p.sizes || [],
      description: p.description || ''
    }));

    res.status(200).json(products);

  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).send('Server error');
  }
});

// Create product
app.post('/products', async (req, res) => {
  try {
    const {
      id,
      name,
      price,
      description,
      sizes,
      stock,
      images,
      isAuction,
      bidDeposit,
      bidStatus,
      auctionEnd,
      videoUrl
    } = req.body;

    const result = await pool.query(
      `INSERT INTO products (
        id, name, price, description, sizes, stock, images,
        is_auction, bid_deposit, bid_status, auction_end, video_url
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`,
      [
        id || Date.now(),
        name,
        price,
        description || '',
        JSON.stringify(sizes || []),
        stock || 1,
        JSON.stringify(images || []),
        isAuction !== false,
        bidDeposit || 5000,
        bidStatus || 'OPEN',
        auctionEnd || null,
        videoUrl || null
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).send('Server error');
  }
});

// Update product
app.put('/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      price,
      description,
      sizes,
      stock,
      images,
      isAuction,
      bidDeposit,
      bidStatus,
      auctionEnd,
      videoUrl
    } = req.body;

    const result = await pool.query(
      `UPDATE products SET
        name = $1,
        price = $2,
        description = $3,
        sizes = $4,
        stock = $5,
        images = $6,
        is_auction = $7,
        bid_deposit = $8,
        bid_status = $9,
        auction_end = $10,
        video_url = $11,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $12
      RETURNING *`,
      [
        name,
        price,
        description || '',
        JSON.stringify(sizes || []),
        stock,
        JSON.stringify(images || []),
        isAuction,
        bidDeposit,
        bidStatus,
        auctionEnd,
        videoUrl,
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('Product not found');
    }

    res.status(200).json(result.rows[0]);

  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).send('Server error');
  }
});

// ========================================
// BIDS ENDPOINTS
// ========================================

// Get all bids
app.get('/bids', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM bids ORDER BY created_at DESC'
    );

    const bids = result.rows.map(b => ({
      ...b,
      address: b.address ? JSON.parse(b.address) : null
    }));

    res.status(200).json(bids);

  } catch (error) {
    console.error('Get bids error:', error);
    res.status(500).send('Server error');
  }
});

// Create bid
app.post('/bids', async (req, res) => {
  try {
    const {
      id,
      productId,
      productName,
      name,
      email,
      phone,
      address,
      country,
      deposit,
      bidAmount,
      code,
      size,
      status,
      userIdentifier
    } = req.body;

    const result = await pool.query(
      `INSERT INTO bids (
        id, product_id, product_name, name, email, phone,
        address, country, deposit, bid_amount, code, size,
        status, user_identifier, edited
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *`,
      [
        id || Date.now(),
        productId,
        productName || '',
        name || '',
        email || '',
        phone || '',
        address ? JSON.stringify(address) : null,
        country || '',
        deposit || 0,
        bidAmount || 0,
        code,
        size || '',
        status || 'ACTIVE',
        userIdentifier || email || phone,
        false
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error('Create bid error:', error);
    res.status(500).send('Server error');
  }
});

// Update bid
app.patch('/bids/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Build dynamic update query
    const fields = [];
    const values = [];
    let index = 1;

    for (const [key, value] of Object.entries(updates)) {
      const snakeKey = key.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
      
      if (snakeKey === 'address' && value) {
        fields.push(`${snakeKey} = $${index}`);
        values.push(JSON.stringify(value));
      } else {
        fields.push(`${snakeKey} = $${index}`);
        values.push(value);
      }
      index++;
    }

    if (fields.length === 0) {
      return res.status(400).send('No fields to update');
    }

    values.push(id);
    const query = `
      UPDATE bids SET ${fields.join(', ')}, updated_at = CURRENT_TIMESTAMP
      WHERE id = $${index}
      RETURNING *
    `;

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).send('Bid not found');
    }

    res.status(200).json(result.rows[0]);

  } catch (error) {
    console.error('Update bid error:', error);
    res.status(500).send('Server error');
  }
});

// ========================================
// ORDERS ENDPOINTS
// ========================================

// Get all orders
app.get('/orders', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM orders ORDER BY created_at DESC'
    );

    res.status(200).json(result.rows);

  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).send('Server error');
  }
});

// Create order
app.post('/orders', async (req, res) => {
  try {
    const {
      id,
      productId,
      bidId,
      code,
      name,
      email,
      country,
      size,
      bidAmount,
      deposit,
      status
    } = req.body;

    const result = await pool.query(
      `INSERT INTO orders (
        id, product_id, bid_id, code, name, email,
        country, size, bid_amount, deposit, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING *`,
      [
        id || Date.now(),
        productId,
        bidId,
        code,
        name || '',
        email || '',
        country || '',
        size || '',
        bidAmount || 0,
        deposit || 0,
        status || 'PROCESSING'
      ]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).send('Server error');
  }
});

// ========================================
// DEPOSITS ENDPOINT
// ========================================

app.post('/deposits', async (req, res) => {
  try {
    const { productId, amount } = req.body;

    const result = await pool.query(
      `INSERT INTO deposits (product_id, amount, user_id)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [productId, amount, req.session.userId || null]
    );

    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error('Record deposit error:', error);
    res.status(500).send('Server error');
  }
});

// ========================================
// HEALTH CHECK
// ========================================

app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString() 
  });
});

// ========================================
// ERROR HANDLING
// ========================================

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).send('Internal server error');
});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {
  console.log(`\n🚀 =======================================`);
  console.log(`🚀 WEARENFEEL Server running on port ${PORT}`);
  console.log(`🚀 =======================================`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:5500'}`);
  console.log(`\n💡 Check http://localhost:${PORT}/health to test\n`);
});