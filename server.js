require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("cookie-session");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(express.json());

// CORS - Allow multiple origins
const allowedOrigins = [
    "https://gentle-faloodeh-cc8195.netlify.app",
    "https://your-github-username.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.some(allowed => origin.startsWith(allowed.replace(/\/$/, '')))) {
            return callback(null, true);
        }
        return callback(null, true); // Allow all for now, tighten later
    },
    credentials: true,
}));

app.use(session({
    name: "session",
    keys: [process.env.SESSION_SECRET || "wearenfeel_secret_key_2024"],
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: "none",
    secure: true,
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: "Not logged in" });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session || !req.session.user || req.session.user.role !== "admin") {
        return res.status(403).json({ error: "Admin only" });
    }
    next();
}

// Health check
app.get("/", (req, res) => res.send("WEARENFEEL backend is running!"));

// Auth routes
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    
    try {
        const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
        if (existing.rows.length > 0) return res.status(400).json({ error: "User already exists" });
        
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            "INSERT INTO users (email, password, role) VALUES ($1, $2, 'user') RETURNING id, email, role",
            [email, hash]
        );
        res.json({ success: true, user: result.rows[0] });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ error: "Signup failed" });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    
    try {
        const result = await pool.query(
            "SELECT id, email, password, role, name, phone, address FROM users WHERE email = $1",
            [email]
        );
        if (result.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
        
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Invalid credentials" });
        
        req.session.user = { id: user.id, email: user.email, role: user.role, name: user.name, phone: user.phone, address: user.address };
        res.json({ success: true, user: req.session.user });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Login failed" });
    }
});

app.get("/me", (req, res) => {
    if (!req.session || !req.session.user) return res.status(401).json({ error: "Not logged in" });
    res.json(req.session.user);
});

app.post("/logout", (req, res) => {
    req.session = null;
    res.json({ success: true });
});

// Products
app.get("/products", async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT * FROM products ORDER BY id DESC");
        res.json(rows);
    } catch (err) {
        console.error("Products error:", err);
        res.status(500).json({ error: "Failed to load products" });
    }
});

app.post("/products", requireAdmin, async (req, res) => {
    const { name, price, description, sizes, stock, images, bidStatus, bidDeposit } = req.body;
    if (!name || !price) return res.status(400).json({ error: "Name and price required" });
    
    try {
        const { rows } = await pool.query(
            `INSERT INTO products (name, price, description, sizes, stock, images, bid_status, bid_deposit)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [name, price, description, JSON.stringify(sizes || []), stock || 1, JSON.stringify(images || []), bidStatus || 'OPEN', bidDeposit || 100]
        );
        res.json(rows[0]);
    } catch (err) {
        console.error("Add product error:", err);
        res.status(500).json({ error: "Failed to add product" });
    }
});

app.put("/products/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, price, description, sizes, stock, images, bidStatus, bidDeposit } = req.body;
    
    try {
        const { rows } = await pool.query(
            `UPDATE products SET name=$1, price=$2, description=$3, sizes=$4, stock=$5, images=$6, bid_status=$7, bid_deposit=$8, updated_at=NOW()
             WHERE id=$9 RETURNING *`,
            [name, price, description, JSON.stringify(sizes || []), stock, JSON.stringify(images || []), bidStatus, bidDeposit, id]
        );
        if (rows.length === 0) return res.status(404).json({ error: "Product not found" });
        res.json(rows[0]);
    } catch (err) {
        console.error("Update product error:", err);
        res.status(500).json({ error: "Failed to update product" });
    }
});

app.delete("/products/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query("DELETE FROM products WHERE id = $1", [id]);
        res.json({ success: true });
    } catch (err) {
        console.error("Delete product error:", err);
        res.status(500).json({ error: "Failed to delete product" });
    }
});

// Deposits
app.post("/deposits", requireAuth, async (req, res) => {
    const { productId, amount } = req.body;
    const userId = req.session.user.id;
    
    try {
        await pool.query(
            `INSERT INTO deposits (user_id, product_id, amount) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, product_id) DO UPDATE SET amount = EXCLUDED.amount`,
            [userId, productId, amount]
        );
        res.json({ success: true });
    } catch (err) {
        console.error("Deposit error:", err);
        res.status(500).json({ error: "Deposit failed" });
    }
});

// Bids
app.get("/bids", async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT b.*, u.email, u.name, u.phone, u.address 
            FROM bids b LEFT JOIN users u ON b.user_id = u.id 
            ORDER BY b.bid_amount DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error("Bids error:", err);
        res.status(500).json({ error: "Failed to load bids" });
    }
});

app.post("/bids", requireAuth, async (req, res) => {
    const { productId, bidAmount, size } = req.body;
    const userId = req.session.user.id;
    
    try {
        // Check deposit
        const dep = await pool.query("SELECT id FROM deposits WHERE user_id=$1 AND product_id=$2", [userId, productId]);
        if (dep.rows.length === 0) return res.status(403).json({ error: "Deposit required" });
        
        // Check minimum bid
        const prod = await pool.query("SELECT price, bid_status FROM products WHERE id=$1", [productId]);
        if (prod.rows.length === 0) return res.status(404).json({ error: "Product not found" });
        if (prod.rows[0].bid_status === 'CLOSED') return res.status(400).json({ error: "Bidding closed" });
        
        const highest = await pool.query("SELECT MAX(bid_amount) as max FROM bids WHERE product_id=$1", [productId]);
        const minBid = Math.max(prod.rows[0].price, (highest.rows[0].max || 0) + 100);
        if (bidAmount < minBid) return res.status(400).json({ error: `Minimum bid is ₹${minBid}` });
        
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const { rows } = await pool.query(
            `INSERT INTO bids (user_id, product_id, bid_amount, code, size, status) VALUES ($1, $2, $3, $4, $5, 'ACTIVE') RETURNING *`,
            [userId, productId, bidAmount, code, size]
        );
        res.json(rows[0]);
    } catch (err) {
        console.error("Bid error:", err);
        res.status(500).json({ error: "Failed to place bid" });
    }
});

app.patch("/bids/:id", requireAuth, async (req, res) => {
    const { id } = req.params;
    const { bidAmount, size } = req.body;
    const userId = req.session.user.id;
    
    try {
        const bid = await pool.query("SELECT * FROM bids WHERE id=$1", [id]);
        if (bid.rows.length === 0) return res.status(404).json({ error: "Bid not found" });
        if (bid.rows[0].user_id !== userId) return res.status(403).json({ error: "Not your bid" });
        if (bid.rows[0].edited) return res.status(400).json({ error: "Already edited once" });
        
        const { rows } = await pool.query(
            `UPDATE bids SET bid_amount=$1, size=$2, edited=TRUE, edited_at=NOW() WHERE id=$3 RETURNING *`,
            [bidAmount, size, id]
        );
        res.json(rows[0]);
    } catch (err) {
        console.error("Edit bid error:", err);
        res.status(500).json({ error: "Failed to edit bid" });
    }
});

// Orders
app.get("/orders", requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query(`
            SELECT o.*, u.email, u.name, u.phone, u.address, p.name as product_name, p.images as product_images, b.code as bid_code, b.size
            FROM orders o 
            LEFT JOIN users u ON o.user_id = u.id 
            LEFT JOIN products p ON o.product_id = p.id
            LEFT JOIN bids b ON o.bid_id = b.id
            ORDER BY o.created_at DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error("Orders error:", err);
        res.status(500).json({ error: "Failed to load orders" });
    }
});

app.post("/orders", requireAdmin, async (req, res) => {
    const { productId, bidId, amount, isSecondChance } = req.body;
    
    try {
        const bid = await pool.query("SELECT user_id FROM bids WHERE id=$1", [bidId]);
        if (bid.rows.length === 0) return res.status(404).json({ error: "Bid not found" });
        
        const userId = bid.rows[0].user_id;
        
        // Mark winner
        await pool.query("UPDATE bids SET status='WINNER' WHERE id=$1", [bidId]);
        await pool.query("UPDATE bids SET status='REFUNDED' WHERE product_id=$1 AND id!=$2", [productId, bidId]);
        await pool.query("UPDATE products SET bid_status='CLOSED' WHERE id=$1", [productId]);
        
        const dep = await pool.query("SELECT amount FROM deposits WHERE user_id=$1 AND product_id=$2", [userId, productId]);
        const depositApplied = dep.rows.length > 0 ? dep.rows[0].amount : 0;
        
        const { rows } = await pool.query(
            `INSERT INTO orders (product_id, bid_id, user_id, amount, deposit_applied, is_second_chance, status)
             VALUES ($1, $2, $3, $4, $5, $6, 'AWAITING_PAYMENT') RETURNING *`,
            [productId, bidId, userId, amount, depositApplied, isSecondChance || false]
        );
        res.json(rows[0]);
    } catch (err) {
        console.error("Create order error:", err);
        res.status(500).json({ error: "Failed to create order" });
    }
});

// Customers
app.get("/customers", requireAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT id, email, name, phone, address, role, created_at FROM users ORDER BY created_at DESC");
        res.json(rows);
    } catch (err) {
        console.error("Customers error:", err);
        res.status(500).json({ error: "Failed to load customers" });
    }
});

app.patch("/customers/:id", requireAuth, async (req, res) => {
    const { id } = req.params;
    const { name, phone, address, password } = req.body;
    const userId = req.session.user.id;
    const isAdmin = req.session.user.role === 'admin';
    
    if (parseInt(id) !== userId && !isAdmin) return res.status(403).json({ error: "Not allowed" });
    
    try {
        let updates = [];
        let values = [];
        let i = 1;
        
        if (name !== undefined) { updates.push(`name=$${i++}`); values.push(name); }
        if (phone !== undefined) { updates.push(`phone=$${i++}`); values.push(phone); }
        if (address !== undefined) { updates.push(`address=$${i++}`); values.push(JSON.stringify(address)); }
        if (password) { updates.push(`password=$${i++}`); values.push(await bcrypt.hash(password, 10)); }
        
        if (updates.length === 0) return res.json({ success: true });
        
        values.push(id);
        const { rows } = await pool.query(
            `UPDATE users SET ${updates.join(', ')}, updated_at=NOW() WHERE id=$${i} RETURNING id, email, name, phone, address, role`,
            values
        );
        
        if (rows.length > 0 && parseInt(id) === userId) {
            req.session.user = { ...req.session.user, ...rows[0] };
        }
        
        res.json(rows[0]);
    } catch (err) {
        console.error("Update customer error:", err);
        res.status(500).json({ error: "Failed to update" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
