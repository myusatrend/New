const express = require("express");
const { Pool } = require("pg");

const app = express();

// Neon database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get("/", (req, res) => {
  res.send("AA1 CASTLE + DATABASE CONNECTED 🗄️🏰");
});

// test database
app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ success: true, time: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
