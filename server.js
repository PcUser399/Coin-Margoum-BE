require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;

const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        price NUMERIC(10,2) NOT NULL,
        category TEXT,
        image_url TEXT,
        available BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("Database table ready");
  } catch (err) {
    console.error("Database initialization failed:", err);
  }
}

initDB();

app.use(express.json());

app.use(cors({
  origin: process.env.FRONTEND_URL , 
  credentials: true
}));

app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { error: "Too many login attempts. Try again later." }
});

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token;

  if (!token) {
    return res.status(401).json({ error: "Not authorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.isAdmin === true) {
      return next();
    }

    return res.status(401).json({ error: "Not authorized" });
  } catch {
    return res.status(401).json({ error: "Not authorized" });
  }
}

app.get("/api/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      success: true,
      time: result.rows[0].now
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database connection failed" });
  }
});

app.post("/api/login", loginLimiter, async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Password required" });
  }

  const isCorrect = await bcrypt.compare(
    password,
    process.env.ADMIN_PASSWORD_HASH
  );

  if (!isCorrect) {
    return res.status(401).json({ error: "Wrong password" });
  }

  const token = jwt.sign(
    { isAdmin: true },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.cookie("admin_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 2
  });

  return res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("admin_token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax"
  });

  res.json({ success: true });
});

app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.json({ isAdmin: true });
});

app.get("/api/menu", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM menu_items
      WHERE available = true
      ORDER BY category, id;
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to load menu" });
  }
});

app.post("/api/admin/menu", requireAdmin, async (req, res) => {
  try {
    const { name, description, price, category, image_url, available } = req.body;

    const result = await pool.query(
      `
      INSERT INTO menu_items 
      (name, description, price, category, image_url, available)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
      `,
      [name, description, price, category, image_url, available ?? true]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add menu item" });
  }
});

app.put("/api/admin/menu/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, category, image_url, available } = req.body;

    const result = await pool.query(
      `
      UPDATE menu_items
      SET name = $1,
          description = $2,
          price = $3,
          category = $4,
          image_url = $5,
          available = $6
      WHERE id = $7
      RETURNING *
      `,
      [name, description, price, category, image_url, available, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Item not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update menu item" });
  }
});

app.delete("/api/admin/menu/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      "DELETE FROM menu_items WHERE id = $1 RETURNING *",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Item not found" });
    }

    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete menu item" });
  }
});

app.post("/api/admin/seed-menu", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      INSERT INTO menu_items 
      (name, description, price, category, image_url, available)
      VALUES 
      ('Pizza Margherita', 'Tomato sauce, mozzarella, basil', 12.50, 'Pizza', '', true),
      ('Classic Burger', 'Beef, cheese, lettuce, tomato', 10.00, 'Burger', '', true)
      RETURNING *;
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Seed failed" });
  }
});


app.get("/", (req, res) => {
  res.send("API is running");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});