require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;

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

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  res.json([
    { id: 1, item: "Pizza", status: "pending" },
    { id: 2, item: "Burger", status: "ready" }
  ]);
});

app.get("/", (req, res) => {
  res.send("API is running");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});