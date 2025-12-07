const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const lusca = require("lusca");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");

const app = express();

// --- BASIC CORS (clean, not vulnerable) ---
app.use(
  cors({
   origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());
app.use(lusca.csrf());

// --- IN-MEMORY SQLITE DB (clean) ---
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync("password123", salt);

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES ('alice', '${passwordHash}', 'alice@example.com');`);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 100, 'Groceries')`);
});

// --- SESSION STORE (simple, predictable token exactly like assignment) ---
const sessions = {};

// Password hashing now uses bcrypt; fastHash removed.

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

// ------------------------------------------------------------
// Q4 — AUTH ISSUE 1 & 2: SHA256 fast hash + SQLi in username.
// Q4 — AUTH ISSUE 3: Username enumeration.
// Q4 — AUTH ISSUE 4: Predictable sessionId.
// ------------------------------------------------------------
// Apply a rate limiter for login attempts (e.g., 5 per minute per IP)
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: { error: "Too many login attempts. Please try again later." }
});

app.post("/login", loginLimiter, (req, res) => {
  const { username, password } = req.body;

  const sql = "SELECT id, username, password_hash FROM users WHERE username = ?";

  db.get(sql, [username], (err, user) => {
    if (!user) return res.status(404).json({ error: "Unknown username" });

    const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Wrong password" });
    }

    const sid = `${username}-${Date.now()}`; // predictable
    sessions[sid] = { userId: user.id };

    // Cookie is intentionally “normal” (not HttpOnly / secure)
    res.cookie("sid", sid, {});

    res.json({ success: true });
  });
});

// ------------------------------------------------------------
// /me — clean route, no vulnerabilities
// ------------------------------------------------------------
// Apply a rate limiter for /me requests (e.g., 100 requests per 15 minutes per IP)
const meLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: "Too many requests to /me. Please try again later." }
});

app.get("/me", auth, meLimiter, (req, res) => {
  db.get(`SELECT username, email FROM users WHERE id = ${req.user.id}`, (err, row) => {
    res.json(row);
  });
});

// Rate limiter for /transactions: e.g., 100 requests per 15 minutes per IP
const transactionsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: "Too many requests to /transactions. Please try again later." }
});

// Rate limiter for /change-email: e.g., 10 requests per 15 minutes per IP
const changeEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: "Too many requests to /change-email. Please try again later." }
});
// Rate limiter for /feedback: e.g., 100 requests per 15 minutes per IP
const feedbackLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: "Too many requests to /feedback. Please try again later." }
});
// ------------------------------------------------------------
// Q1 — SQLi in transaction search
// ------------------------------------------------------------
app.get("/transactions", auth, transactionsLimiter, (req, res) => {
  const q = req.query.q || "";
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;
  db.all(sql, [req.user.id, `%${q}%`], (err, rows) => res.json(rows));
});

// ------------------------------------------------------------
// Q2 — Stored XSS + SQLi in feedback insert
// ------------------------------------------------------------

app.get("/feedback", auth, feedbackLimiter, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    res.json(rows);
  });
});

// ------------------------------------------------------------
// Q3 — CSRF + SQLi in email update
// ------------------------------------------------------------
app.post("/change-email", auth, changeEmailLimiter, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });

  const sql = `
    UPDATE users SET email = ? WHERE id = ?
  `;
  db.run(sql, [newEmail, req.user.id], () => {
    res.json({ success: true, email: newEmail });
  });
});

// ------------------------------------------------------------
app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
