const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
// bcrypt is installed but NOT used in the vulnerable baseline:
const bcrypt = require("bcrypt");
const lusca = require("lusca");
const helmet = require("helmet");

const app = express();

app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );
  next();
});
app.disable("x-powered-by");

const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));
app.use(lusca.csrf());

app.use(
  helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  })
);


// Fix ZAP’s expected files to prevent warnings
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>`);
});

/**
 * VULNERABLE FAKE USER DB
 * For simplicity, we start with a single user whose password is "password123".
 * In the vulnerable version, we hash with a fast hash (SHA-256-like).
 */
const users = [
  {
    id: 1,
    username: "student",
    // FIXED: bcrypt hash with salt
    passwordHash: bcrypt.hashSync("password123", bcrypt.genSaltSync(12)) // password is "password123"
  }
];

// In-memory session store
const sessions = {}; // token -> { userId }

/**
 * VULNERABLE FAST HASH FUNCTION
 * Students MUST STOP using this and replace logic with bcrypt.
 */
// fastHash function removed; use bcrypt instead

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * VULNERABLE LOGIN ENDPOINT
 * - Uses fastHash instead of bcrypt
 * - Error messages leak whether username exists
 * - Session token is simple and predictable
 * - Cookie lacks security flags
 */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    // VULNERABLE: username enumeration via message
    return res
      .status(401)
      .json({ success: false, message: "Unknown username" });
  }

  // Use bcrypt to verify password
  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res
      .status(401)
      .json({ success: false, message: "Wrong password" });
  }

  // VULNERABLE: predictable token
  const token = username + "-" + Date.now();

  // VULNERABLE: session stored without expiration
  sessions[token] = { userId: user.id };

  // VULNERABLE: cookie without httpOnly, secure, sameSite
  res.cookie("session", token, {
    // students must add: httpOnly: true, secure: true, sameSite: "lax"
  });

  // Client-side JS (login.html) will store this token in localStorage (vulnerable)
  res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.use((err, req, res, next) => {
  console.error("Internal error:", err); // OK to log server-side
  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
