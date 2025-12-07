// Hardened Express app with comprehensive security headers and safe error handling

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const lusca = require("lusca");
const helmet = require("helmet");
const path = require("path");

const app = express();
const PORT = 3001;
const isProd = process.env.NODE_ENV === "production";

/* ---------------- SECURITY HEADERS ---------------- */
app.disable("x-powered-by");

app.use(
  helmet({
    // Cross-origin isolation for Spectre mitigations
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginEmbedderPolicy: { policy: "require-corp" },
    crossOriginResourcePolicy: { policy: "same-origin" },

    // Content Security Policy (explicit directives, no fallbacks)
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'"],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        mediaSrc: ["'self'"],
        workerSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: []
      }
    },

    // Other recommended headers
    referrerPolicy: { policy: "no-referrer" },
    hsts: isProd ? { maxAge: 15552000, includeSubDomains: true } : false
  })
);

// Permissions-Policy (feature policy)
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), interest-cohort=()"
  );
  next();
});

/* ---------------- PARSERS ---------------- */
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

/* ---------------- STATIC FILES ---------------- */
app.use(
  express.static(path.join(__dirname, "public"), {
    etag: true,
    maxAge: isProd ? "7d" : 0,
    setHeaders: (res) => {
      res.setHeader("Cache-Control", isProd ? "public, max-age=604800" : "no-store");
    }
  })
);

/* ---------------- FIX robots + sitemap ---------------- */
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>`);
});

/* ---------------- USER DATABASE ---------------- */
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", bcrypt.genSaltSync(12))
  }
];

const sessions = {}; // token → { userId, createdAt }

/* ---------------- HELPERS ---------------- */
function findUser(username) {
  return users.find((u) => u.username === username);
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

/* ---------------- API ROUTES ---------------- */

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(200).json({ authenticated: false });
  }
  const user = users.find((u) => u.id === sessions[token].userId);
  if (!user) {
    return res.status(200).json({ authenticated: false });
  }
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = findUser(username);

  // Prevent username enumeration
  if (!user) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  const ok = bcrypt.compareSync(password || "", user.passwordHash);
  if (!ok) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  const token = generateSessionToken();
  sessions[token] = { userId: user.id, createdAt: Date.now() };

  res.cookie("session", token, {
    httpOnly: true,
    secure: isProd, // true in production with HTTPS
    sameSite: "strict"
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) delete sessions[token];
  res.clearCookie("session", { httpOnly: true, secure: isProd, sameSite: "strict" });
  res.json({ success: true });
});

/* ---------------- CSRF PROTECTION ---------------- */
app.use((req, res, next) => {
  const csrfExcluded = [
    "/api/login",
    "/api/logout",
    "/api/me",
    "/robots.txt",
    "/sitemap.xml"
  ];
  if (csrfExcluded.includes(req.path) || req.path.startsWith("/api/")) {
    return next();
  }
  return lusca.csrf()(req, res, next);
});

/* ---------------- HOME ROUTE ---------------- */
app.get("/", (req, res) => {
  res.status(200).json({ status: "ok" });
});

/* ---------------- 404 HANDLER ---------------- */
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Not found" });
});

/* ---------------- ERROR HANDLER (FINAL) ---------------- */
app.use((err, req, res, next) => {
  // Avoid detailed error logging in production
  if (!isProd) {
    console.error("SERVER ERROR:", err);
  } else {
    console.error("SERVER ERROR");
  }
  res.status(500).json({ success: false, message: "Internal server error" });
});

/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log(`Secure FastBank Auth Lab running at http://localhost:${PORT}`);
});
