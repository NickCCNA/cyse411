const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const lusca = require("lusca");
const helmet = require("helmet");

const app = express();
const PORT = 3001;

/* ---------------- SECURITY HEADERS ---------------- */
app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
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
    }
  })
);

app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

/* ---------------- ERROR HANDLER ---------------- */
app.use((err, req, res, next) => {
  // In production, avoid logging full error details
  console.error("SERVER ERROR"); 
  res.status(500).json({ success: false, message: "Internal server error" });
});


/* ---------------- PARSERS ---------------- */
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

/* ---------------- STATIC FILES ---------------- */
app.use(express.static("public"));

/* ---------------- FIX robots + sitemap ---------------- */
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>`);
});

/* ---------------- USER DATABASE ---------------- */
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", bcrypt.genSaltSync(12))
  }
];

const sessions = {}; // token → { userId }

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
    return res.status(401).json({ authenticated: false });
  }
  const user = users.find((u) => u.id === sessions[token].userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  // Prevent username enumeration
  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid credentials" });
  }

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid credentials" });
  }

  const token = generateSessionToken();
  sessions[token] = { userId: user.id };

  res.cookie("session", token, {
    httpOnly: true,
    secure: false, // set true in production with HTTPS
    sameSite: "lax"
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) delete sessions[token];
  res.clearCookie("session");
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

/* ---------------- START ---------------- */
app.listen(PORT, () => {
  console.log(`Secure FastBank Auth Lab running at http://localhost:${PORT}`);
});
