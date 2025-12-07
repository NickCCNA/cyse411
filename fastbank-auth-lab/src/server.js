const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const lusca = require("lusca");
const helmet = require("helmet");

const app = express();
const PORT = 3001;

/* ----------------------------------------------------
   SECURITY HEADERS (GLOBAL)
---------------------------------------------------- */

// Remove X-Powered-By
app.disable("x-powered-by");

// Full Helmet (adds: nosniff, hsts, noopen, frameguard, etc.)
app.use(helmet());

// Strict site isolation (fix ZAP 90004)
app.use(
  helmet.crossOriginOpenerPolicy({
    policy: "same-origin"
  })
);

// CSP for XSS protection
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

// Permissions Policy
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );
  next();
});

/* ----------------------------------------------------
   BODY / COOKIE PARSING
---------------------------------------------------- */
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

/* ----------------------------------------------------
   STATIC FILES
---------------------------------------------------- */
app.use(express.static("public"));

/* ----------------------------------------------------
   CSRF PROTECTION
---------------------------------------------------- */
const csrfExcluded = [
  "/api/login",
  "/api/logout",
  "/api/me",
  "/robots.txt",
  "/sitemap.xml"
];

app.use((req, res, next) => {
  if (csrfExcluded.includes(req.path) || req.path.startsWith("/api/")) {
    return next();
  }
  return lusca.csrf()(req, res, next);
});

/* ----------------------------------------------------
   FIX /robots.txt and /sitemap.xml FOR ZAP
---------------------------------------------------- */
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml").send(
    `<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>`
  );
});

/* ----------------------------------------------------
   FAKE USER DB
---------------------------------------------------- */
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", bcrypt.genSaltSync(12))
  }
];

const sessions = {}; // token → { userId }

/* ----------------------------------------------------
   HELPERS
---------------------------------------------------- */
function findUser(username) {
  return users.find((u) => u.username === username);
}

/* ----------------------------------------------------
   API: WHO AM I
---------------------------------------------------- */
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;

  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);

  res.json({ authenticated: true, username: user.username });
});

/* ----------------------------------------------------
   API: LOGIN (still intentionally vulnerable)
---------------------------------------------------- */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res.status(401).json({ success: false, message: "Unknown username" });
  }

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ success: false, message: "Wrong password" });
  }

  // Predictable token (intentionally vulnerable)
  const token = username + "-" + Date.now();

  sessions[token] = { userId: user.id };

  // Insecure cookie (intentionally vulnerable)
  res.cookie("session", token);

  res.json({ success: true, token });
});

/* ----------------------------------------------------
   API: LOGOUT
---------------------------------------------------- */
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];

  res.clearCookie("session");
  res.json({ success: true });
});

/* ----------------------------------------------------
   SAFE ROOT & NOT FOUND ROUTE
---------------------------------------------------- */
app.get("/", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// Final 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: "Not found" });
});

/* ----------------------------------------------------
   ERROR HANDLER
---------------------------------------------------- */
app.use((err, req, res, next) => {
  console.error("Internal error:", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

/* ----------------------------------------------------
   START SERVER
---------------------------------------------------- */
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
