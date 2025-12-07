const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const helmet = require("helmet");

const app = express();
const PORT = 3001;

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));
app.disable("x-powered-by");

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      objectSrc: ["'none'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    },
  })
);

// Permissions-Policy applied to ALL responses
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );
  next();
});


app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`);
});

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", bcrypt.genSaltSync(12))
  }
];

const sessions = {}; // token -> { userId }

function findUser(username) {
  return users.find((u) => u.username === username);
}


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

  if (!user) {
    return res.status(401).json({ success: false, message: "Unknown username" });
  }

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ success: false, message: "Wrong password" });
  }

  const token = username + "-" + Date.now();

  sessions[token] = { userId: user.id };

  res.cookie("session", token, {
    // (kept intentionally insecure for teaching demo)
  });

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

// --------------------------------------------------------

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
