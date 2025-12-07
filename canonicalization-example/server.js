// Hardened Express server with security headers and minimal robots/sitemap

const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const BASE_DIR = path.resolve(__dirname, 'files');
const isProd = process.env.NODE_ENV === 'production';

// Ensure base directory exists
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

/* ---------------- SECURITY HEADERS ---------------- */
app.disable('x-powered-by');

// Helmet with explicit security policies
app.use(
  helmet({
    // Anti-clickjacking
    frameguard: { action: 'deny' },

    // X-Content-Type-Options: nosniff
    noSniff: true,

    // Referrer policy
    referrerPolicy: { policy: 'no-referrer' },

    // HSTS (only in production with HTTPS)
    hsts: isProd ? { maxAge: 15552000, includeSubDomains: true, preload: false } : false,

    // Cross-origin isolation (Spectre mitigations)
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginResourcePolicy: { policy: 'same-origin' },

    // Comprehensive CSP (explicit directives, no reliance on fallback)
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
    }
  })
);

// Permissions-Policy (Feature-Policy successor)
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    [
      'geolocation=()',
      'microphone=()',
      'camera=()',
      'accelerometer=()',
      'gyroscope=()',
      'magnetometer=()',
      'fullscreen=()',
      'payment=()'
    ].join(', ')
  );
  next();
});

/* ---------------- PARSERS ---------------- */
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

/* ---------------- STATIC FILES ---------------- */
app.use(
  express.static(path.join(__dirname, 'public'), {
    etag: true,
    maxAge: isProd ? '7d' : 0,
    setHeaders: (res) => {
      res.setHeader('Cache-Control', isProd ? 'public, max-age=604800' : 'no-store');
      // Allow static assets to be embedded if needed under COEP (set corp)
      res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    }
  })
);

/* ---------------- AUX ROUTES (robots + sitemap) ---------------- */
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send('User-agent: *\nDisallow:');
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').send('<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>');
});

/* ---------------- RATE LIMITING ---------------- */
const readLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

/* ---------------- HELPERS ---------------- */
function resolveSafe(baseDir, userInput) {
  let input = String(userInput || '');
  try {
    input = decodeURIComponent(input);
  } catch (_) {}
  return path.resolve(baseDir, input);
}

/* ---------------- SECURE ROUTE ---------------- */
app.post(
  '/read',
  readLimiter,
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom((value) => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    // Ensure path is inside BASE_DIR
    const baseWithSep = BASE_DIR.endsWith(path.sep) ? BASE_DIR : BASE_DIR + path.sep;
    if (!normalized.startsWith(baseWithSep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

/* ---------------- DEMO (INTENTIONALLY LESS STRICT) ---------------- */
app.post('/read-no-validate', readLimiter, (req, res) => {
  const filename = req.body.filename || '';
  const normalized = resolveSafe(BASE_DIR, filename);
  const baseWithSep = BASE_DIR.endsWith(path.sep) ? BASE_DIR : BASE_DIR + path.sep;

  if (!normalized.startsWith(baseWithSep)) {
    return res.status(403).json({ error: 'Path traversal detected' });
  }
  if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found', path: normalized });

  const content = fs.readFileSync(normalized, 'utf8');
  res.json({ path: normalized, content });
});

/* ---------------- SAMPLE SETUP ---------------- */
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  for (const k of Object.keys(samples)) {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  }
  res.json({ ok: true, base: BASE_DIR });
});

/* ---------------- HEALTH + 404 ---------------- */
app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Not found' });
});

/* ---------------- ERROR HANDLER ---------------- */
app.use((err, req, res, next) => {
  // Avoid detailed error logging in production to minimize disclosure
  if (!isProd) {
    console.error('SERVER ERROR:', err);
  } else {
    console.error('SERVER ERROR');
  }
  res.status(500).json({ success: false, message: 'Internal server error' });
});

/* ---------------- START ---------------- */
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
