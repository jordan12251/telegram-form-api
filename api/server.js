
const express = require("express");
const bodyParser = require("body-parser");
const FormData = require("form-data");
const serverless = require("serverless-http");

const app = express();
app.use(bodyParser.json({ limit: "10mb" }));

// ---------------- CONFIG ----------------
const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const CODE_LENGTH = 6;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 20;
const rateMap = new Map();

// ---------------- HELPERS ----------------
function encodeUid(uid) {
  uid = Number(uid);
  if (!Number.isFinite(uid) || uid < 0) throw new Error("uid must be a non-negative integer");
  const parts = [];
  for (let p = CODE_LENGTH - 1; p >= 0; p--) {
    const v = Math.floor(uid / (64 ** p)) % 64;
    parts.push(CHARS[v]);
  }
  return parts.join("");
}

function decodeCode(code) {
  if (!code || typeof code !== "string") throw new Error("invalid code");
  let decoded = 0;
  for (let i = 0; i < code.length; i++) {
    const idx = CHARS.indexOf(code[i]);
    if (idx === -1) throw new Error("invalid character");
    decoded = decoded * 64 + idx;
  }
  return decoded;
}

function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ---------------- SECURITY ----------------
function requireApiKeyMiddleware(req, res, next) {
  const required = process.env.API_KEY || "";
  if (!required) return res.status(500).send("API_KEY missing");
  const provided = String(req.headers["x-api-key"] || "");
  if (provided !== required) return res.status(401).send("Unauthorized");
  next();
}

// ---------------- CORS ----------------
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-API-KEY");
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

// ---------------- WHITELIST & RATE LIMIT ----------------
function isUidWhitelisted(uid) {
  const raw = process.env.WHITELIST || "";
  if (!raw.trim()) return true;
  const list = raw.split(",").map(s => s.trim());
  return list.includes(String(uid));
}

function checkRateLimit(uid) {
  const now = Date.now();
  const entry = rateMap.get(uid) || { count: 0, reset: now + RATE_LIMIT_WINDOW_MS };
  if (now > entry.reset) {
    entry.count = 0;
    entry.reset = now + RATE_LIMIT_WINDOW_MS;
  }
  entry.count++;
  rateMap.set(uid, entry);
  return entry.count <= RATE_LIMIT_MAX;
}

// ---------------- ROUTES ----------------

// Encode UID
app.post("/api/encode", requireApiKeyMiddleware, (req, res) => {
  const { uid } = req.body || {};
  if (uid === undefined) return res.status(400).json({ error: "uid missing" });
  try {
    res.json({ code: encodeUid(uid) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Decode code
app.post("/api/decode", requireApiKeyMiddleware, (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "code missing" });
  try {
    res.json({ uid: String(decodeCode(code)) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Submit form → Telegram
app.post("/api/submit", async (req, res) => {
  const { code, source, form } = req.body || {};
  if (!code || !form) return res.status(400).send("invalid payload");

  let uid;
  try {
    uid = String(decodeCode(code));
  } catch {
    return res.status(400).send("invalid code");
  }

  if (!checkRateLimit(uid)) return res.status(429).send("rate limit");

  const botToken = process.env.TELEGRAM_TOKEN;
  if (!botToken) return res.status(500).send("TELEGRAM_TOKEN missing");

  const text =
    `<b>UID :</b> ${escapeHtml(uid)}\n` +
    `<b>Source :</b> ${escapeHtml(source || "unknown")}\n\n` +
    Object.entries(form)
      .map(([k, v]) => `• <b>${escapeHtml(k)}:</b> ${escapeHtml(v)}`)
      .join("\n");

  const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: uid,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
    }),
  });

  if (!resp.ok) return res.status(502).send("telegram error");
  res.send("ok");
});

// Submit photo → Telegram
app.post("/api/submit-photo", async (req, res) => {
  const { code, source, photo } = req.body || {};
  if (!code || !photo) return res.status(400).send("missing code or photo");

  let uid;
  try {
    uid = String(decodeCode(code));
  } catch {
    return res.status(400).send("invalid code");
  }

  if (!checkRateLimit(uid)) return res.status(429).send("rate limit");

  const botToken = process.env.TELEGRAM_TOKEN;
  if (!botToken) return res.status(500).send("TELEGRAM_TOKEN missing");

  const base64Data = photo.replace(/^data:image\/\w+;base64,/, "");
  const buffer = Buffer.from(base64Data, "base64");

  const formData = new FormData();
  formData.append("chat_id", uid);
  formData.append("photo", buffer, { filename: "photo.jpg" });
  if (source) formData.append("caption", `📸 ${source}`);

  const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendPhoto`, {
    method: "POST",
    body: formData,
    headers: formData.getHeaders(),
  });

  if (!resp.ok) return res.status(502).send("telegram error");
  res.send("photo sent");
});

// Health check
app.get("/api", (req, res) => res.send("API ready ✅"));

module.exports = serverless(app);
