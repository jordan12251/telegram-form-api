   // api/server.js
// Version compatible avec Vercel (export via module.exports)

const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());

// --- Config
const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const CODE_LENGTH = 6;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 20;
const rateMap = new Map();

// Helpers
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
    if (idx === -1) throw new Error("Invalid code character");
    decoded = decoded * 64 + idx;
  }
  return decoded;
}

function escapeHtml(str = "") {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function requireApiKeyMiddleware(req, res, next) {
  const required = process.env.API_KEY || "";
  if (!required) return res.status(500).send("Server not configured (API_KEY missing)");
  const provided = String(req.headers["x-api-key"] || "");
  if (provided !== required) return res.status(401).send("Unauthorized (invalid API key)");
  next();
}

// --- CORS
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-API-KEY");
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

// --- Whitelist & Rate Limit
function isUidWhitelisted(uid) {
  const raw = process.env.WHITELIST || "";
  if (!raw) return false;
  const list = raw.split(",").map(s => s.trim()).filter(Boolean);
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

// --- Routes

// Encode
app.post("/api/encode", requireApiKeyMiddleware, (req, res) => {
  const { uid } = req.body || {};
  if (uid === undefined || uid === null) return res.status(400).json({ error: "uid missing" });
  try {
    const code = encodeUid(uid);
    return res.json({ code });
  } catch (e) {
    return res.status(400).json({ error: e.message || "invalid uid" });
  }
});

// Decode
app.post("/api/decode", requireApiKeyMiddleware, (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "code missing" });
  try {
    const uid = decodeCode(String(code));
    return res.json({ uid: String(uid) });
  } catch (e) {
    return res.status(400).json({ error: e.message || "invalid code" });
  }
});

// Submit form
app.post("/api/submit", async (req, res) => {
  const { code, source, form } = req.body || {};
  if (!code || !form || typeof form !== "object") return res.status(400).send("code or form missing/invalid");

  let uid;
  try {
    uid = String(decodeCode(String(code)));
  } catch {
    return res.status(400).send("invalid code");
  }

  const providedKey = String(req.headers["x-api-key"] || "");
  const requiredKey = process.env.API_KEY || "";
  const isOwnerCall = requiredKey && providedKey === requiredKey;

  if (!isOwnerCall && !isUidWhitelisted(uid)) {
    return res.status(403).send("Target UID not allowed");
  }

  if (!checkRateLimit(uid)) {
    return res.status(429).send("Too many requests (rate limit)");
  }

  const clean = (s) => escapeHtml(String(s || ""));
  const lines = Object.entries(form)
    .map(([k, v]) => `• <b>${clean(k)}:</b> ${clean(v)}`)
    .join("\n");

  const botToken = process.env.TELEGRAM_TOKEN;
  if (!botToken) return res.status(500).send("Server misconfigured (missing TELEGRAM_TOKEN)");

  const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
  const text = `<b>Page :</b> ${clean(source || "unknown")}\n<b>UID :</b> ${clean(uid)}\n\n<b>Formulaire :</b>\n${lines}`;

  try {
    const resp = await fetch(telegramUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: uid,
        text,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
    });

    const j = await resp.json();
    if (!resp.ok || !j.ok) {
      console.error("Telegram API error:", j);
      return res.status(502).send("Telegram API error");
    }

    return res.status(200).send("Formulaire envoyé ✅");
  } catch (err) {
    console.error("Network error:", err);
    return res.status(502).send("Network error");
  }
});

// Default route
app.get("/api", (req, res) => res.send("API ready ✅"));

// ✅ Export pour Vercel
module.exports = app;
