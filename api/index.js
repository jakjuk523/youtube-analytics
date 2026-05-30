import express from "express";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(express.json());

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const COOKIE_NAME    = "yt_session";
const COOKIE_MAX_AGE = 365 * 24 * 60 * 60; // 365 дней в секундах
const JWT_SECRET     = process.env.JWT_SECRET;

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  const origin = process.env.APP_URL || "*";
  res.setHeader("Access-Control-Allow-Origin",      origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods",     "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers",     "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// ── Cookie parser ─────────────────────────────────────────────────────────────
function parseCookies(cookieHeader = "") {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(";").map((c) => {
      const [key, ...val] = c.trim().split("=");
      return [key, decodeURIComponent(val.join("="))];
    })
  );
}

// ── JWT helper ────────────────────────────────────────────────────────────────
function signSession(user) {
  return jwt.sign(
    {
      sub:          user.id,
      email:        user.email,
      channel_id:   user.channel_id   ?? null,
      channel_name: user.channel_name ?? null,
      avatar_url:   user.avatar_url   ?? null,
    },
    JWT_SECRET,
    { expiresIn: "365d" }
  );
}

function buildCookieHeader(token) {
  return [
    `${COOKIE_NAME}=${token}`,
    `Max-Age=${COOKIE_MAX_AGE}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
  ].join("; ");
}

// ══════════════════════════════════════════════════════════════════════════════
// GET /api/auth/google — редирект на Google OAuth 2.0
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/auth/google", (req, res) => {
  const redirectUri = `${process.env.APP_URL}/api/auth/callback`;

  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  redirectUri,
    response_type: "code",
    scope:         "openid email profile https://www.googleapis.com/auth/youtube.readonly",
    access_type:   "offline",
    prompt:        "consent",
  });

  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

  // Жёсткий редирект — Vercel не должен перехватывать
  res.writeHead(302, { Location: googleAuthUrl });
  res.end();
});

// ══════════════════════════════════════════════════════════════════════════════
// GET /api/auth/callback — обмен кода, Supabase upsert, JWT-кука
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/auth/callback", async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.redirect(`${process.env.APP_URL}/?auth_error=${encodeURIComponent(error)}`);
  }

  if (!code) {
    return res.status(400).json({ error: "Authorization code is missing" });
  }

  try {
    // ── 1. Меняем code на access_token ───────────────────────────────────
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri:  `${process.env.APP_URL}/api/auth/callback`,
        grant_type:    "authorization_code",
      }),
    });

    if (!tokenRes.ok) {
      const tokenErr = await tokenRes.json().catch(() => ({}));
      console.error("Token exchange error:", tokenErr);
      return res.status(502).json({ error: "Failed to exchange code for tokens" });
    }

    const { access_token } = await tokenRes.json();

    // ── 2. Профиль Google ────────────────────────────────────────────────
    const profileRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    if (!profileRes.ok) {
      return res.status(502).json({ error: "Failed to fetch Google profile" });
    }

    const profile = await profileRes.json();
    // profile: { sub, email, name, picture }

    // ── 3. YouTube канал ─────────────────────────────────────────────────
    const ytRes = await fetch(
      `https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true&key=${process.env.YOUTUBE_API_KEY}`,
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    let channel_name = null;
    let channel_id   = null;

    if (ytRes.ok) {
      const ytData  = await ytRes.json();
      const channel = ytData.items?.[0];
      if (channel) {
        channel_id   = channel.id;
        channel_name = channel.snippet?.title ?? null;
      }
    } else {
      console.warn("YouTube channel fetch failed:", await ytRes.text());
    }

    // ── 4. Upsert в Supabase ─────────────────────────────────────────────
    const { data: user, error: dbError } = await supabase
      .from("users")
      .upsert(
        {
          id:           profile.sub,
          email:        profile.email,
          channel_name,
          channel_id,
          avatar_url:   profile.picture ?? null,
          updated_at:   new Date().toISOString(),
        },
        { onConflict: "id" }
      )
      .select()
      .single();

    if (dbError) {
      console.error("Supabase upsert error:", dbError);
      return res.status(500).json({ error: "Failed to save user to database" });
    }

    // ── 5. JWT + кука 365 дней ───────────────────────────────────────────
    const token = signSession(user);
    res.setHeader("Set-Cookie", buildCookieHeader(token));

    // ── 6. Редирект на дашборд ───────────────────────────────────────────
    return res.redirect(`${process.env.APP_URL}/dashboard`);

  } catch (err) {
    console.error("Callback handler error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// GET /api/auth/me — проверка куки, возврат данных или 401
// Также возвращает свежий Set-Cookie, продлевая сессию при каждом визите
// ══════════════════════════════════════════════════════════════════════════════
app.get("/api/auth/me", (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const token   = cookies[COOKIE_NAME];

  if (!token) {
    return res.status(401).json({ error: "No session cookie found" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    const userData = {
      id:           payload.sub,
      email:        payload.email,
      channel_id:   payload.channel_id   ?? null,
      channel_name: payload.channel_name ?? null,
      avatar_url:   payload.avatar_url   ?? null,
    };

    // Продлеваем куку при каждом успешном запросе /me
    // Это гарантирует, что активные пользователи не вылетают
    const freshToken = signSession({
      id:           userData.id,
      email:        userData.email,
      channel_id:   userData.channel_id,
      channel_name: userData.channel_name,
      avatar_url:   userData.avatar_url,
    });

    res.setHeader("Set-Cookie", buildCookieHeader(freshToken));

    return res.status(200).json(userData);

  } catch (err) {
    // Удаляем протухшую куку из браузера
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None`
    );

    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Session expired, please log in again" });
    }
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid session token" });
    }

    console.error("JWT verification error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// POST /api/auth/logout — явный выход: убиваем куку на сервере
// ══════════════════════════════════════════════════════════════════════════════
app.post("/api/auth/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None`
  );
  return res.status(200).json({ ok: true });
});

// ── Fallback 404 ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ── Экспорт для Vercel Serverless ─────────────────────────────────────────────
export default app;
