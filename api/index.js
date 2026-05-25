
Backend all in one · JS
// ══════════════════════════════════════════════════════════════════════════════
// YouTube Analytics SaaS — Vercel Serverless Backend
// Структура: поместите каждый раздел в соответствующий файл
// ══════════════════════════════════════════════════════════════════════════════
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 📦 package.json
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// {
//   "name": "yt-analytics-backend",
//   "version": "1.0.0",
//   "type": "module",
//   "dependencies": {
//     "@supabase/supabase-js": "^2.45.0",
//     "jsonwebtoken": "^9.0.2"
//   }
// }
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ⚙️  vercel.json
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// {
//   "version": 2,
//   "rewrites": [
//     { "source": "/api/auth/google",   "destination": "/api/auth/google.js" },
//     { "source": "/api/auth/callback", "destination": "/api/auth/callback.js" },
//     { "source": "/api/auth/me",       "destination": "/api/auth/me.js" }
//   ],
//   "headers": [
//     {
//       "source": "/api/(.*)",
//       "headers": [
//         { "key": "Access-Control-Allow-Origin",      "value": "https://YOUR_GITHUB_PAGES_DOMAIN" },
//         { "key": "Access-Control-Allow-Credentials", "value": "true" },
//         { "key": "Access-Control-Allow-Methods",     "value": "GET, POST, OPTIONS" },
//         { "key": "Access-Control-Allow-Headers",     "value": "Content-Type, Authorization" }
//       ]
//     }
//   ]
// }
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 🗄️  supabase/schema.sql  — выполните в Supabase Dashboard → SQL Editor
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// CREATE TABLE IF NOT EXISTS public.users (
//   id            TEXT        PRIMARY KEY,
//   email         TEXT        NOT NULL UNIQUE,
//   channel_name  TEXT,
//   channel_id    TEXT,
//   avatar_url    TEXT,
//   created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//   updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
// );
//
// CREATE INDEX IF NOT EXISTS users_email_idx      ON public.users (email);
// CREATE INDEX IF NOT EXISTS users_channel_id_idx ON public.users (channel_id);
//
// ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
//
// -- Если используете service_role ключ на бэкенде — RLS не мешает.
// -- Если anon-ключ — раскомментируйте политику ниже:
// -- CREATE POLICY "Server can upsert users"
// --   ON public.users FOR ALL USING (true) WITH CHECK (true);
//
// CREATE OR REPLACE FUNCTION update_updated_at_column()
// RETURNS TRIGGER AS $$
// BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
// $$ LANGUAGE plpgsql;
//
// CREATE TRIGGER set_users_updated_at
//   BEFORE UPDATE ON public.users
//   FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 🔐 api/auth/google.js — редирект на Google OAuth 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 
export function googleHandler(req, res) {
  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  `${process.env.APP_URL}/api/auth/callback`,
    response_type: "code",
    scope: [
      "openid",
      "email",
      "profile",
      "https://www.googleapis.com/auth/youtube.readonly",
    ].join(" "),
    access_type: "offline",
    prompt:      "consent",
  });
 
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
}
 
// Экспорт для Vercel (файл api/auth/google.js):
// export default googleHandler;
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 🔄 api/auth/callback.js — обмен кода, YouTube, Supabase, JWT-кука
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";
 
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
 
const COOKIE_NAME    = "yt_session";
const COOKIE_MAX_AGE = 365 * 24 * 60 * 60; // 365 дней в секундах
const JWT_SECRET     = process.env.JWT_SECRET;
 
export async function callbackHandler(req, res) {
  const { code, error } = req.query;
 
  if (error) {
    return res.redirect(`${process.env.APP_URL}/?auth_error=${error}`);
  }
 
  if (!code) {
    return res.status(400).json({ error: "Authorization code is missing" });
  }
 
  try {
    // ── 1. Обмениваем code на access_token ──────────────────────────────
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
      console.error("Token exchange error:", await tokenRes.json());
      return res.status(502).json({ error: "Failed to exchange code for tokens" });
    }
 
    const { access_token } = await tokenRes.json();
 
    // ── 2. Профиль пользователя из Google ───────────────────────────────
    const profileRes = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      { headers: { Authorization: `Bearer ${access_token}` } }
    );
 
    if (!profileRes.ok) {
      return res.status(502).json({ error: "Failed to fetch Google profile" });
    }
 
    const profile = await profileRes.json();
    // profile содержит: { sub, email, name, picture }
 
    // ── 3. Данные YouTube-канала ─────────────────────────────────────────
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
      // Канала может не быть — не критично, продолжаем
      console.warn("YouTube channel fetch failed:", await ytRes.text());
    }
 
    // ── 4. Upsert пользователя в Supabase ───────────────────────────────
    const { data: user, error: dbError } = await supabase
      .from("users")
      .upsert(
        {
          id:           profile.sub,        // Google user ID как PK
          email:        profile.email,
          channel_name,
          channel_id,
          avatar_url:   profile.picture ?? null,
          updated_at:   new Date().toISOString(),
        },
        { onConflict: "id" }               // повторный вход — обновляем
      )
      .select()
      .single();
 
    if (dbError) {
      console.error("Supabase upsert error:", dbError);
      return res.status(500).json({ error: "Failed to save user to database" });
    }
 
    // ── 5. JWT-сессия → зашифрованная кука на 365 дней ──────────────────
    const token = jwt.sign(
      {
        sub:          user.id,
        email:        user.email,
        channel_id:   user.channel_id,
        channel_name: user.channel_name,
        avatar_url:   user.avatar_url,
      },
      JWT_SECRET,
      { expiresIn: "365d" }
    );
 
    res.setHeader(
      "Set-Cookie",
      [
        `${COOKIE_NAME}=${token}`,
        `Max-Age=${COOKIE_MAX_AGE}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=None",
      ].join("; ")
    );
 
    // ── 6. Редирект на дашборд ───────────────────────────────────────────
    return res.redirect(`${process.env.APP_URL}/dashboard`);
 
  } catch (err) {
    console.error("Callback handler error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}
 
// Экспорт для Vercel (файл api/auth/callback.js):
// export default callbackHandler;
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 👤 api/auth/me.js — проверка куки, возврат данных или 401
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 
function parseCookies(cookieHeader = "") {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(";").map((c) => {
      const [key, ...val] = c.trim().split("=");
      return [key, decodeURIComponent(val.join("="))];
    })
  );
}
 
export function meHandler(req, res) {
  res.setHeader("Access-Control-Allow-Origin",      process.env.APP_URL);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods",     "GET, OPTIONS");
 
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET")
    return res.status(405).json({ error: "Method not allowed" });
 
  // ── 1. Читаем куку ───────────────────────────────────────────────────
  const cookies = parseCookies(req.headers.cookie);
  const token   = cookies[COOKIE_NAME];
 
  if (!token) {
    return res.status(401).json({ error: "No session cookie found" });
  }
 
  // ── 2. Верифицируем JWT ──────────────────────────────────────────────
  try {
    const payload = jwt.verify(token, JWT_SECRET);
 
    return res.status(200).json({
      id:           payload.sub,
      email:        payload.email,
      channel_id:   payload.channel_id,
      channel_name: payload.channel_name,
      avatar_url:   payload.avatar_url,
    });
 
  } catch (err) {
    if (err.name === "TokenExpiredError")
      return res.status(401).json({ error: "Session expired, please log in again" });
    if (err.name === "JsonWebTokenError")
      return res.status(401).json({ error: "Invalid session token" });
 
    console.error("JWT verification error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}
 
// Экспорт для Vercel (файл api/auth/me.js):
// export default meHandler;
 
 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 📋 ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ — добавьте в Vercel Dashboard → Settings → Env Vars
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
//  YOUTUBE_API_KEY       = ваш ключ Google Developer
//  SUPABASE_URL          = https://xxxx.supabase.co
//  SUPABASE_KEY          = ваш anon или service_role ключ
//  GOOGLE_CLIENT_ID      = xxxx.apps.googleusercontent.com
//  GOOGLE_CLIENT_SECRET  = GOCSPX-xxxx
//  JWT_SECRET            = (openssl rand -base64 32)
//  APP_URL               = https://ваш-домен.github.io
 