// api/index.js — YTMetrics Backend
// Vercel Serverless · Express · Google OAuth 2.0 + YouTube APIs

import express        from 'express';
import jwt            from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());

// ═══════════════════════════════════════════════════════
// ENV
// ═══════════════════════════════════════════════════════
const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  JWT_SECRET,
  SUPABASE_URL,
  SUPABASE_KEY,
  APP_URL = 'https://nightsightr.github.io',
} = process.env;

const REDIRECT_URI = 'https://youtube-analytics-ruddy.vercel.app/api/auth/callback';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ═══════════════════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════════════════
app.use((req, res, next) => {
  const allowed = [
    'https://nightsightr.github.io',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
  ];
  const origin = req.headers.origin;
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ═══════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════

/** Строим cookie-заголовок */
function buildCookieHeader(token) {
  return [
    `ytm_session=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=None',
    'Max-Age=31536000',
  ].join('; ');
}

/** Подписываем JWT */
function signSession(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '365d' });
}

/** Достаём токен из cookie или Authorization-заголовка */
function extractToken(req) {
  // 1) Из cookie
  const raw = req.headers.cookie || '';
  const match = raw.match(/ytm_session=([^;]+)/);
  if (match) return match[1];

  // 2) Из Bearer-заголовка (запасной вариант)
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);

  return null;
}

/** GET-запрос к Google API с access_token */
async function gFetch(url, accessToken) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Google API error ${res.status}: ${err}`);
  }
  return res.json();
}

/** Обновляем access_token через refresh_token */
async function refreshAccessToken(refreshToken) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type:    'refresh_token',
    }),
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error_description || 'Token refresh failed');
  return data.access_token;
}

// ═══════════════════════════════════════════════════════
// SCOPES
// ИСПРАВЛЕНИЕ 1: все нужные права YouTube
// ═══════════════════════════════════════════════════════
const YOUTUBE_SCOPES = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/youtube.readonly',
  'https://www.googleapis.com/auth/yt-analytics.readonly',
  'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
].join(' ');

// ═══════════════════════════════════════════════════════
// ROUTE 1: /api/auth/google — редирект на OAuth
// ═══════════════════════════════════════════════════════
app.get('/api/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    response_type: 'code',
    scope:         YOUTUBE_SCOPES,
    access_type:   'offline',    // получаем refresh_token
    prompt:        'consent',    // ОБЯЗАТЕЛЬНО: показываем окно с галочками каждый раз
    include_granted_scopes: 'true',
  });

  const url = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  // Используем writeHead чтобы Vercel не перехватил редирект
  res.writeHead(302, { Location: url });
  res.end();
});

// ═══════════════════════════════════════════════════════
// ROUTE 2: /api/auth/callback — обработка кода OAuth
// ═══════════════════════════════════════════════════════
app.get('/api/auth/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) {
    res.writeHead(302, { Location: `${APP_URL}?error=oauth_denied` });
    return res.end();
  }

  try {
    // ── 1. Меняем code на токены ──────────────────────
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  REDIRECT_URI,
        grant_type:    'authorization_code',
      }),
    });

    const tokens = await tokenRes.json();
    if (!tokenRes.ok || tokens.error) {
      console.error('Token exchange error:', tokens);
      res.writeHead(302, { Location: `${APP_URL}?error=token_exchange` });
      return res.end();
    }

    const { access_token, refresh_token, id_token } = tokens;

    // ── 2. Получаем Google-профиль (email, sub) ───────
    let googleProfile;
    try {
      googleProfile = await gFetch(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        access_token
      );
    } catch (e) {
      console.error('userinfo error:', e.message);
      res.writeHead(302, { Location: `${APP_URL}?error=userinfo` });
      return res.end();
    }

    const googleId = googleProfile.sub;
    const email    = googleProfile.email;

    // ── 3. ИСПРАВЛЕНИЕ 2: Получаем список YouTube-каналов ──
    let channels = [];
    try {
      const ytRes = await gFetch(
        'https://www.googleapis.com/youtube/v3/channels' +
        '?part=snippet,statistics&mine=true&maxResults=50',
        access_token
      );

      if (ytRes.items && ytRes.items.length > 0) {
        channels = ytRes.items.map(item => ({
          channel_id:   item.id,
          channel_name: item.snippet?.title || 'YouTube канал',
          // ИСПРАВЛЕНИЕ 3: Берём самый высокий доступный thumbnail
          avatar_url:
            item.snippet?.thumbnails?.high?.url     ||
            item.snippet?.thumbnails?.medium?.url   ||
            item.snippet?.thumbnails?.default?.url  ||
            null,
          description:  item.snippet?.description  || '',
          subscribers:  parseInt(item.statistics?.subscriberCount  || '0', 10),
          video_count:  parseInt(item.statistics?.videoCount        || '0', 10),
          view_count:   parseInt(item.statistics?.viewCount         || '0', 10),
          country:      item.snippet?.country || null,
          published_at: item.snippet?.publishedAt || null,
        }));
      }
    } catch (e) {
      console.warn('YouTube channels fetch warning (non-fatal):', e.message);
      // Не фатально — продолжаем без каналов
    }

    // Основной канал (первый или единственный)
    const primaryChannel = channels[0] || null;

    // ── 4. Сохраняем / обновляем пользователя в Supabase ──
    const userRecord = {
      id:           googleId,
      email,
      channel_id:   primaryChannel?.channel_id   || null,
      channel_name: primaryChannel?.channel_name || null,
      avatar_url:   primaryChannel?.avatar_url   || googleProfile.picture || null,
      subscribers:  primaryChannel?.subscribers  || 0,
      // Сохраняем refresh_token для будущих запросов к Analytics API
      refresh_token: refresh_token || null,
      updated_at:   new Date().toISOString(),
    };

    const { error: dbError } = await supabase
      .from('users')
      .upsert(userRecord, { onConflict: 'id' });

    if (dbError) {
      console.error('Supabase upsert error:', dbError);
      // Не прерываем — продолжаем без БД
    }

    // ── 5. Формируем payload для JWT ──────────────────
    const jwtPayload = {
      sub:          googleId,
      email,
      // Текущий активный канал
      channel_id:   primaryChannel?.channel_id   || null,
      channel_name: primaryChannel?.channel_name || null,
      avatar_url:   primaryChannel?.avatar_url   || googleProfile.picture || null,
      subscribers:  primaryChannel?.subscribers  || 0,
      // Все каналы пользователя — фронтенд покажет экран выбора
      channels,
      // Токены для Analytics API — шифруются внутри JWT
      access_token,
      refresh_token: refresh_token || null,
    };

    const sessionToken = signSession(jwtPayload);

    // ── 6. Редиректим на фронтенд с cookie ────────────
    res.writeHead(302, {
      'Set-Cookie': buildCookieHeader(sessionToken),
      Location: `${APP_URL}/dashboard`,
    });
    res.end();

  } catch (e) {
    console.error('Callback fatal error:', e);
    res.writeHead(302, { Location: `${APP_URL}?error=server` });
    res.end();
  }
});

// ═══════════════════════════════════════════════════════
// ROUTE 3: /api/auth/me — проверка сессии
// ═══════════════════════════════════════════════════════
app.get('/api/auth/me', async (req, res) => {
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json({ error: 'No session' });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    // Токен протух — пробуем обновить через refresh_token
    try {
      const expired = jwt.decode(token);
      if (!expired?.refresh_token) {
        return res.status(401).json({ error: 'Session expired' });
      }

      const newAccessToken = await refreshAccessToken(expired.refresh_token);

      // Обновляем список каналов с новым токеном
      let channels = expired.channels || [];
      try {
        const ytRes = await gFetch(
          'https://www.googleapis.com/youtube/v3/channels' +
          '?part=snippet,statistics&mine=true&maxResults=50',
          newAccessToken
        );
        if (ytRes.items?.length > 0) {
          channels = ytRes.items.map(item => ({
            channel_id:   item.id,
            channel_name: item.snippet?.title || 'YouTube канал',
            avatar_url:
              item.snippet?.thumbnails?.high?.url   ||
              item.snippet?.thumbnails?.medium?.url ||
              item.snippet?.thumbnails?.default?.url || null,
            subscribers: parseInt(item.statistics?.subscriberCount || '0', 10),
            video_count: parseInt(item.statistics?.videoCount       || '0', 10),
            view_count:  parseInt(item.statistics?.viewCount        || '0', 10),
          }));
        }
      } catch (ytErr) {
        console.warn('YouTube refresh channels warning:', ytErr.message);
      }

      const newPayload = {
        ...expired,
        access_token: newAccessToken,
        channels,
        iat: undefined,
        exp: undefined,
      };

      const newToken = signSession(newPayload);

      res.setHeader('Set-Cookie', buildCookieHeader(newToken));

      const { access_token: _at, refresh_token: _rt, ...safe } = newPayload;
      return res.json(safe);

    } catch (refreshErr) {
      console.error('Refresh failed:', refreshErr.message);
      res.setHeader('Set-Cookie', 'ytm_session=; Path=/; Max-Age=0');
      return res.status(401).json({ error: 'Session expired and refresh failed' });
    }
  }

  // Токен валиден — обновляем cookie и отдаём данные без токенов
  res.setHeader('Set-Cookie', buildCookieHeader(token));
  const { access_token: _at, refresh_token: _rt, ...safe } = payload;
  res.json(safe);
});

// ═══════════════════════════════════════════════════════
// ROUTE 4: /api/auth/logout
// ═══════════════════════════════════════════════════════
app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'ytm_session=; Path=/; Max-Age=0; SameSite=None; Secure');
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// ROUTE 5: /api/youtube/channels — список каналов
// (для повторного запроса с фронтенда без перелогина)
// ═══════════════════════════════════════════════════════
app.get('/api/youtube/channels', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'No session' });

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid session' }); }

  let accessToken = payload.access_token;

  // Если токен протух — обновляем
  if (!accessToken && payload.refresh_token) {
    try { accessToken = await refreshAccessToken(payload.refresh_token); }
    catch (e) { return res.status(401).json({ error: 'Cannot refresh token' }); }
  }

  try {
    const ytRes = await gFetch(
      'https://www.googleapis.com/youtube/v3/channels' +
      '?part=snippet,statistics,brandingSettings&mine=true&maxResults=50',
      accessToken
    );

    const channels = (ytRes.items || []).map(item => ({
      channel_id:   item.id,
      channel_name: item.snippet?.title || 'YouTube канал',
      avatar_url:
        item.snippet?.thumbnails?.high?.url     ||
        item.snippet?.thumbnails?.medium?.url   ||
        item.snippet?.thumbnails?.default?.url  ||
        item.brandingSettings?.image?.bannerExternalUrl || null,
      description:  item.snippet?.description  || '',
      subscribers:  parseInt(item.statistics?.subscriberCount  || '0', 10),
      video_count:  parseInt(item.statistics?.videoCount        || '0', 10),
      view_count:   parseInt(item.statistics?.viewCount         || '0', 10),
      country:      item.snippet?.country || null,
    }));

    res.json({ channels });
  } catch (e) {
    console.error('Channels fetch error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════
// ROUTE 6: /api/youtube/videos — список видео канала
// ═══════════════════════════════════════════════════════
app.get('/api/youtube/videos', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'No session' });

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid session' }); }

  const { channel_id, max_results = 20 } = req.query;
  let accessToken = payload.access_token;

  if (!accessToken && payload.refresh_token) {
    try { accessToken = await refreshAccessToken(payload.refresh_token); }
    catch { return res.status(401).json({ error: 'Cannot refresh token' }); }
  }

  // Определяем channelId
  const channelId = channel_id || payload.channel_id;
  if (!channelId) return res.status(400).json({ error: 'channel_id required' });

  try {
    // Получаем последние видео канала
    const searchRes = await gFetch(
      `https://www.googleapis.com/youtube/v3/search` +
      `?part=snippet&channelId=${channelId}&maxResults=${max_results}` +
      `&order=date&type=video`,
      accessToken
    );

    const videoIds = (searchRes.items || []).map(i => i.id.videoId).filter(Boolean);

    if (!videoIds.length) return res.json({ videos: [] });

    // Получаем детальную статистику видео
    const statsRes = await gFetch(
      `https://www.googleapis.com/youtube/v3/videos` +
      `?part=snippet,statistics,contentDetails&id=${videoIds.join(',')}`,
      accessToken
    );

    const videos = (statsRes.items || []).map(item => {
      const duration = item.contentDetails?.duration || 'PT0S';
      // Определяем тип: Shorts = вертикальное или ≤60 сек
      const durationSec = parseDurationToSeconds(duration);
      const isShort     = durationSec <= 60;

      return {
        id:           item.id,
        type:         isShort ? 'short' : 'long',
        title:        item.snippet?.title || 'Без названия',
        description:  item.snippet?.description || '',
        thumbnail:    item.snippet?.thumbnails?.medium?.url || null,
        published_at: item.snippet?.publishedAt || null,
        duration_sec: durationSec,
        views:        parseInt(item.statistics?.viewCount    || '0', 10),
        likes:        parseInt(item.statistics?.likeCount    || '0', 10),
        comments:     parseInt(item.statistics?.commentCount || '0', 10),
      };
    });

    res.json({ videos });
  } catch (e) {
    console.error('Videos fetch error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════
// ROUTE 7: /api/youtube/analytics — метрики видео
// ИСПРАВЛЕНИЕ 3: реальные данные из YouTube Analytics API
// ═══════════════════════════════════════════════════════
app.get('/api/youtube/analytics', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'No session' });

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid session' }); }

  const { video_id, channel_id, start_date, end_date } = req.query;

  if (!video_id) return res.status(400).json({ error: 'video_id required' });

  let accessToken = payload.access_token;
  if (!accessToken && payload.refresh_token) {
    try { accessToken = await refreshAccessToken(payload.refresh_token); }
    catch { return res.status(401).json({ error: 'Cannot refresh token' }); }
  }

  const channelId = channel_id || payload.channel_id;
  const endDate   = end_date   || new Date().toISOString().split('T')[0];
  const startDate = start_date || getDateDaysAgo(90);

  try {
    // ── Базовые метрики видео ─────────────────────────
    const metricsRes = await gFetch(
      `https://youtubeanalytics.googleapis.com/v2/reports` +
      `?ids=channel==${channelId}` +
      `&startDate=${startDate}` +
      `&endDate=${endDate}` +
      `&metrics=views,likes,comments,shares,estimatedMinutesWatched,averageViewDuration,averageViewPercentage,impressions,impressionClickThroughRate,subscribersGained` +
      `&dimensions=video` +
      `&filters=video==${video_id}` +
      `&sort=-views`,
      accessToken
    );

    // ── Retention curve (audience retention) ──────────
    let retentionData = null;
    try {
      const retRes = await gFetch(
        `https://youtubeanalytics.googleapis.com/v2/reports` +
        `?ids=channel==${channelId}` +
        `&startDate=${startDate}` +
        `&endDate=${endDate}` +
        `&metrics=audienceWatchRatio,relativeRetentionPerformance` +
        `&dimensions=elapsedVideoTimeRatio` +
        `&filters=video==${video_id}` +
        `&sort=elapsedVideoTimeRatio`,
        accessToken
      );
      retentionData = retRes;
    } catch (retErr) {
      console.warn('Retention fetch warning (non-fatal):', retErr.message);
    }

    // ── Shorts-specific: swipe data ───────────────────
    // Для Shorts: cardImpressions / cardClickRate как прокси для свайпов
    let shortsData = null;
    try {
      const shortsRes = await gFetch(
        `https://youtubeanalytics.googleapis.com/v2/reports` +
        `?ids=channel==${channelId}` +
        `&startDate=${startDate}` +
        `&endDate=${endDate}` +
        `&metrics=views,swipeUpImpressions,swipeUpClickRate` +
        `&dimensions=video` +
        `&filters=video==${video_id}`,
        accessToken
      );
      shortsData = shortsRes;
    } catch (shortsErr) {
      // swipeUpImpressions доступны только для Shorts в некоторых регионах
      console.warn('Shorts swipe data warning (non-fatal):', shortsErr.message);
    }

    // ── Парсим базовые метрики ─────────────────────────
    const rows       = metricsRes?.rows    || [];
    const headers    = metricsRes?.columnHeaders || [];
    const row        = rows[0] || [];

    const getMetric = (name) => {
      const idx = headers.findIndex(h => h.name === name);
      return idx >= 0 ? (row[idx] ?? null) : null;
    };

    const views                = getMetric('views');
    const likes                = getMetric('likes');
    const comments             = getMetric('comments');
    const shares               = getMetric('shares');
    const avgViewDurationSec   = getMetric('averageViewDuration');
    const avgViewPct           = getMetric('averageViewPercentage');   // % удержания 0–100
    const impressions          = getMetric('impressions');
    const ctr                  = getMetric('impressionClickThroughRate'); // 0–1, умножим на 100
    const subscribersGained    = getMetric('subscribersGained');
    const estMinutesWatched    = getMetric('estimatedMinutesWatched');

    // ── Парсим retention curve ────────────────────────
    let retentionCurve = null;
    if (retentionData?.rows?.length > 0) {
      const retHeaders = retentionData.columnHeaders || [];
      const ratioIdx   = retHeaders.findIndex(h => h.name === 'elapsedVideoTimeRatio');
      const watchIdx   = retHeaders.findIndex(h => h.name === 'audienceWatchRatio');

      retentionCurve = retentionData.rows
        .filter(r => ratioIdx >= 0 && watchIdx >= 0)
        .map(r => ({
          time_ratio:  parseFloat(r[ratioIdx] || 0),   // 0.0 – 1.0 (позиция в видео)
          watch_ratio: parseFloat(r[watchIdx] || 0),   // 0.0 – 1.0+ (аудитория)
        }));
    }

    // ── Парсим Shorts свайпы ──────────────────────────
    let swipeData = null;
    if (shortsData?.rows?.length > 0) {
      const sHeaders    = shortsData.columnHeaders || [];
      const sViewsIdx   = sHeaders.findIndex(h => h.name === 'views');
      const swipeImprIdx= sHeaders.findIndex(h => h.name === 'swipeUpImpressions');
      const swipeRateIdx= sHeaders.findIndex(h => h.name === 'swipeUpClickRate');
      const sRow        = shortsData.rows[0] || [];

      if (swipeImprIdx >= 0) {
        swipeData = {
          swipe_impressions: sRow[swipeImprIdx] || 0,
          swipe_rate:        sRow[swipeRateIdx] || 0,  // доля свайпнувших 0–1
        };
      }
    }

    // ── Формируем ответ ───────────────────────────────
    const analytics = {
      video_id,

      // Основные цифры
      views:              views,
      likes:              likes,
      comments:           comments,
      shares:             shares,
      subscribers_gained: subscribersGained,

      // Удержание
      avg_view_duration_sec: avgViewDurationSec,
      retention_pct:         avgViewPct,           // % от длины видео (0–100, может быть >100 для Shorts-лупов)

      // CTR
      impressions:           impressions,
      ctr_pct:               ctr != null ? parseFloat((ctr * 100).toFixed(2)) : null,

      // Дополнительно
      est_minutes_watched:   estMinutesWatched,

      // Кривая удержания (массив точек)
      retention_curve: retentionCurve,

      // Shorts-свайпы
      swipe_data: swipeData
        ? {
            // swipe_rate = 1 − viewed_ratio
            viewed_ratio:  parseFloat(((1 - swipeData.swipe_rate) * 100).toFixed(1)),
            swiped_ratio:  parseFloat((swipeData.swipe_rate * 100).toFixed(1)),
          }
        : null,

      // Мета
      date_range: { start: startDate, end: endDate },
    };

    res.json(analytics);

  } catch (e) {
    console.error('Analytics fetch error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════
// ROUTE 8: /api/youtube/channel-analytics — аналитика канала
// ═══════════════════════════════════════════════════════
app.get('/api/youtube/channel-analytics', async (req, res) => {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'No session' });

  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid session' }); }

  let accessToken = payload.access_token;
  if (!accessToken && payload.refresh_token) {
    try { accessToken = await refreshAccessToken(payload.refresh_token); }
    catch { return res.status(401).json({ error: 'Cannot refresh token' }); }
  }

  const channelId = req.query.channel_id || payload.channel_id;
  if (!channelId) return res.status(400).json({ error: 'channel_id required' });

  const endDate   = new Date().toISOString().split('T')[0];
  const startDate = getDateDaysAgo(30);

  try {
    // Общие метрики канала за 30 дней
    const channelRes = await gFetch(
      `https://youtubeanalytics.googleapis.com/v2/reports` +
      `?ids=channel==${channelId}` +
      `&startDate=${startDate}` +
      `&endDate=${endDate}` +
      `&metrics=views,likes,comments,shares,subscribersGained,subscribersLost,estimatedMinutesWatched,impressions,impressionClickThroughRate` +
      `&dimensions=day` +
      `&sort=day`,
      accessToken
    );

    const headers = channelRes?.columnHeaders || [];
    const rows    = channelRes?.rows || [];

    const getIdx = name => headers.findIndex(h => h.name === name);

    const viewsIdx    = getIdx('views');
    const subsGainIdx = getIdx('subscribersGained');
    const subsLostIdx = getIdx('subscribersLost');
    const ctrIdx      = getIdx('impressionClickThroughRate');
    const dayIdx      = getIdx('day');

    // Дневная разбивка просмотров
    const daily_views = rows.map(r => ({
      date:  r[dayIdx] || '',
      views: parseInt(r[viewsIdx] || 0, 10),
    }));

    // Суммарные за период
    const total_views   = daily_views.reduce((s, d) => s + d.views, 0);
    const total_subs_gained = rows.reduce((s, r) => s + parseInt(r[subsGainIdx] || 0, 10), 0);
    const total_subs_lost   = rows.reduce((s, r) => s + parseInt(r[subsLostIdx] || 0, 10), 0);
    const avg_ctr = rows.length > 0
      ? parseFloat((rows.reduce((s, r) => s + parseFloat(r[ctrIdx] || 0), 0) / rows.length * 100).toFixed(2))
      : 0;

    res.json({
      channel_id: channelId,
      date_range: { start: startDate, end: endDate },
      total_views,
      subscribers_gained: total_subs_gained,
      subscribers_lost:   total_subs_lost,
      net_subscribers:    total_subs_gained - total_subs_lost,
      avg_ctr_pct:        avg_ctr,
      daily_views,
    });

  } catch (e) {
    console.error('Channel analytics error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════
// ROUTE 9: /api/health — проверка работоспособности
// ═══════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({
    ok:      true,
    ts:      new Date().toISOString(),
    version: '2.0.0',
    scopes:  YOUTUBE_SCOPES.split(' '),
  });
});

// ═══════════════════════════════════════════════════════
// УТИЛИТЫ
// ═══════════════════════════════════════════════════════

/** ISO 8601 duration → секунды. Например PT15M33S → 933 */
function parseDurationToSeconds(duration) {
  if (!duration) return 0;
  const match = duration.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return 0;
  const h = parseInt(match[1] || 0, 10);
  const m = parseInt(match[2] || 0, 10);
  const s = parseInt(match[3] || 0, 10);
  return h * 3600 + m * 60 + s;
}

/** Дата N дней назад в формате YYYY-MM-DD */
function getDateDaysAgo(days) {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().split('T')[0];
}

// ═══════════════════════════════════════════════════════
// EXPORT для Vercel Serverless
// ═══════════════════════════════════════════════════════
export default app;
