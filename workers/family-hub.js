// family-hub Worker v1.0.0
// Single-file: REST API + embedded SPA
// Bindings needed: DB (D1 family-hub), PHOTOS (R2 family-hub-photos)

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function htmlResp(content) {
  return new Response(content, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 10000, hash: 'SHA-256' },
    key, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken(len = 24) {
  return Array.from(crypto.getRandomValues(new Uint8Array(len)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getUser(env, sessionToken) {
  if (!sessionToken) return null;
  try {
    return await env.DB.prepare(
      `SELECT u.* FROM sessions s JOIN users u ON s.user_id = u.id
       WHERE s.id = ? AND (s.expires_at IS NULL OR s.expires_at > CURRENT_TIMESTAMP)`
    ).bind(sessionToken).first();
  } catch { return null; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // Serve SPA for all non-API routes
    if (!path.startsWith('/api/')) {
      return htmlResp(getSPA());
    }

    // Auth: get session user
    const authHeader = request.headers.get('Authorization');
    const sessionToken = authHeader?.replace('Bearer ', '') || null;
    const user = await getUser(env, sessionToken);

    try {
      // ── AUTH (no token required) ──────────────────────────────────
      if (path === '/api/auth/redeem' && request.method === 'POST') {
        const { token, name, password } = await request.json();
        const existing = await env.DB.prepare(
          'SELECT * FROM users WHERE invite_token = ?'
        ).bind(token).first();
        if (!existing) return json({ error: 'Invalid invite link' }, 401);
        if (existing.password_hash) return json({ error: 'Already activated — please log in' }, 400);
        const salt = generateToken(16);
        const hash = await hashPassword(password, salt);
        const displayName = (name || existing.name).trim();
        await env.DB.prepare(
          'UPDATE users SET name = ?, password_hash = ?, invite_token = NULL WHERE id = ?'
        ).bind(displayName, `${salt}:${hash}`, existing.id).run();
        const sessionId = generateToken();
        await env.DB.prepare('INSERT INTO sessions (id, user_id) VALUES (?, ?)').bind(sessionId, existing.id).run();
        const updatedUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(existing.id).first();
        return json({ token: sessionId, user: sanitizeUser(updatedUser) });
      }

      if (path === '/api/auth/login' && request.method === 'POST') {
        const { name, password } = await request.json();
        const existing = await env.DB.prepare(
          'SELECT * FROM users WHERE LOWER(name) = LOWER(?)'
        ).bind(name.trim()).first();
        if (!existing || !existing.password_hash) return json({ error: 'Invalid name or password' }, 401);
        const [salt, hash] = existing.password_hash.split(':');
        const attempt = await hashPassword(password, salt);
        if (attempt !== hash) return json({ error: 'Invalid name or password' }, 401);
        const sessionId = generateToken();
        await env.DB.prepare('INSERT INTO sessions (id, user_id) VALUES (?, ?)').bind(sessionId, existing.id).run();
        return json({ token: sessionId, user: sanitizeUser(existing) });
      }

      if (path === '/api/auth/me' && request.method === 'GET') {
        if (!user) return json({ error: 'Unauthorized' }, 401);
        return json({ user: sanitizeUser(user) });
      }

      // ── ALL ROUTES BELOW REQUIRE AUTH ────────────────────────────
      if (!user) return json({ error: 'Unauthorized' }, 401);

      // ── USERS ─────────────────────────────────────────────────────
      if (path === '/api/users' && request.method === 'GET') {
        const users = await env.DB.prepare(
          'SELECT id, name, relationship, avatar_url, birthday FROM users ORDER BY name ASC'
        ).all();
        return json(users.results);
      }

      if (path === '/api/users/me' && request.method === 'PUT') {
        const { name, avatar_url, birthday } = await request.json();
        await env.DB.prepare(
          'UPDATE users SET name = COALESCE(?, name), avatar_url = COALESCE(?, avatar_url), birthday = COALESCE(?, birthday) WHERE id = ?'
        ).bind(name || null, avatar_url || null, birthday || null, user.id).run();
        const updated = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
        return json({ user: sanitizeUser(updated) });
      }

      // ── FEED / POSTS ──────────────────────────────────────────────
      if (path === '/api/posts' && request.method === 'GET') {
        const posts = await env.DB.prepare(`
          SELECT p.*, u.name as author_name, u.avatar_url as author_avatar,
            (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) as likes_count,
            (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id) as comments_count,
            (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id AND user_id = ?) as liked_by_me
          FROM posts p JOIN users u ON p.user_id = u.id
          ORDER BY p.created_at DESC LIMIT 50
        `).bind(user.id).all();
        return json(posts.results);
      }

      if (path === '/api/posts' && request.method === 'POST') {
        const { content, media_urls, post_type } = await request.json();
        const result = await env.DB.prepare(
          'INSERT INTO posts (user_id, content, media_urls, post_type) VALUES (?, ?, ?, ?) RETURNING *'
        ).bind(user.id, content || '', JSON.stringify(media_urls || []), post_type || 'post').first();
        return json({ ...result, author_name: user.name, author_avatar: user.avatar_url, likes_count: 0, comments_count: 0, liked_by_me: 0 });
      }

      const likeMatch = path.match(/^\/api\/posts\/(\d+)\/like$/);
      if (likeMatch && request.method === 'POST') {
        const postId = likeMatch[1];
        const ex = await env.DB.prepare('SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?').bind(postId, user.id).first();
        if (ex) {
          await env.DB.prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?').bind(postId, user.id).run();
          return json({ liked: false });
        }
        await env.DB.prepare('INSERT INTO post_likes (post_id, user_id) VALUES (?, ?)').bind(postId, user.id).run();
        return json({ liked: true });
      }

      const commentsMatch = path.match(/^\/api\/posts\/(\d+)\/comments$/);
      if (commentsMatch) {
        const postId = commentsMatch[1];
        if (request.method === 'GET') {
          const comments = await env.DB.prepare(
            'SELECT c.*, u.name as author_name FROM post_comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC'
          ).bind(postId).all();
          return json(comments.results);
        }
        if (request.method === 'POST') {
          const { content } = await request.json();
          const result = await env.DB.prepare(
            'INSERT INTO post_comments (post_id, user_id, content) VALUES (?, ?, ?) RETURNING *'
          ).bind(postId, user.id, content).first();
          return json({ ...result, author_name: user.name });
        }
      }

      // ── CHATS ─────────────────────────────────────────────────────
      if (path === '/api/chats' && request.method === 'GET') {
        const chats = await env.DB.prepare(`
          SELECT c.*,
            (SELECT m.content FROM messages m WHERE m.chat_id = c.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
            (SELECT u2.name FROM messages m2 JOIN users u2 ON m2.user_id = u2.id WHERE m2.chat_id = c.id ORDER BY m2.created_at DESC LIMIT 1) as last_author,
            (SELECT m3.created_at FROM messages m3 WHERE m3.chat_id = c.id ORDER BY m3.created_at DESC LIMIT 1) as last_at
          FROM chats c
          JOIN chat_members cm ON c.id = cm.chat_id
          WHERE cm.user_id = ?
          ORDER BY last_at DESC
        `).bind(user.id).all();
        return json(chats.results);
      }

      if (path === '/api/chats' && request.method === 'POST') {
        const { name, chat_type, member_ids } = await request.json();
        const chat = await env.DB.prepare(
          'INSERT INTO chats (name, chat_type, created_by) VALUES (?, ?, ?) RETURNING *'
        ).bind(name, chat_type || 'group', user.id).first();
        const members = [...new Set([user.id, ...(member_ids || [])])];
        for (const mid of members) {
          await env.DB.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)').bind(chat.id, mid).run();
        }
        return json(chat);
      }

      const chatMsgMatch = path.match(/^\/api\/chats\/(\d+)\/messages$/);
      if (chatMsgMatch) {
        const chatId = chatMsgMatch[1];
        const isMember = await env.DB.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').bind(chatId, user.id).first();
        if (!isMember) return json({ error: 'Not a member of this chat' }, 403);
        if (request.method === 'GET') {
          const msgs = await env.DB.prepare(
            'SELECT m.*, u.name as author_name FROM messages m JOIN users u ON m.user_id = u.id WHERE m.chat_id = ? ORDER BY m.created_at ASC LIMIT 200'
          ).bind(chatId).all();
          return json(msgs.results);
        }
        if (request.method === 'POST') {
          const { content } = await request.json();
          const result = await env.DB.prepare(
            'INSERT INTO messages (chat_id, user_id, content) VALUES (?, ?, ?) RETURNING *'
          ).bind(chatId, user.id, content).first();
          return json({ ...result, author_name: user.name });
        }
      }

      // ── BIRTHDAYS ─────────────────────────────────────────────────
      if (path === '/api/birthdays' && request.method === 'GET') {
        const bdays = await env.DB.prepare(
          `SELECT id, name, relationship, birthday FROM users WHERE birthday IS NOT NULL ORDER BY strftime('%m-%d', birthday) ASC`
        ).all();
        return json(bdays.results);
      }

      // ── GIFT LISTS ────────────────────────────────────────────────
      if (path === '/api/gifts' && request.method === 'GET') {
        const userId = url.searchParams.get('user_id') || user.id;
        const gifts = await env.DB.prepare(`
          SELECT g.*, u.name as claimed_by_name
          FROM gift_lists g
          LEFT JOIN users u ON g.claimed_by = u.id
          WHERE g.user_id = ?
          ORDER BY g.event_type, g.created_at DESC
        `).bind(userId).all();
        // Hide who claimed if it's the user's own list (so no spoilers)
        const results = gifts.results.map(g => {
          if (parseInt(userId) === user.id && g.claimed_by) {
            return { ...g, claimed_by: 'someone', claimed_by_name: 'Someone ✓' };
          }
          return g;
        });
        return json(results);
      }

      if (path === '/api/gifts' && request.method === 'POST') {
        const { title, description, url: gUrl, price, event_type } = await request.json();
        const result = await env.DB.prepare(
          'INSERT INTO gift_lists (user_id, title, description, url, price, event_type) VALUES (?, ?, ?, ?, ?, ?) RETURNING *'
        ).bind(user.id, title, description || null, gUrl || null, price || null, event_type || 'birthday').first();
        return json(result);
      }

      const claimMatch = path.match(/^\/api\/gifts\/(\d+)\/claim$/);
      if (claimMatch && request.method === 'POST') {
        const giftId = claimMatch[1];
        const gift = await env.DB.prepare('SELECT * FROM gift_lists WHERE id = ?').bind(giftId).first();
        if (!gift) return json({ error: 'Not found' }, 404);
        if (gift.user_id === user.id) return json({ error: "Can't claim your own gift idea" }, 400);
        const newClaimed = gift.claimed_by ? null : user.id;
        await env.DB.prepare('UPDATE gift_lists SET claimed_by = ? WHERE id = ?').bind(newClaimed, giftId).run();
        return json({ claimed: !!newClaimed });
      }

      const deleteGiftMatch = path.match(/^\/api\/gifts\/(\d+)$/);
      if (deleteGiftMatch && request.method === 'DELETE') {
        const giftId = deleteGiftMatch[1];
        await env.DB.prepare('DELETE FROM gift_lists WHERE id = ? AND user_id = ?').bind(giftId, user.id).run();
        return json({ ok: true });
      }

      // ── KK DRAW ───────────────────────────────────────────────────
      if (path === '/api/kk' && request.method === 'GET') {
        const draws = await env.DB.prepare('SELECT * FROM kk_draws ORDER BY year DESC').all();
        return json(draws.results);
      }

      if (path === '/api/kk' && request.method === 'POST') {
        const { year, budget } = await request.json();
        const existing = await env.DB.prepare('SELECT id FROM kk_draws WHERE year = ?').bind(year).first();
        if (existing) return json({ error: `KK draw for ${year} already exists` }, 400);
        const draw = await env.DB.prepare(
          'INSERT INTO kk_draws (year, budget) VALUES (?, ?) RETURNING *'
        ).bind(year, budget || null).first();
        return json(draw);
      }

      const drawMatch = path.match(/^\/api\/kk\/(\d+)\/draw$/);
      if (drawMatch && request.method === 'POST') {
        const drawId = drawMatch[1];
        const { participant_ids } = await request.json();
        if (participant_ids.length < 3) return json({ error: 'Need at least 3 participants' }, 400);
        // Fisher-Yates shuffle, ensure no self-gifting
        const ids = [...participant_ids];
        let shuffled;
        let attempts = 0;
        do {
          shuffled = [...ids].sort(() => Math.random() - 0.5);
          attempts++;
        } while (shuffled.some((id, i) => id === ids[i]) && attempts < 100);
        await env.DB.prepare('DELETE FROM kk_assignments WHERE draw_id = ?').bind(drawId).run();
        for (let i = 0; i < shuffled.length; i++) {
          const giver = shuffled[i];
          const receiver = shuffled[(i + 1) % shuffled.length];
          await env.DB.prepare(
            'INSERT INTO kk_assignments (draw_id, giver_id, receiver_id) VALUES (?, ?, ?)'
          ).bind(drawId, giver, receiver).run();
        }
        await env.DB.prepare("UPDATE kk_draws SET status = 'drawn', drawn_at = CURRENT_TIMESTAMP WHERE id = ?").bind(drawId).run();
        return json({ ok: true, count: shuffled.length });
      }

      const myAssignMatch = path.match(/^\/api\/kk\/(\d+)\/my-assignment$/);
      if (myAssignMatch && request.method === 'GET') {
        const drawId = myAssignMatch[1];
        const assignment = await env.DB.prepare(`
          SELECT ka.*, u.name as receiver_name, u.birthday as receiver_birthday
          FROM kk_assignments ka JOIN users u ON ka.receiver_id = u.id
          WHERE ka.draw_id = ? AND ka.giver_id = ?
        `).bind(drawId, user.id).first();
        return json(assignment || null);
      }

      // ── EXPENSES ──────────────────────────────────────────────────
      if (path === '/api/expenses' && request.method === 'GET') {
        const expenses = await env.DB.prepare(`
          SELECT e.*, u.name as paid_by_name,
            (SELECT SUM(CASE WHEN es.user_id = ? AND es.paid = 0 THEN es.amount ELSE 0 END)
             FROM expense_splits es WHERE es.expense_id = e.id) as i_owe,
            (SELECT GROUP_CONCAT(u2.name || ':' || es2.amount || ':' || es2.paid, '|')
             FROM expense_splits es2 JOIN users u2 ON es2.user_id = u2.id WHERE es2.expense_id = e.id) as splits_raw
          FROM expenses e JOIN users u ON e.paid_by = u.id
          ORDER BY e.created_at DESC
        `).bind(user.id).all();
        return json(expenses.results);
      }

      if (path === '/api/expenses' && request.method === 'POST') {
        const { description, total_amount, category, split_with } = await request.json();
        const expense = await env.DB.prepare(
          'INSERT INTO expenses (description, total_amount, paid_by, category) VALUES (?, ?, ?, ?) RETURNING *'
        ).bind(description, total_amount, user.id, category || 'general').first();
        const allPeople = [...new Set([user.id, ...(split_with || [])])];
        const share = +(total_amount / allPeople.length).toFixed(2);
        for (const uid of allPeople) {
          await env.DB.prepare(
            'INSERT INTO expense_splits (expense_id, user_id, amount, paid) VALUES (?, ?, ?, ?)'
          ).bind(expense.id, uid, share, uid === user.id ? 1 : 0).run();
        }
        return json(expense);
      }

      const settleMatch = path.match(/^\/api\/expenses\/(\d+)\/settle$/);
      if (settleMatch && request.method === 'POST') {
        const expenseId = settleMatch[1];
        await env.DB.prepare('UPDATE expense_splits SET paid = 1 WHERE expense_id = ? AND user_id = ?').bind(expenseId, user.id).run();
        return json({ ok: true });
      }

      return json({ error: 'Route not found' }, 404);

    } catch (e) {
      return json({ error: e.message, stack: e.stack }, 500);
    }
  }
};

function sanitizeUser(u) {
  if (!u) return null;
  const { password_hash, invite_token, ...safe } = u;
  return safe;
}

// ── EMBEDDED SPA ──────────────────────────────────────────────────────────────
function getSPA() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#FF6B6B">
<title>Family Hub 🏠</title>
<style>
  :root {
    --primary: #FF6B6B;
    --primary-dark: #e05555;
    --accent: #FFE66D;
    --bg: #FFF8F3;
    --card: #FFFFFF;
    --text: #2D2D2D;
    --muted: #888;
    --border: #F0E8E8;
    --nav-height: 64px;
    --safe-bottom: env(safe-area-inset-bottom, 0px);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100dvh; }
  #app { max-width: 480px; margin: 0 auto; position: relative; min-height: 100dvh; }

  /* AUTH */
  .auth-screen { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100dvh; padding: 24px; background: linear-gradient(135deg, #FF6B6B 0%, #FF8E53 100%); }
  .auth-logo { font-size: 64px; margin-bottom: 8px; }
  .auth-title { font-size: 28px; font-weight: 800; color: white; margin-bottom: 4px; }
  .auth-sub { color: rgba(255,255,255,0.85); font-size: 15px; margin-bottom: 32px; text-align: center; }
  .auth-card { background: white; border-radius: 20px; padding: 24px; width: 100%; max-width: 360px; box-shadow: 0 8px 32px rgba(0,0,0,0.15); }
  .auth-tabs { display: flex; margin-bottom: 20px; border-radius: 10px; overflow: hidden; border: 2px solid var(--border); }
  .auth-tab { flex: 1; padding: 10px; text-align: center; font-size: 14px; font-weight: 600; cursor: pointer; background: none; border: none; color: var(--muted); }
  .auth-tab.active { background: var(--primary); color: white; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 13px; font-weight: 600; color: var(--muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
  .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 12px 14px; border: 2px solid var(--border); border-radius: 12px; font-size: 15px; outline: none; transition: border-color 0.2s; font-family: inherit; }
  .form-group input:focus, .form-group select:focus, .form-group textarea:focus { border-color: var(--primary); }
  .btn { width: 100%; padding: 14px; background: var(--primary); color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 700; cursor: pointer; transition: background 0.2s; }
  .btn:hover { background: var(--primary-dark); }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
  .btn-ghost { background: transparent; color: var(--primary); border: 2px solid var(--primary); }
  .btn-ghost:hover { background: var(--primary); color: white; }
  .btn-sm { padding: 8px 14px; font-size: 13px; width: auto; border-radius: 8px; }
  .error-msg { color: #e74c3c; font-size: 13px; margin-top: 8px; padding: 8px 12px; background: #ffeaea; border-radius: 8px; }

  /* MAIN APP */
  .main-app { display: none; flex-direction: column; min-height: 100dvh; }
  .main-app.visible { display: flex; }
  .header { background: var(--primary); color: white; padding: 16px 16px 12px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 10; }
  .header-title { font-size: 20px; font-weight: 800; }
  .header-sub { font-size: 13px; opacity: 0.85; }
  .header-avatar { width: 36px; height: 36px; border-radius: 50%; background: rgba(255,255,255,0.3); display: flex; align-items: center; justify-content: center; font-size: 18px; cursor: pointer; overflow: hidden; }
  .header-avatar img { width: 100%; height: 100%; object-fit: cover; }
  .content { flex: 1; overflow-y: auto; padding-bottom: calc(var(--nav-height) + var(--safe-bottom) + 16px); }
  .bottom-nav { position: fixed; bottom: 0; left: 50%; transform: translateX(-50%); width: 100%; max-width: 480px; height: calc(var(--nav-height) + var(--safe-bottom)); background: white; border-top: 1px solid var(--border); display: flex; padding-bottom: var(--safe-bottom); z-index: 10; box-shadow: 0 -4px 20px rgba(0,0,0,0.08); }
  .nav-item { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 3px; cursor: pointer; font-size: 10px; font-weight: 600; color: var(--muted); transition: color 0.2s; border: none; background: none; padding: 4px 0; }
  .nav-item.active { color: var(--primary); }
  .nav-icon { font-size: 22px; line-height: 1; }

  /* TABS */
  .screen { display: none; animation: fadeIn 0.2s ease; }
  .screen.active { display: block; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

  /* CARDS */
  .card { background: var(--card); border-radius: 16px; padding: 16px; margin: 12px 12px 0; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }
  .card + .card { margin-top: 10px; }
  .section-header { padding: 16px 16px 8px; display: flex; justify-content: space-between; align-items: center; }
  .section-title { font-size: 16px; font-weight: 700; }
  .badge { background: var(--primary); color: white; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 20px; }

  /* FEED */
  .post-card { background: var(--card); border-radius: 16px; margin: 12px 12px 0; overflow: hidden; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }
  .post-header { display: flex; align-items: center; gap: 10px; padding: 14px 14px 10px; }
  .post-avatar { width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, var(--primary), #FF8E53); display: flex; align-items: center; justify-content: center; font-size: 18px; font-weight: 700; color: white; flex-shrink: 0; overflow: hidden; }
  .post-avatar img { width: 100%; height: 100%; object-fit: cover; }
  .post-author { font-size: 15px; font-weight: 700; }
  .post-time { font-size: 12px; color: var(--muted); }
  .post-content { padding: 0 14px 10px; font-size: 15px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
  .post-image { width: 100%; max-height: 400px; object-fit: cover; }
  .post-actions { display: flex; gap: 16px; padding: 10px 14px 14px; border-top: 1px solid var(--border); }
  .post-action { display: flex; align-items: center; gap: 5px; font-size: 13px; font-weight: 600; color: var(--muted); cursor: pointer; background: none; border: none; }
  .post-action.liked { color: var(--primary); }
  .post-action:hover { color: var(--primary); }
  .post-comments { padding: 0 14px 14px; border-top: 1px solid var(--border); }
  .comment { display: flex; gap: 8px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
  .comment:last-child { border-bottom: none; }
  .comment-author { font-weight: 700; color: var(--primary); flex-shrink: 0; }
  .comment-input-row { display: flex; gap: 8px; padding-top: 8px; }
  .comment-input-row input { flex: 1; padding: 8px 12px; border: 2px solid var(--border); border-radius: 20px; font-size: 14px; outline: none; font-family: inherit; }
  .comment-input-row input:focus { border-color: var(--primary); }
  .comment-send { background: var(--primary); color: white; border: none; border-radius: 50%; width: 36px; height: 36px; font-size: 16px; cursor: pointer; flex-shrink: 0; }

  /* COMPOSE */
  .compose-bar { background: white; border-top: 1px solid var(--border); padding: 12px; display: flex; gap: 10px; align-items: center; margin: 12px 12px 0; border-radius: 16px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); cursor: pointer; }
  .compose-avatar { width: 36px; height: 36px; border-radius: 50%; background: linear-gradient(135deg, var(--primary), #FF8E53); display: flex; align-items: center; justify-content: center; font-size: 16px; color: white; flex-shrink: 0; }
  .compose-placeholder { color: var(--muted); font-size: 15px; }

  /* MODAL */
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 100; display: none; align-items: flex-end; }
  .modal-overlay.open { display: flex; }
  .modal { background: white; border-radius: 24px 24px 0 0; padding: 24px; width: 100%; max-height: 90vh; overflow-y: auto; animation: slideUp 0.3s ease; }
  @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
  .modal-handle { width: 40px; height: 4px; background: var(--border); border-radius: 2px; margin: 0 auto 16px; }
  .modal-title { font-size: 18px; font-weight: 800; margin-bottom: 16px; }
  .modal-close { position: absolute; right: 20px; top: 20px; background: var(--border); border: none; border-radius: 50%; width: 32px; height: 32px; font-size: 18px; cursor: pointer; display: flex; align-items: center; justify-content: center; color: var(--muted); }

  /* CHATS */
  .chat-item { display: flex; align-items: center; gap: 12px; padding: 14px 16px; cursor: pointer; border-bottom: 1px solid var(--border); transition: background 0.15s; }
  .chat-item:hover { background: var(--bg); }
  .chat-icon { width: 48px; height: 48px; border-radius: 50%; background: linear-gradient(135deg, #A29BFE, #6C5CE7); display: flex; align-items: center; justify-content: center; font-size: 22px; flex-shrink: 0; }
  .chat-icon.dm { background: linear-gradient(135deg, #74B9FF, #0984E3); }
  .chat-name { font-size: 15px; font-weight: 700; }
  .chat-preview { font-size: 13px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 220px; }
  .chat-time { font-size: 12px; color: var(--muted); margin-left: auto; }

  /* CHAT VIEW */
  .chat-view { display: none; position: fixed; inset: 0; background: var(--bg); z-index: 50; flex-direction: column; max-width: 480px; left: 50%; transform: translateX(-50%); }
  .chat-view.open { display: flex; }
  .chat-header { background: var(--primary); color: white; padding: 16px; display: flex; align-items: center; gap: 12px; }
  .back-btn { background: none; border: none; color: white; font-size: 22px; cursor: pointer; line-height: 1; }
  .chat-messages { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 8px; }
  .msg { max-width: 75%; padding: 10px 14px; border-radius: 18px; font-size: 14px; line-height: 1.4; word-break: break-word; }
  .msg.mine { background: var(--primary); color: white; align-self: flex-end; border-bottom-right-radius: 4px; }
  .msg.theirs { background: white; color: var(--text); align-self: flex-start; border-bottom-left-radius: 4px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
  .msg-author { font-size: 11px; font-weight: 700; margin-bottom: 2px; opacity: 0.7; }
  .msg-time { font-size: 10px; margin-top: 2px; opacity: 0.65; text-align: right; }
  .chat-input-bar { padding: 12px; background: white; border-top: 1px solid var(--border); display: flex; gap: 10px; align-items: flex-end; padding-bottom: max(12px, env(safe-area-inset-bottom, 12px)); }
  .chat-input { flex: 1; padding: 10px 14px; border: 2px solid var(--border); border-radius: 20px; font-size: 15px; outline: none; resize: none; max-height: 100px; font-family: inherit; line-height: 1.4; }
  .chat-input:focus { border-color: var(--primary); }
  .send-btn { background: var(--primary); color: white; border: none; border-radius: 50%; width: 40px; height: 40px; font-size: 18px; cursor: pointer; flex-shrink: 0; display: flex; align-items: center; justify-content: center; }

  /* BIRTHDAYS */
  .birthday-item { display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }
  .birthday-item:last-child { border-bottom: none; }
  .birthday-avatar { width: 44px; height: 44px; border-radius: 50%; background: linear-gradient(135deg, var(--primary), #FF8E53); display: flex; align-items: center; justify-content: center; font-size: 20px; color: white; font-weight: 700; flex-shrink: 0; }
  .birthday-name { font-size: 15px; font-weight: 700; }
  .birthday-date { font-size: 13px; color: var(--muted); }
  .birthday-days { margin-left: auto; text-align: right; }
  .days-number { font-size: 20px; font-weight: 800; color: var(--primary); }
  .days-label { font-size: 11px; color: var(--muted); }
  .days-today { font-size: 24px; }

  /* WISHLISTS */
  .gift-item { display: flex; align-items: flex-start; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--border); }
  .gift-item:last-child { border-bottom: none; }
  .gift-claimed { opacity: 0.5; text-decoration: line-through; }
  .gift-title { font-size: 14px; font-weight: 600; }
  .gift-meta { font-size: 12px; color: var(--muted); }

  /* KK */
  .kk-card { background: linear-gradient(135deg, #2D3436, #636E72); color: white; border-radius: 20px; padding: 20px; margin: 12px; text-align: center; }
  .kk-year { font-size: 13px; font-weight: 600; opacity: 0.7; margin-bottom: 4px; }
  .kk-receiver { font-size: 32px; font-weight: 900; margin: 8px 0; }
  .kk-budget { font-size: 14px; opacity: 0.8; }

  /* EXPENSES */
  .expense-item { padding: 12px 0; border-bottom: 1px solid var(--border); }
  .expense-item:last-child { border-bottom: none; }
  .expense-desc { font-size: 15px; font-weight: 600; }
  .expense-meta { font-size: 13px; color: var(--muted); margin-top: 2px; }
  .expense-amount { font-size: 18px; font-weight: 800; color: var(--primary); }
  .expense-owe { font-size: 12px; color: #e17055; font-weight: 600; }
  .expense-settled { font-size: 12px; color: #00b894; font-weight: 600; }

  /* PEOPLE PICKER */
  .person-chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 20px; border: 2px solid var(--border); cursor: pointer; font-size: 13px; font-weight: 600; margin: 4px; transition: all 0.15s; }
  .person-chip.selected { background: var(--primary); color: white; border-color: var(--primary); }

  /* EMPTY STATES */
  .empty { text-align: center; padding: 48px 24px; color: var(--muted); }
  .empty-icon { font-size: 48px; margin-bottom: 12px; }
  .empty-text { font-size: 16px; font-weight: 600; }
  .empty-sub { font-size: 14px; margin-top: 4px; }

  /* FAB */
  .fab { position: fixed; bottom: calc(var(--nav-height) + var(--safe-bottom) + 16px); right: max(16px, calc(50vw - 240px + 16px)); background: var(--primary); color: white; border: none; border-radius: 50%; width: 56px; height: 56px; font-size: 24px; cursor: pointer; box-shadow: 0 4px 20px rgba(255,107,107,0.5); z-index: 20; display: none; align-items: center; justify-content: center; }
  .fab.visible { display: flex; }

  /* TOAST */
  .toast { position: fixed; top: 80px; left: 50%; transform: translateX(-50%); background: #2D2D2D; color: white; padding: 10px 20px; border-radius: 20px; font-size: 14px; font-weight: 600; z-index: 200; opacity: 0; transition: opacity 0.3s; pointer-events: none; white-space: nowrap; }
  .toast.show { opacity: 1; }

  /* PROFILE PILL */
  .profile-row { display: flex; align-items: center; gap: 12px; padding: 16px; background: white; border-radius: 16px; margin: 12px 12px 0; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }
  .profile-big-avatar { width: 56px; height: 56px; border-radius: 50%; background: linear-gradient(135deg, var(--primary), #FF8E53); display: flex; align-items: center; justify-content: center; font-size: 26px; color: white; font-weight: 700; flex-shrink: 0; overflow: hidden; }
  .profile-big-avatar img { width: 100%; height: 100%; object-fit: cover; }
  .profile-name { font-size: 17px; font-weight: 800; }
  .profile-rel { font-size: 13px; color: var(--muted); }

  /* LOADING */
  .loading { display: flex; align-items: center; justify-content: center; padding: 32px; color: var(--muted); font-size: 14px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .spinner { width: 24px; height: 24px; border: 3px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.7s linear infinite; margin-right: 10px; }
</style>
</head>
<body>
<div id="app">

  <!-- AUTH SCREEN -->
  <div class="auth-screen" id="authScreen">
    <div class="auth-logo">🏠</div>
    <div class="auth-title">Family Hub</div>
    <div class="auth-sub">Your family's private little corner of the internet</div>
    <div class="auth-card">
      <div class="auth-tabs">
        <button class="auth-tab active" id="loginTab" onclick="showAuthTab('login')">Log In</button>
        <button class="auth-tab" id="inviteTab" onclick="showAuthTab('invite')">Join with Link</button>
      </div>

      <!-- LOGIN FORM -->
      <div id="loginForm">
        <div class="form-group"><label>Your Name</label><input type="text" id="loginName" placeholder="e.g. Mona" autocomplete="username"></div>
        <div class="form-group"><label>Password</label><input type="password" id="loginPass" placeholder="Your password" autocomplete="current-password"></div>
        <button class="btn" onclick="doLogin()">Log In 👋</button>
        <div id="loginError" class="error-msg" style="display:none"></div>
      </div>

      <!-- INVITE FORM -->
      <div id="inviteForm" style="display:none">
        <div class="form-group"><label>Invite Token</label><input type="text" id="inviteToken" placeholder="Paste your invite token"></div>
        <div class="form-group"><label>Your Name (or keep as-is)</label><input type="text" id="inviteName" placeholder="Your name"></div>
        <div class="form-group"><label>Choose a Password</label><input type="password" id="invitePass" placeholder="Choose a password" autocomplete="new-password"></div>
        <button class="btn" onclick="doRedeem()">Join Family Hub 🎉</button>
        <div id="inviteError" class="error-msg" style="display:none"></div>
      </div>
    </div>
  </div>

  <!-- MAIN APP -->
  <div class="main-app" id="mainApp">
    <div class="header">
      <div>
        <div class="header-title" id="headerTitle">Family Hub 🏠</div>
        <div class="header-sub" id="headerSub">Everyone's here</div>
      </div>
      <div class="header-avatar" onclick="showProfile()" id="headerAvatar">👤</div>
    </div>

    <div class="content" id="mainContent">

      <!-- FEED TAB -->
      <div class="screen active" id="screenFeed">
        <div class="compose-bar" onclick="openModal('composeModal')">
          <div class="compose-avatar" id="composeAvatar">✨</div>
          <div class="compose-placeholder">What's happening in the family?</div>
        </div>
        <div id="feedList"><div class="loading"><div class="spinner"></div>Loading...</div></div>
      </div>

      <!-- CHATS TAB -->
      <div class="screen" id="screenChats">
        <div id="chatList"><div class="loading"><div class="spinner"></div>Loading...</div></div>
      </div>

      <!-- BIRTHDAYS TAB -->
      <div class="screen" id="screenBirthdays">
        <div class="card" id="birthdayList"><div class="loading"><div class="spinner"></div>Loading...</div></div>
        <div class="section-header"><span class="section-title">🎁 Wish Lists</span></div>
        <div class="card" style="padding:0" id="wishlistPicker">
          <div style="padding:14px 16px; border-bottom:1px solid var(--border)">
            <select class="form-group" id="wishlistUser" onchange="loadGifts(this.value)" style="width:100%;padding:8px 12px;border:none;font-size:14px;font-weight:600;outline:none;background:none">
              <option value="">— pick a family member —</option>
            </select>
          </div>
          <div id="giftList" style="padding:0 16px"></div>
        </div>
        <div id="myWishlistSection" style="margin-top:0"></div>
      </div>

      <!-- KK TAB -->
      <div class="screen" id="screenKK">
        <div id="kkContent"><div class="loading"><div class="spinner"></div>Loading...</div></div>
      </div>

      <!-- EXPENSES TAB -->
      <div class="screen" id="screenExpenses">
        <div class="card" id="expenseList"><div class="loading"><div class="spinner"></div>Loading...</div></div>
      </div>

    </div>

    <!-- BOTTOM NAV -->
    <nav class="bottom-nav">
      <button class="nav-item active" id="navFeed" onclick="switchTab('Feed')"><span class="nav-icon">🏠</span>Feed</button>
      <button class="nav-item" id="navChats" onclick="switchTab('Chats')"><span class="nav-icon">💬</span>Chats</button>
      <button class="nav-item" id="navBirthdays" onclick="switchTab('Birthdays')"><span class="nav-icon">🎂</span>Birthdays</button>
      <button class="nav-item" id="navKK" onclick="switchTab('KK')"><span class="nav-icon">🎅</span>KK</button>
      <button class="nav-item" id="navExpenses" onclick="switchTab('Expenses')"><span class="nav-icon">💸</span>Expenses</button>
    </nav>

    <!-- FAB -->
    <button class="fab" id="fab" onclick="onFabClick()">+</button>
  </div>

  <!-- TOAST -->
  <div class="toast" id="toast"></div>

  <!-- CHAT VIEW (full screen overlay) -->
  <div class="chat-view" id="chatView">
    <div class="chat-header">
      <button class="back-btn" onclick="closeChat()">←</button>
      <div>
        <div style="font-weight:800;font-size:16px" id="chatViewName">Chat</div>
        <div style="font-size:12px;opacity:0.8" id="chatViewType">Group</div>
      </div>
    </div>
    <div class="chat-messages" id="chatMessages"></div>
    <div class="chat-input-bar">
      <textarea class="chat-input" id="chatInputField" placeholder="Message..." rows="1"
        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage()}"
        oninput="this.style.height='auto';this.style.height=this.scrollHeight+'px'"></textarea>
      <button class="send-btn" onclick="sendMessage()">→</button>
    </div>
  </div>

  <!-- MODALS -->
  <!-- Compose Post -->
  <div class="modal-overlay" id="composeModal" onclick="if(event.target===this)closeModal('composeModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <div class="modal-title">✍️ New Post</div>
      <button class="modal-close" onclick="closeModal('composeModal')">×</button>
      <div class="form-group"><textarea id="postContent" placeholder="What's happening? 👶📸🎉" rows="4" style="resize:none"></textarea></div>
      <div class="form-group"><label>Photo URL (optional)</label><input type="url" id="postImageUrl" placeholder="https://..."></div>
      <div class="form-group"><label>Post type</label>
        <select id="postType"><option value="post">📝 General</option><option value="photo">📸 Photo / Baby spam</option><option value="milestone">🎉 Milestone</option><option value="holiday">✈️ Holiday</option></select>
      </div>
      <button class="btn" onclick="submitPost()">Post it! 🚀</button>
    </div>
  </div>

  <!-- New Chat -->
  <div class="modal-overlay" id="newChatModal" onclick="if(event.target===this)closeModal('newChatModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <div class="modal-title">💬 New Chat</div>
      <button class="modal-close" onclick="closeModal('newChatModal')">×</button>
      <div class="form-group"><label>Chat Name</label><input type="text" id="newChatName" placeholder="e.g. Sisters ❤️"></div>
      <div class="form-group"><label>Type</label>
        <select id="newChatType"><option value="group">👨‍👩‍👧 Group</option><option value="direct">👤 Private (1:1)</option></select>
      </div>
      <div class="form-group"><label>Add Family Members</label>
        <div id="chatMemberPicker"></div>
      </div>
      <button class="btn" onclick="createChat()">Start Chat 💬</button>
    </div>
  </div>

  <!-- Add Gift -->
  <div class="modal-overlay" id="addGiftModal" onclick="if(event.target===this)closeModal('addGiftModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <div class="modal-title">🎁 Add to Wish List</div>
      <button class="modal-close" onclick="closeModal('addGiftModal')">×</button>
      <div class="form-group"><label>What do you want?</label><input type="text" id="giftTitle" placeholder="e.g. Cozy jumper, size M"></div>
      <div class="form-group"><label>Notes (optional)</label><input type="text" id="giftDesc" placeholder="Colour, brand, anything helpful"></div>
      <div class="form-group"><label>Link (optional)</label><input type="url" id="giftUrl" placeholder="https://..."></div>
      <div class="form-group"><label>Price (€ approx)</label><input type="number" id="giftPrice" placeholder="30"></div>
      <div class="form-group"><label>For</label>
        <select id="giftEvent"><option value="birthday">🎂 Birthday</option><option value="christmas">🎄 Christmas</option><option value="general">🎁 General</option></select>
      </div>
      <button class="btn" onclick="submitGift()">Add to List 🎁</button>
    </div>
  </div>

  <!-- KK Draw -->
  <div class="modal-overlay" id="kkModal" onclick="if(event.target===this)closeModal('kkModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <div class="modal-title">🎅 Set Up KK Draw</div>
      <button class="modal-close" onclick="closeModal('kkModal')">×</button>
      <div class="form-group"><label>Year</label><input type="number" id="kkYear" value="2026"></div>
      <div class="form-group"><label>Budget (€)</label><input type="number" id="kkBudget" placeholder="e.g. 50"></div>
      <button class="btn" onclick="createKKDraw()">Create Draw 🎄</button>
    </div>
  </div>

  <!-- KK Participants -->
  <div class="modal-overlay" id="kkDrawModal" onclick="if(event.target===this)closeModal('kkDrawModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <div class="modal-title">🎁 Draw Names</div>
      <button class="modal-close" onclick="closeModal('kkDrawModal')">×</button>
      <div class="form-group"><label>Who's in this year's KK?</label>
        <div id="kkParticipantPicker"></div>
      </div>
      <button class="btn" onclick="runKKDraw()">Draw Names! 🎲</button>
    </div>
  </div>

  <!-- Add Expense -->
  <div class="modal-overlay" id="addExpenseModal" onclick="if(event.target===this)closeModal('addExpenseModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <div class="modal-title">💸 Add Expense</div>
      <button class="modal-close" onclick="closeModal('addExpenseModal')">×</button>
      <div class="form-group"><label>What for?</label><input type="text" id="expenseDesc" placeholder="e.g. Car insurance, Mum's birthday dinner"></div>
      <div class="form-group"><label>Total Amount (€)</label><input type="number" id="expenseAmount" placeholder="100"></div>
      <div class="form-group"><label>Category</label>
        <select id="expenseCategory">
          <option value="presents">🎁 Presents</option>
          <option value="insurance">🛡️ Insurance</option>
          <option value="holiday">✈️ Holiday</option>
          <option value="food">🍽️ Food / Dinner</option>
          <option value="general">📋 General</option>
        </select>
      </div>
      <div class="form-group"><label>Split with</label>
        <div id="expenseSplitPicker"></div>
      </div>
      <button class="btn" onclick="submitExpense()">Add Expense 💸</button>
    </div>
  </div>

</div><!-- #app -->

<script>
// ── STATE ──────────────────────────────────────────────────────────────────
let token = localStorage.getItem('fh_token');
let me = null;
let allUsers = [];
let currentTab = 'Feed';
let currentChatId = null;
let currentKKDrawId = null;
const API = '';

// ── BOOT ───────────────────────────────────────────────────────────────────
async function boot() {
  // Check URL for invite token
  const params = new URLSearchParams(location.search);
  const inviteParam = params.get('invite');
  if (inviteParam) {
    showAuthTab('invite');
    document.getElementById('inviteToken').value = inviteParam;
    history.replaceState({}, '', '/');
  }

  if (token) {
    try {
      const res = await api('/api/auth/me');
      if (res.user) {
        me = res.user;
        showApp();
        return;
      }
    } catch {}
    localStorage.removeItem('fh_token');
    token = null;
  }
  document.getElementById('authScreen').style.display = 'flex';
}

// ── API HELPER ─────────────────────────────────────────────────────────────
async function api(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(API + path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ── AUTH ───────────────────────────────────────────────────────────────────
function showAuthTab(tab) {
  document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
  document.getElementById('inviteForm').style.display = tab === 'invite' ? 'block' : 'none';
  document.getElementById('loginTab').classList.toggle('active', tab === 'login');
  document.getElementById('inviteTab').classList.toggle('active', tab === 'invite');
}

async function doLogin() {
  const name = document.getElementById('loginName').value.trim();
  const password = document.getElementById('loginPass').value;
  const errEl = document.getElementById('loginError');
  errEl.style.display = 'none';
  if (!name || !password) { showErr(errEl, 'Please fill in all fields'); return; }
  try {
    const res = await api('/api/auth/login', 'POST', { name, password });
    token = res.token; me = res.user;
    localStorage.setItem('fh_token', token);
    showApp();
  } catch (e) { showErr(errEl, e.message); }
}

async function doRedeem() {
  const invToken = document.getElementById('inviteToken').value.trim();
  const name = document.getElementById('inviteName').value.trim();
  const password = document.getElementById('invitePass').value;
  const errEl = document.getElementById('inviteError');
  errEl.style.display = 'none';
  if (!invToken || !password) { showErr(errEl, 'Please fill in all fields'); return; }
  try {
    const res = await api('/api/auth/redeem', 'POST', { token: invToken, name, password });
    token = res.token; me = res.user;
    localStorage.setItem('fh_token', token);
    showApp();
  } catch (e) { showErr(errEl, e.message); }
}

function showErr(el, msg) { el.textContent = msg; el.style.display = 'block'; }

// ── APP INIT ───────────────────────────────────────────────────────────────
async function showApp() {
  document.getElementById('authScreen').style.display = 'none';
  document.getElementById('mainApp').classList.add('visible');
  updateHeader();
  allUsers = await api('/api/users');
  switchTab('Feed');
}

function updateHeader() {
  if (!me) return;
  const initial = me.name ? me.name[0].toUpperCase() : '?';
  document.getElementById('headerAvatar').textContent = initial;
  document.getElementById('composeAvatar').textContent = initial;
}

// ── NAVIGATION ─────────────────────────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  const tabs = ['Feed','Chats','Birthdays','KK','Expenses'];
  tabs.forEach(t => {
    document.getElementById('screen' + t).classList.toggle('active', t === tab);
    document.getElementById('nav' + t).classList.toggle('active', t === tab);
  });
  const fab = document.getElementById('fab');
  fab.classList.toggle('visible', ['Feed','Chats','Birthdays','Expenses'].includes(tab));
  const titles = { Feed: 'Family Hub 🏠', Chats: 'Chats 💬', Birthdays: 'Birthdays & Gifts 🎂', KK: 'Christmas KK 🎅', Expenses: 'Shared Expenses 💸' };
  document.getElementById('headerTitle').textContent = titles[tab];
  document.getElementById('headerSub').textContent = me?.name ? 'Hi ' + me.name + '! 👋' : 'Everyone\'s here';
  if (tab === 'Feed') loadFeed();
  if (tab === 'Chats') loadChats();
  if (tab === 'Birthdays') loadBirthdays();
  if (tab === 'KK') loadKK();
  if (tab === 'Expenses') loadExpenses();
}

function onFabClick() {
  if (currentTab === 'Feed') openModal('composeModal');
  else if (currentTab === 'Chats') { populateMemberPicker('chatMemberPicker', []); openModal('newChatModal'); }
  else if (currentTab === 'Birthdays') openModal('addGiftModal');
  else if (currentTab === 'Expenses') { populateSplitPicker(); openModal('addExpenseModal'); }
}

// ── MODALS ─────────────────────────────────────────────────────────────────
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── TOAST ──────────────────────────────────────────────────────────────────
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2800);
}

// ── FEED ───────────────────────────────────────────────────────────────────
async function loadFeed() {
  const list = document.getElementById('feedList');
  list.innerHTML = '<div class="loading"><div class="spinner"></div>Loading feed...</div>';
  try {
    const posts = await api('/api/posts');
    if (!posts.length) {
      list.innerHTML = '<div class="empty"><div class="empty-icon">📭</div><div class="empty-text">No posts yet</div><div class="empty-sub">Be the first to post something! 🎉</div></div>';
      return;
    }
    list.innerHTML = posts.map(p => postHTML(p)).join('');
  } catch (e) { list.innerHTML = '<div class="empty"><div class="empty-icon">😬</div><div class="empty-text">' + e.message + '</div></div>'; }
}

function postHTML(p) {
  const initial = p.author_name ? p.author_name[0].toUpperCase() : '?';
  const imgs = (() => { try { return JSON.parse(p.media_urls || '[]'); } catch { return []; } })();
  const typeEmoji = { photo: '📸', milestone: '🎉', holiday: '✈️', post: '' }[p.post_type] || '';
  return \`<div class="post-card" id="post-\${p.id}">
    <div class="post-header">
      <div class="post-avatar">\${initial}</div>
      <div>
        <div class="post-author">\${esc(p.author_name)} \${typeEmoji}</div>
        <div class="post-time">\${timeAgo(p.created_at)}</div>
      </div>
    </div>
    \${p.content ? '<div class="post-content">' + esc(p.content) + '</div>' : ''}
    \${imgs.length ? imgs.map(u => '<img class="post-image" src="' + esc(u) + '" onerror="this.style.display=\'none\'">').join('') : ''}
    <div class="post-actions">
      <button class="post-action \${p.liked_by_me ? 'liked' : ''}" onclick="toggleLike(\${p.id}, this)">
        \${p.liked_by_me ? '❤️' : '🤍'} <span class="like-count">\${p.likes_count || 0}</span>
      </button>
      <button class="post-action" onclick="toggleComments(\${p.id})">💬 \${p.comments_count || 0}</button>
    </div>
    <div id="comments-\${p.id}" class="post-comments" style="display:none">
      <div id="comment-list-\${p.id}"></div>
      <div class="comment-input-row">
        <input id="comment-input-\${p.id}" placeholder="Write a comment..." onkeydown="if(event.key==='Enter')submitComment(\${p.id})">
        <button class="comment-send" onclick="submitComment(\${p.id})">→</button>
      </div>
    </div>
  </div>\`;
}

async function toggleLike(postId, btn) {
  try {
    const res = await api('/api/posts/' + postId + '/like', 'POST');
    const countEl = btn.querySelector('.like-count');
    const count = parseInt(countEl.textContent);
    if (res.liked) { btn.classList.add('liked'); btn.innerHTML = '❤️ <span class="like-count">' + (count+1) + '</span>'; }
    else { btn.classList.remove('liked'); btn.innerHTML = '🤍 <span class="like-count">' + Math.max(0,count-1) + '</span>'; }
  } catch {}
}

async function toggleComments(postId) {
  const el = document.getElementById('comments-' + postId);
  const visible = el.style.display !== 'none';
  el.style.display = visible ? 'none' : 'block';
  if (!visible) {
    const listEl = document.getElementById('comment-list-' + postId);
    listEl.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:8px 0">Loading...</div>';
    const comments = await api('/api/posts/' + postId + '/comments');
    listEl.innerHTML = comments.length ? comments.map(c =>
      '<div class="comment"><span class="comment-author">' + esc(c.author_name) + '</span> ' + esc(c.content) + '</div>'
    ).join('') : '<div style="color:var(--muted);font-size:13px;padding:8px 0">No comments yet</div>';
  }
}

async function submitComment(postId) {
  const input = document.getElementById('comment-input-' + postId);
  const content = input.value.trim();
  if (!content) return;
  try {
    const c = await api('/api/posts/' + postId + '/comments', 'POST', { content });
    const listEl = document.getElementById('comment-list-' + postId);
    listEl.innerHTML += '<div class="comment"><span class="comment-author">' + esc(c.author_name) + '</span> ' + esc(c.content) + '</div>';
    input.value = '';
  } catch {}
}

async function submitPost() {
  const content = document.getElementById('postContent').value.trim();
  const imageUrl = document.getElementById('postImageUrl').value.trim();
  const post_type = document.getElementById('postType').value;
  if (!content && !imageUrl) { toast('Add some text or a photo!'); return; }
  try {
    await api('/api/posts', 'POST', { content, media_urls: imageUrl ? [imageUrl] : [], post_type });
    closeModal('composeModal');
    document.getElementById('postContent').value = '';
    document.getElementById('postImageUrl').value = '';
    loadFeed();
    toast('Posted! 🎉');
  } catch (e) { toast('Error: ' + e.message); }
}

// ── CHATS ──────────────────────────────────────────────────────────────────
async function loadChats() {
  const list = document.getElementById('chatList');
  list.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
  try {
    const chats = await api('/api/chats');
    if (!chats.length) {
      list.innerHTML = '<div class="empty"><div class="empty-icon">💬</div><div class="empty-text">No chats yet</div><div class="empty-sub">Start a family group chat!</div></div>';
      return;
    }
    list.innerHTML = chats.map(c => \`<div class="chat-item" onclick="openChat(\${c.id}, '\${esc(c.name)}', '\${c.chat_type}')">
      <div class="chat-icon \${c.chat_type === 'direct' ? 'dm' : ''}">\${c.chat_type === 'direct' ? '👤' : '👨‍👩‍👧'}</div>
      <div style="flex:1;min-width:0">
        <div class="chat-name">\${esc(c.name)}</div>
        <div class="chat-preview">\${c.last_author ? esc(c.last_author) + ': ' + esc(c.last_message || '') : 'No messages yet'}</div>
      </div>
      <div class="chat-time">\${c.last_at ? timeAgo(c.last_at) : ''}</div>
    </div>\`).join('');
  } catch (e) { list.innerHTML = '<div class="empty"><div class="empty-icon">😬</div><div class="empty-text">' + e.message + '</div></div>'; }
}

function openChat(id, name, type) {
  currentChatId = id;
  document.getElementById('chatViewName').textContent = name;
  document.getElementById('chatViewType').textContent = type === 'direct' ? 'Private chat' : 'Group chat';
  document.getElementById('chatView').classList.add('open');
  loadMessages(id);
}

function closeChat() {
  document.getElementById('chatView').classList.remove('open');
  currentChatId = null;
}

async function loadMessages(chatId) {
  const container = document.getElementById('chatMessages');
  container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
  const msgs = await api('/api/chats/' + chatId + '/messages');
  container.innerHTML = msgs.length ? msgs.map(m => msgHTML(m)).join('') : '<div class="empty"><div class="empty-icon">👋</div><div class="empty-text">Say something!</div></div>';
  container.scrollTop = container.scrollHeight;
}

function msgHTML(m) {
  const mine = m.user_id === me.id;
  return \`<div style="display:flex;flex-direction:column;align-items:\${mine ? 'flex-end' : 'flex-start'}">
    \${!mine ? '<div style="font-size:11px;color:var(--muted);margin-left:4px;margin-bottom:2px">' + esc(m.author_name) + '</div>' : ''}
    <div class="msg \${mine ? 'mine' : 'theirs'}">\${esc(m.content)}
      <div class="msg-time">\${timeAgo(m.created_at)}</div>
    </div>
  </div>\`;
}

async function sendMessage() {
  const input = document.getElementById('chatInputField');
  const content = input.value.trim();
  if (!content || !currentChatId) return;
  input.value = ''; input.style.height = 'auto';
  try {
    const m = await api('/api/chats/' + currentChatId + '/messages', 'POST', { content });
    const container = document.getElementById('chatMessages');
    container.innerHTML += msgHTML(m);
    container.scrollTop = container.scrollHeight;
  } catch (e) { toast('Send failed: ' + e.message); }
}

function populateMemberPicker(containerId, selected) {
  const el = document.getElementById(containerId);
  el.innerHTML = allUsers.filter(u => u.id !== me.id).map(u =>
    \`<span class="person-chip \${selected.includes(u.id) ? 'selected' : ''}" data-id="\${u.id}" onclick="toggleChip(this)">\${esc(u.name)}</span>\`
  ).join('');
}

function toggleChip(el) { el.classList.toggle('selected'); }

function getSelectedChips(containerId) {
  return [...document.querySelectorAll('#' + containerId + ' .person-chip.selected')].map(el => parseInt(el.dataset.id));
}

async function createChat() {
  const name = document.getElementById('newChatName').value.trim();
  const chat_type = document.getElementById('newChatType').value;
  const member_ids = getSelectedChips('chatMemberPicker');
  if (!name) { toast('Give the chat a name'); return; }
  try {
    await api('/api/chats', 'POST', { name, chat_type, member_ids });
    closeModal('newChatModal');
    document.getElementById('newChatName').value = '';
    loadChats();
    toast('Chat created! 💬');
  } catch (e) { toast('Error: ' + e.message); }
}

// ── BIRTHDAYS ──────────────────────────────────────────────────────────────
async function loadBirthdays() {
  const listEl = document.getElementById('birthdayList');
  try {
    const bdays = await api('/api/birthdays');
    // Populate wishlist user picker
    const sel = document.getElementById('wishlistUser');
    sel.innerHTML = '<option value="">— pick a family member —</option>' +
      allUsers.map(u => \`<option value="\${u.id}">\${esc(u.name)}\${u.id === me.id ? ' (you)' : ''}</option>\`).join('');

    if (!bdays.length) {
      listEl.innerHTML = '<div class="empty"><div class="empty-icon">🎂</div><div class="empty-text">No birthdays added yet</div></div>';
      return;
    }
    const today = new Date(); today.setHours(0,0,0,0);
    listEl.innerHTML = '<div class="section-header" style="padding:0 0 12px"><span class="section-title">📅 Upcoming Birthdays</span></div>' +
      bdays.map(u => {
        const bd = nextBirthday(u.birthday);
        const days = bd ? Math.round((bd - today) / 86400000) : null;
        return \`<div class="birthday-item">
          <div class="birthday-avatar">\${u.name[0]}</div>
          <div>
            <div class="birthday-name">\${esc(u.name)}</div>
            <div class="birthday-date">\${formatDate(u.birthday)}\${u.relationship ? ' · ' + esc(u.relationship) : ''}</div>
          </div>
          <div class="birthday-days">
            \${days === 0 ? '<div class="days-today">🎂</div><div class="days-label">TODAY!</div>' :
              days !== null ? '<div class="days-number">' + days + '</div><div class="days-label">days</div>' : ''}
          </div>
        </div>\`;
      }).join('');
  } catch (e) { listEl.innerHTML = '<div class="empty">' + e.message + '</div>'; }
}

async function loadGifts(userId) {
  if (!userId) { document.getElementById('giftList').innerHTML = ''; return; }
  const listEl = document.getElementById('giftList');
  listEl.innerHTML = '<div class="loading" style="padding:16px"><div class="spinner"></div>Loading...</div>';
  const gifts = await api('/api/gifts?user_id=' + userId);
  const isMe = parseInt(userId) === me.id;
  if (!gifts.length) {
    listEl.innerHTML = \`<div style="padding:16px;color:var(--muted);font-size:14px">No wish list yet.\${isMe ? ' <button class="btn btn-sm" style="display:inline;width:auto;margin-left:8px" onclick="openModal(\'addGiftModal\')">Add items</button>' : ''}</div>\`;
    return;
  }
  listEl.innerHTML = '<div style="padding:0 0 8px">' + gifts.map(g => \`<div class="gift-item \${g.claimed_by ? 'gift-claimed' : ''}">
    <div style="flex:1">
      <div class="gift-title">\${esc(g.title)}\${g.price ? ' · €' + g.price : ''}</div>
      <div class="gift-meta">\${g.description ? esc(g.description) + ' ' : ''}\${g.url ? '<a href="' + esc(g.url) + '" target="_blank" style="color:var(--primary)">View →</a>' : ''}</div>
      \${g.claimed_by && !isMe ? '<div style="font-size:11px;color:#00b894;font-weight:700">✓ Claimed by ' + esc(g.claimed_by_name || 'someone') + '</div>' : ''}
      \${g.claimed_by && isMe ? '<div style="font-size:11px;color:#00b894;font-weight:700">✓ Someone\'s got this!</div>' : ''}
    </div>
    \${!isMe ? '<button class="btn btn-sm \${g.claimed_by && g.claimed_by !== me.id ? 'btn-ghost' : ''}" style="flex-shrink:0" onclick="claimGift(\${g.id}, this)">\${g.claimed_by === me.id ? 'Unclaim' : g.claimed_by ? 'Taken' : 'I\'ll get it!'}</button>' : ''}
    \${isMe ? '<button class="btn btn-sm btn-ghost" style="flex-shrink:0;font-size:12px" onclick="deleteGift(\${g.id})">✕</button>' : ''}
  </div>\`).join('') + '</div>';
}

async function claimGift(giftId, btn) {
  try {
    const res = await api('/api/gifts/' + giftId + '/claim', 'POST');
    toast(res.claimed ? '✓ Claimed!' : 'Unclaimed');
    loadGifts(document.getElementById('wishlistUser').value);
  } catch (e) { toast(e.message); }
}

async function deleteGift(giftId) {
  await api('/api/gifts/' + giftId, 'DELETE');
  loadGifts(me.id);
  toast('Removed');
}

async function submitGift() {
  const title = document.getElementById('giftTitle').value.trim();
  if (!title) { toast('Give it a name!'); return; }
  try {
    await api('/api/gifts', 'POST', {
      title,
      description: document.getElementById('giftDesc').value.trim(),
      url: document.getElementById('giftUrl').value.trim(),
      price: parseFloat(document.getElementById('giftPrice').value) || null,
      event_type: document.getElementById('giftEvent').value
    });
    closeModal('addGiftModal');
    ['giftTitle','giftDesc','giftUrl','giftPrice'].forEach(id => document.getElementById(id).value = '');
    loadGifts(me.id);
    document.getElementById('wishlistUser').value = me.id;
    toast('Added to your wish list! 🎁');
  } catch (e) { toast('Error: ' + e.message); }
}

// ── KK ─────────────────────────────────────────────────────────────────────
async function loadKK() {
  const el = document.getElementById('kkContent');
  const draws = await api('/api/kk');
  if (!draws.length) {
    el.innerHTML = \`<div class="empty" style="padding-top:60px">
      <div class="empty-icon">🎅</div>
      <div class="empty-text">No KK draw yet</div>
      <div class="empty-sub">Set one up for Christmas!</div>
      <button class="btn" style="width:auto;margin-top:20px;padding:12px 24px" onclick="openModal('kkModal')">Set Up KK Draw 🎄</button>
    </div>\`;
    return;
  }
  el.innerHTML = draws.map(d => \`
    <div style="margin:12px">
      <div class="kk-card">
        <div class="kk-year">🎄 KK \${d.year} · \${d.status === 'drawn' ? 'Drawn!' : 'Not drawn yet'}\${d.budget ? ' · Budget €' + d.budget : ''}</div>
        \${d.status === 'drawn' ? '<div id="kk-assign-' + d.id + '"><div class="loading"><div class="spinner"></div></div></div>' : ''}
      </div>
      \${d.status !== 'drawn' ? '<button class="btn" style="margin-top:10px" onclick="openKKDrawModal(' + d.id + ')">Draw Names! 🎲</button>' : ''}
    </div>
  \`).join('') + '<div style="text-align:center;padding:16px"><button class="btn btn-ghost" style="width:auto;padding:10px 24px" onclick="openModal(\'kkModal\')">+ New Year</button></div>';

  // Load my assignments
  for (const d of draws.filter(d => d.status === 'drawn')) {
    const assignment = await api('/api/kk/' + d.id + '/my-assignment');
    const el2 = document.getElementById('kk-assign-' + d.id);
    if (el2) {
      el2.innerHTML = assignment
        ? \`<div style="margin-top:12px"><div style="font-size:13px;opacity:0.7">You're buying for</div><div class="kk-receiver">\${esc(assignment.receiver_name)} 🎁</div></div>\`
        : \`<div style="margin-top:8px;opacity:0.7;font-size:14px">Not in this draw</div>\`;
    }
  }
}

async function createKKDraw() {
  const year = parseInt(document.getElementById('kkYear').value);
  const budget = parseFloat(document.getElementById('kkBudget').value) || null;
  try {
    await api('/api/kk', 'POST', { year, budget });
    closeModal('kkModal');
    loadKK();
    toast('KK draw created! 🎄');
  } catch (e) { toast(e.message); }
}

function openKKDrawModal(drawId) {
  currentKKDrawId = drawId;
  populateMemberPicker('kkParticipantPicker', allUsers.map(u => u.id));
  // Pre-select all
  document.querySelectorAll('#kkParticipantPicker .person-chip').forEach(el => el.classList.add('selected'));
  openModal('kkDrawModal');
}

async function runKKDraw() {
  const ids = getSelectedChips('kkParticipantPicker');
  if (ids.length < 3) { toast('Need at least 3 people!'); return; }
  try {
    await api('/api/kk/' + currentKKDrawId + '/draw', 'POST', { participant_ids: ids });
    closeModal('kkDrawModal');
    loadKK();
    toast('Names drawn! Check who you got 🎁');
  } catch (e) { toast(e.message); }
}

// ── EXPENSES ───────────────────────────────────────────────────────────────
async function loadExpenses() {
  const listEl = document.getElementById('expenseList');
  listEl.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';
  try {
    const expenses = await api('/api/expenses');
    if (!expenses.length) {
      listEl.innerHTML = '<div class="empty"><div class="empty-icon">💸</div><div class="empty-text">No shared expenses yet</div><div class="empty-sub">Track who owes who for presents, insurance, holidays...</div></div>';
      return;
    }
    listEl.innerHTML = expenses.map(e => \`<div class="expense-item">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div>
          <div class="expense-desc">\${esc(e.description)}</div>
          <div class="expense-meta">Paid by \${esc(e.paid_by_name)} · \${categoryEmoji(e.category)} \${esc(e.category)}</div>
        </div>
        <div style="text-align:right">
          <div class="expense-amount">€\${e.total_amount}</div>
          \${e.i_owe > 0 ? '<div class="expense-owe">You owe €' + e.i_owe.toFixed(2) + '<button class="btn btn-sm" style="margin-left:8px;padding:4px 10px;font-size:11px" onclick="settleExpense(' + e.id + ')">Settled</button></div>' :
            e.paid_by === me.id ? '' : '<div class="expense-settled">✓ You\'re settled</div>'}
        </div>
      </div>
    </div>\`).join('');
  } catch (e) { listEl.innerHTML = '<div class="empty">' + e.message + '</div>'; }
}

function populateSplitPicker() {
  const el = document.getElementById('expenseSplitPicker');
  el.innerHTML = allUsers.filter(u => u.id !== me.id).map(u =>
    \`<span class="person-chip" data-id="\${u.id}" onclick="toggleChip(this)">\${esc(u.name)}</span>\`
  ).join('');
}

async function submitExpense() {
  const description = document.getElementById('expenseDesc').value.trim();
  const total_amount = parseFloat(document.getElementById('expenseAmount').value);
  const category = document.getElementById('expenseCategory').value;
  const split_with = getSelectedChips('expenseSplitPicker');
  if (!description || !total_amount) { toast('Fill in description and amount'); return; }
  try {
    await api('/api/expenses', 'POST', { description, total_amount, category, split_with });
    closeModal('addExpenseModal');
    document.getElementById('expenseDesc').value = '';
    document.getElementById('expenseAmount').value = '';
    loadExpenses();
    toast('Expense added 💸');
  } catch (e) { toast(e.message); }
}

async function settleExpense(id) {
  await api('/api/expenses/' + id + '/settle', 'POST');
  loadExpenses();
  toast('Settled! ✓');
}

// ── PROFILE ────────────────────────────────────────────────────────────────
function showProfile() {
  toast('Profile editing coming soon!');
}

// ── HELPERS ────────────────────────────────────────────────────────────────
function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function timeAgo(ts) {
  if (!ts) return '';
  const d = new Date(ts + (ts.includes('Z') || ts.includes('+') ? '' : 'Z'));
  const diff = (Date.now() - d) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  if (diff < 604800) return Math.floor(diff/86400) + 'd ago';
  return d.toLocaleDateString('en-IE', { day: 'numeric', month: 'short' });
}

function formatDate(d) {
  if (!d) return '';
  const parts = d.split('-');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return (parts[2] ? parts[2] + ' ' : '') + months[parseInt(parts[1])-1] + (parts[0] && parts[0] !== '0000' ? ' ' + parts[0] : '');
}

function nextBirthday(dateStr) {
  if (!dateStr) return null;
  const parts = dateStr.split('-');
  const now = new Date(); now.setHours(0,0,0,0);
  let bd = new Date(now.getFullYear(), parseInt(parts[1])-1, parseInt(parts[2] || 1));
  if (bd < now) bd.setFullYear(bd.getFullYear() + 1);
  return bd;
}

function categoryEmoji(cat) {
  return { presents: '🎁', insurance: '🛡️', holiday: '✈️', food: '🍽️', general: '📋' }[cat] || '📋';
}

// ── GO ─────────────────────────────────────────────────────────────────────
boot();
</script>
</body>
</html>`;
}
