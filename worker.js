// Family Hub v2 — single-file Cloudflare Worker
// Built: 2026-05-03 (v14 — visual overhaul)

// Family Hub v2 - Part 1: Auth, Crypto, Core API helpers

// ─── CRYPTO UTILS ────────────────────────────────────────────────────────────
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt:enc.encode(salt), iterations:10000, hash:'SHA-256'}, key, 256);
  return Array.from(new Uint8Array(bits)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function getChatKey(chatId, secret) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HKDF'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'HKDF', hash:'SHA-256', salt:enc.encode('family-hub-chat-v2'), info:enc.encode(String(chatId))},
    keyMaterial, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}

async function encryptMsg(content, chatId, secret) {
  const key = await getChatKey(chatId, secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(content));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...out));
}

async function decryptMsg(encoded, chatId, secret) {
  try {
    const key = await getChatKey(chatId, secret);
    const buf = Uint8Array.from(atob(encoded), c=>c.charCodeAt(0));
    const iv = buf.slice(0,12);
    const ct = buf.slice(12);
    const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return new TextDecoder().decode(plain);
  } catch { return '[encrypted]'; }
}

async function encryptDoc(content, docId, secret) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HKDF'}, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    {name:'HKDF', hash:'SHA-256', salt:enc.encode('family-hub-docs-v2'), info:enc.encode(String(docId))},
    keyMaterial, {name:'AES-GCM', length:256}, false, ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = typeof content === 'string' ? enc.encode(content) : content;
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return out;
}

async function decryptDoc(buf, docId, secret) {
  try {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HKDF'}, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      {name:'HKDF', hash:'SHA-256', salt:enc.encode('family-hub-docs-v2'), info:enc.encode(String(docId))},
      keyMaterial, {name:'AES-GCM', length:256}, false, ['decrypt']
    );
    const iv = buf.slice(0,12);
    const ct = buf.slice(12);
    return await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
  } catch { return null; }
}

// ─── SESSION / AUTH ───────────────────────────────────────────────────────────
async function getSession(request, env) {
  const token = request.headers.get('x-session-token') ||
    (request.headers.get('cookie') || '').match(/session=([^;]+)/)?.[1];
  if (!token) return null;
  const row = await env.DB.prepare('SELECT * FROM sessions WHERE token=? AND expires_at > datetime("now")').bind(token).first();
  if (!row) return null;
  return await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(row.user_id).first();
}

function json(data, status=200) {
  return new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json','access-control-allow-origin':'*'}});
}
function err(msg, status=400) { return json({error:msg}, status); }

async function createNotif(env, userId, type, title, body, refId=null, refType=null) {
  try {
    const pref = await env.DB.prepare('SELECT enabled FROM notification_prefs WHERE user_id=? AND type=?').bind(userId, type).first();
    if (pref && pref.enabled === 0) return; // user disabled this type
    await env.DB.prepare(
      'INSERT INTO notifications (user_id,type,title,body,ref_id,ref_type) VALUES (?,?,?,?,?,?)'
    ).bind(userId, type, title, body, refId, refType).run();
  } catch {}
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
async function handleAuth(path, request, env) {
  const method = request.method;

  if (path === '/api/auth/invite' && method === 'GET') {
    const token = new URL(request.url).searchParams.get('token');
    const invite = await env.DB.prepare('SELECT * FROM invites WHERE token=? AND used=0').bind(token).first();
    if (!invite) return err('Invalid or used invite', 404);
    return json({name: invite.name, role: invite.role});
  }

  if (path === '/api/auth/register' && method === 'POST') {
    const {token, name, email, password} = await request.json();
    const invite = await env.DB.prepare('SELECT * FROM invites WHERE token=? AND used=0').bind(token).first();
    if (!invite) return err('Invalid invite');
    const salt = crypto.randomUUID();
    const hash = await hashPassword(password, salt);
    // If invite has a seeded user_id, UPDATE that row — otherwise INSERT new
    let userId;
    if (invite.user_id) {
      userId = invite.user_id;
      await env.DB.prepare('UPDATE users SET password_hash=?,salt=?,name=COALESCE(?,name),email=COALESCE(?,email) WHERE id=?').bind(hash, salt, name||null, email||null, userId).run();
    } else {
      userId = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO users (id,name,email,role,password_hash,salt,avatar_color) VALUES (?,?,?,?,?,?,?)').bind(
        userId, name || invite.name, email||null, invite.role, hash, salt, invite.avatar_color || '#6366f1'
      ).run();
    }
    await env.DB.prepare('UPDATE invites SET used=1,used_by=?,used_at=datetime("now") WHERE token=?').bind(userId, token).run();
    // Add to family group chat (chat_id=1)
    try { await env.DB.prepare('INSERT OR IGNORE INTO chat_members (chat_id,user_id) VALUES (1,?)').bind(userId).run(); } catch {}
    const sessionToken = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,datetime("now","+"||?||" days"))').bind(sessionToken, userId, 30).run();
    const finalUser = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(userId).first();
    // Auto-join any family the seeded user belongs to
    try {
      const families = await env.DB.prepare('SELECT family_id FROM family_members WHERE user_id=?').bind(invite.user_id||userId).all();
      for (const fm of families.results||[]) {
        await env.DB.prepare("INSERT OR IGNORE INTO family_members (family_id,user_id,role) VALUES (?,?,'member')").bind(fm.family_id, userId).run();
      }
    } catch {}
    return json({token: sessionToken, user: {id:userId, name:finalUser?.name||name, role:invite.role}});
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const {email, name, password} = await request.json();
    const identifier = (email || name || '').trim();
    if (!identifier) return err('Email is required', 400);
    const user = await env.DB.prepare('SELECT * FROM users WHERE (LOWER(email)=LOWER(?) OR LOWER(name)=LOWER(?)) AND password_hash IS NOT NULL ORDER BY created_at DESC').bind(identifier, identifier).first();
    if (!user) return err('No account found with that email', 401);
    const hash = await hashPassword(password, user.salt);
    if (hash !== user.password_hash) return err('Wrong password', 401);
    const token = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,datetime("now","+30 days"))').bind(token, user.id).run();
    return json({token, user: {id:user.id, name:user.name, role:user.role, avatar_color:user.avatar_color, avatar_url:user.avatar_url}});
  }

  if (path === '/api/auth/me' && method === 'GET') {
    const user = await getSession(request, env);
    if (!user) return err('Unauth', 401);
    return json({id:user.id, name:user.name, role:user.role, avatar_color:user.avatar_color, avatar_url:user.avatar_url, bio:user.bio});
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const token = request.headers.get('x-session-token') || (request.headers.get('cookie')||'').match(/session=([^;]+)/)?.[1];
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(token).run();
    return json({ok:true});
  }

  if (path === '/api/auth/profile' && method === 'PATCH') {
    const user = await getSession(request, env);
    if (!user) return err('Unauth', 401);
    const {name, bio, avatar_color} = await request.json();
    await env.DB.prepare('UPDATE users SET name=COALESCE(?,name), bio=COALESCE(?,bio), avatar_color=COALESCE(?,avatar_color) WHERE id=?')
      .bind(name||null, bio||null, avatar_color||null, user.id).run();
    return json({ok:true});
  }

  return null;
}

// ─── POSTS / FEED ─────────────────────────────────────────────────────────────
async function handlePosts(path, request, env, user) {
  const method = request.method;
  const url = new URL(request.url);

  if (path === '/api/posts' && method === 'GET') {
    const limit = parseInt(url.searchParams.get('limit')||'20');
    const offset = parseInt(url.searchParams.get('offset')||'0');
    const posts = await env.DB.prepare(
      `SELECT p.*, u.name as author_name, u.avatar_color, u.avatar_url,
       (SELECT COUNT(*) FROM reactions WHERE ref_id=p.id AND ref_type='post') as reaction_count,
       (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comment_count,
       (SELECT reaction FROM reactions WHERE ref_id=p.id AND ref_type='post' AND user_id=?) as my_reaction
       FROM posts p JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC LIMIT ? OFFSET ?`
    ).bind(user.id, limit, offset).all();
    // Attach media urls
    const results = await Promise.all(posts.results.map(async p => {
      let media = [];
      try {
        const m = await env.DB.prepare('SELECT * FROM post_media WHERE post_id=? ORDER BY position').bind(p.id).all();
        media = m.results;
      } catch {}
      return {...p, media};
    }));
    return json(results);
  }

  if (path === '/api/posts' && method === 'POST') {
    const ct = request.headers.get('content-type')||'';
    let content='', media_keys=[];
    if (ct.includes('multipart/form-data')) {
      const fd = await request.formData();
      content = fd.get('content')||'';
      const files = fd.getAll('media');
      for (const file of files) {
        if (file && file.size > 0) {
          const key = `posts/${user.id}/${Date.now()}-${Math.random().toString(36).slice(2)}.${file.name?.split('.').pop()||'jpg'}`;
          await env.PHOTOS.put(key, file.stream(), {httpMetadata:{contentType:file.type||'image/jpeg'}});
          media_keys.push(key);
        }
      }
    } else {
      const body = await request.json();
      content = body.content || '';
      media_keys = body.media_keys || [];
    }
    if (!content && media_keys.length === 0) return err('Empty post');
    const postId = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO posts (id,user_id,content) VALUES (?,?,?)').bind(postId, user.id, content).run();
    for (let i=0; i<media_keys.length; i++) {
      await env.DB.prepare('INSERT INTO post_media (post_id,r2_key,media_type,position) VALUES (?,?,?,?)')
        .bind(postId, media_keys[i], 'image', i).run();
    }
    return json({id:postId, ok:true}, 201);
  }

  // Reactions
  const reactMatch = path.match(/^\/api\/posts\/([^/]+)\/react$/);
  if (reactMatch && method === 'POST') {
    const postId = reactMatch[1];
    const {reaction} = await request.json();
    const existing = await env.DB.prepare("SELECT * FROM reactions WHERE ref_id=? AND ref_type='post' AND user_id=?").bind(postId, user.id).first();
    if (existing) {
      if (existing.reaction === reaction) {
        await env.DB.prepare("DELETE FROM reactions WHERE ref_id=? AND ref_type='post' AND user_id=?").bind(postId, user.id).run();
      } else {
        await env.DB.prepare("UPDATE reactions SET reaction=? WHERE ref_id=? AND ref_type='post' AND user_id=?").bind(reaction, postId, user.id).run();
      }
    } else {
      await env.DB.prepare("INSERT INTO reactions (ref_id,ref_type,user_id,reaction) VALUES (?,'post',?,?)").bind(postId, user.id, reaction).run();
      // Notify post author
      const post = await env.DB.prepare('SELECT user_id FROM posts WHERE id=?').bind(postId).first();
      if (post && post.user_id !== user.id) {
        await createNotif(env, post.user_id, 'reaction', `${user.name} reacted`, `${user.name} reacted ${reaction} to your post`, postId, 'post');
      }
    }
    const count = await env.DB.prepare("SELECT COUNT(*) as c FROM reactions WHERE ref_id=? AND ref_type='post'").bind(postId).first();
    return json({count: count.c});
  }

  // Comments
  const commentsMatch = path.match(/^\/api\/posts\/([^/]+)\/comments$/);
  if (commentsMatch) {
    const postId = commentsMatch[1];
    if (method === 'GET') {
      const comments = await env.DB.prepare(
        'SELECT c.*, u.name, u.avatar_color FROM comments c JOIN users u ON c.user_id=u.id WHERE c.post_id=? ORDER BY c.created_at'
      ).bind(postId).all();
      return json(comments.results);
    }
    if (method === 'POST') {
      const {content} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO comments (id,post_id,user_id,content) VALUES (?,?,?,?)').bind(id, postId, user.id, content).run();
      const post = await env.DB.prepare('SELECT user_id FROM posts WHERE id=?').bind(postId).first();
      if (post && post.user_id !== user.id) {
        await createNotif(env, post.user_id, 'comment', `${user.name} commented`, `${user.name}: ${content.slice(0,60)}`, postId, 'post');
      }
      return json({id, ok:true}, 201);
    }
  }

  // DELETE post (owner only)
  const deletePostMatch = path.match(/^\/api\/posts\/([^/]+)$/);
  if (deletePostMatch && method === 'DELETE') {
    const postId = deletePostMatch[1];
    const post = await env.DB.prepare('SELECT user_id FROM posts WHERE id=?').bind(postId).first();
    if (!post) return err('Not found', 404);
    if (post.user_id !== user.id) return err('Forbidden', 403);
    await env.DB.prepare('DELETE FROM post_media WHERE post_id=?').bind(postId).run();
    await env.DB.prepare("DELETE FROM reactions WHERE ref_id=? AND ref_type='post'").bind(postId).run();
    await env.DB.prepare('DELETE FROM comments WHERE post_id=?').bind(postId).run();
    await env.DB.prepare('DELETE FROM posts WHERE id=?').bind(postId).run();
    return json({ok:true});
  }

  return null;
}

// ─── PHOTO PROXY ─────────────────────────────────────────────────────────────
async function handlePhotos(path, request, env, user) {
  // GET /api/photos/:key* — proxy R2 object
  if (request.method === 'GET') {
    const key = decodeURIComponent(path.replace('/api/photos/', ''));
    const obj = await env.PHOTOS.get(key);
    if (!obj) return err('Not found', 404);
    const headers = new Headers();
    obj.writeHttpMetadata(headers);
    headers.set('cache-control', 'public, max-age=86400');
    return new Response(obj.body, {headers});
  }
  // POST /api/photos/upload — generic upload
  if (request.method === 'POST') {
    const fd = await request.formData();
    const file = fd.get('file');
    if (!file) return err('No file');
    const folder = fd.get('folder') || 'uploads';
    const key = `${folder}/${user.id}/${Date.now()}-${Math.random().toString(36).slice(2)}.${file.name?.split('.').pop()||'bin'}`;
    await env.PHOTOS.put(key, file.stream(), {httpMetadata:{contentType:file.type||'application/octet-stream'}});
    return json({key, url:`/api/photos/${encodeURIComponent(key)}`}, 201);
  }
  return null;
}


// Family Hub v2 - Part 2: Chats (SSE + encrypted), Stories, Events, Transfers, Notifications, Documents

// ─── CHATS ────────────────────────────────────────────────────────────────────
async function handleChats(path, request, env, user) {
  const method = request.method;

  if (path === '/api/chats' && method === 'GET') {
    const chats = await env.DB.prepare(
      `SELECT c.*,
       (SELECT COUNT(*) FROM chat_members WHERE chat_id=c.id) as member_count,
       (SELECT content FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) as last_msg_enc,
       (SELECT created_at FROM messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1) as last_msg_at,
       (SELECT u2.name FROM messages m2 JOIN users u2 ON m2.user_id=u2.id WHERE m2.chat_id=c.id ORDER BY m2.created_at DESC LIMIT 1) as last_sender
       FROM chats c
       JOIN chat_members cm ON cm.chat_id=c.id AND cm.user_id=?
       ORDER BY COALESCE(last_msg_at, c.created_at) DESC`
    ).bind(user.id).all();

    const results = await Promise.all(chats.results.map(async c => {
      let last_msg = '';
      if (c.last_msg_enc) {
        try { last_msg = await decryptMsg(c.last_msg_enc, c.id, env.ENCRYPTION_KEY); } catch { last_msg = '🔒'; }
      }
      const members = await env.DB.prepare(
        'SELECT u.id,u.name,u.avatar_color,u.avatar_url FROM users u JOIN chat_members cm ON cm.user_id=u.id WHERE cm.chat_id=?'
      ).bind(c.id).all();
      return {...c, last_msg, members: members.results, last_msg_enc: undefined};
    }));
    return json(results);
  }

  if (path === '/api/chats' && method === 'POST') {
    const {name, member_ids, is_group, chat_type} = await request.json();
    const ins = await env.DB.prepare('INSERT INTO chats (name,is_group,created_by,chat_type) VALUES (?,?,?,?)').bind(name||null, is_group?1:0, user.id, chat_type||'text').run();
    const chatId = ins.meta.last_row_id;
    const allMembers = [...new Set([user.id, ...(member_ids||[])])];
    for (const uid of allMembers) {
      await env.DB.prepare('INSERT OR IGNORE INTO chat_members (chat_id,user_id) VALUES (?,?)').bind(chatId, uid).run();
    }
    return json({id: chatId, ok:true}, 201);
  }

  // Messages
  const msgsMatch = path.match(/^\/api\/chats\/([^/]+)\/messages$/);
  if (msgsMatch) {
    const chatId = msgsMatch[1];
    const isMember = await env.DB.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').bind(chatId, user.id).first();
    if (!isMember) return err('Not a member', 403);

    if (method === 'GET') {
      const limit = parseInt(new URL(request.url).searchParams.get('limit')||'50');
      const before = new URL(request.url).searchParams.get('before');
      let query, args;
      if (before) {
        query = 'SELECT m.*,u.name as sender_name,u.avatar_color FROM messages m JOIN users u ON m.user_id=u.id WHERE m.chat_id=? AND m.created_at < ? ORDER BY m.created_at DESC LIMIT ?';
        args = [chatId, before, limit];
      } else {
        query = 'SELECT m.*,u.name as sender_name,u.avatar_color FROM messages m JOIN users u ON m.user_id=u.id WHERE m.chat_id=? ORDER BY m.created_at DESC LIMIT ?';
        args = [chatId, limit];
      }
      const msgs = await env.DB.prepare(query).bind(...args).all();
      const decrypted = await Promise.all(msgs.results.reverse().map(async m => {
        let content = m.content;
        if (m.encrypted && env.ENCRYPTION_KEY) {
          try { content = await decryptMsg(m.content, chatId, env.ENCRYPTION_KEY); } catch {}
        }
        let reactions = [];
        try {
          const r = await env.DB.prepare("SELECT reaction,COUNT(*) as c FROM reactions WHERE ref_id=? AND ref_type='message' GROUP BY reaction").bind(m.id).all();
          reactions = r.results;
        } catch {}
        return {...m, content, reactions};
      }));
      return json(decrypted);
    }

    if (method === 'POST') {
      const ct = request.headers.get('content-type')||'';
      let content='', media_key=null, msg_type='text', reply_to=null;
      if (ct.includes('multipart/form-data')) {
        const fd = await request.formData();
        content = fd.get('content')||'';
        const file = fd.get('file');
        msg_type = fd.get('type')||'text';
        reply_to = fd.get('reply_to')||null;
        if (file && file.size > 0) {
          media_key = `chats/${chatId}/${Date.now()}-${Math.random().toString(36).slice(2)}.${file.name?.split('.').pop()||'bin'}`;
          await env.PHOTOS.put(media_key, file.stream(), {httpMetadata:{contentType:file.type||'application/octet-stream'}});
          msg_type = file.type?.startsWith('image/') ? 'image' : 'file';
        }
      } else {
        const body = await request.json();
        content = body.content || '';
        msg_type = body.type || 'text';
        reply_to = body.reply_to || null;
      }

      let storedContent = content;
      let encrypted = 0;
      if (content && env.ENCRYPTION_KEY) {
        storedContent = await encryptMsg(content, chatId, env.ENCRYPTION_KEY);
        encrypted = 1;
      }

      const msgId = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO messages (id,chat_id,user_id,content,encrypted,msg_type,media_key,reply_to) VALUES (?,?,?,?,?,?,?,?)')
        .bind(msgId, chatId, user.id, storedContent, encrypted, msg_type, media_key, reply_to).run();

      // Notify other members
      const members = await env.DB.prepare('SELECT user_id FROM chat_members WHERE chat_id=? AND user_id!=?').bind(chatId, user.id).all();
      const chat = await env.DB.prepare('SELECT name FROM chats WHERE id=?').bind(chatId).first();
      const notifBody = content ? content.slice(0,80) : `sent a ${msg_type}`;
      for (const m of members.results) {
        await createNotif(env, m.user_id, 'message', `${user.name}`, notifBody, chatId, 'chat');
      }

      return json({id:msgId, content, encrypted:false, ok:true}, 201);
    }
  }

  // Message reactions
  const msgReactMatch = path.match(/^\/api\/chats\/([^/]+)\/messages\/([^/]+)\/react$/);
  if (msgReactMatch && method === 'POST') {
    const [,chatId, msgId] = msgReactMatch;
    const {reaction} = await request.json();
    const existing = await env.DB.prepare("SELECT * FROM reactions WHERE ref_id=? AND ref_type='message' AND user_id=?").bind(msgId, user.id).first();
    if (existing) {
      if (existing.reaction === reaction) await env.DB.prepare("DELETE FROM reactions WHERE ref_id=? AND ref_type='message' AND user_id=?").bind(msgId, user.id).run();
      else await env.DB.prepare("UPDATE reactions SET reaction=? WHERE ref_id=? AND ref_type='message' AND user_id=?").bind(reaction, msgId, user.id).run();
    } else {
      await env.DB.prepare("INSERT INTO reactions (ref_id,ref_type,user_id,reaction) VALUES (?,'message',?,?)").bind(msgId, user.id, reaction).run();
    }
    return json({ok:true});
  }

  // SSE stream
  const streamMatch = path.match(/^\/api\/chats\/([^/]+)\/stream$/);
  if (streamMatch && method === 'GET') {
    const chatId = streamMatch[1];
    const isMember = await env.DB.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?').bind(chatId, user.id).first();
    if (!isMember) return err('Not a member', 403);

    // Simple long-poll: return latest msgs since timestamp
    const since = new URL(request.url).searchParams.get('since') || new Date(Date.now()-5000).toISOString();
    const msgs = await env.DB.prepare(
      'SELECT m.*,u.name as sender_name,u.avatar_color FROM messages m JOIN users u ON m.user_id=u.id WHERE m.chat_id=? AND m.created_at > ? ORDER BY m.created_at LIMIT 50'
    ).bind(chatId, since).all();
    const decrypted = await Promise.all(msgs.results.map(async m => {
      let content = m.content;
      if (m.encrypted && env.ENCRYPTION_KEY) { try { content = await decryptMsg(m.content, chatId, env.ENCRYPTION_KEY); } catch {} }
      return {...m, content};
    }));
    return json(decrypted);
  }

  // Users list (for new chat) — filtered to co-family members
  if (path === '/api/users' && method === 'GET') {
    const coFamilyUsers = await env.DB.prepare(
      `SELECT DISTINCT u.id,u.name,u.role,u.avatar_color,u.avatar_url FROM users u
       JOIN family_members fm ON fm.user_id=u.id
       WHERE fm.family_id IN (SELECT family_id FROM family_members WHERE user_id=?)
       ORDER BY u.name`
    ).bind(user.id).all();
    return json(coFamilyUsers.results);
  }

  return null;
}

// ─── STORIES ─────────────────────────────────────────────────────────────────
async function handleStories(path, request, env, user) {
  const method = request.method;

  if (path === '/api/stories' && method === 'GET') {
    // Clean expired
    await env.DB.prepare("DELETE FROM stories WHERE expires_at <= datetime('now')").run();
    const stories = await env.DB.prepare(
      `SELECT s.*, u.name, u.avatar_color, u.avatar_url,
       (SELECT 1 FROM story_views WHERE story_id=s.id AND user_id=?) as seen
       FROM stories s JOIN users u ON s.user_id=u.id
       WHERE s.expires_at > datetime('now') ORDER BY s.created_at DESC`
    ).bind(user.id).all();
    return json(stories.results);
  }

  if (path === '/api/stories' && method === 'POST') {
    const ct = request.headers.get('content-type')||'';
    let content='', media_key=null, story_type='text', bg_color='#6366f1';
    if (ct.includes('multipart/form-data')) {
      const fd = await request.formData();
      content = fd.get('content')||'';
      bg_color = fd.get('bg_color')||bg_color;
      const file = fd.get('media');
      if (file && file.size > 0) {
        media_key = `stories/${user.id}/${Date.now()}.${file.name?.split('.').pop()||'jpg'}`;
        await env.PHOTOS.put(media_key, file.stream(), {httpMetadata:{contentType:file.type||'image/jpeg'}});
        story_type = 'image';
      }
    } else {
      const body = await request.json();
      content = body.content||''; bg_color = body.bg_color||bg_color; story_type = body.type||'text';
    }
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO stories (id,user_id,content,media_key,story_type,bg_color,expires_at) VALUES (?,?,?,?,?,?,datetime('now','+24 hours'))")
      .bind(id, user.id, content, media_key, story_type, bg_color).run();
    return json({id, ok:true}, 201);
  }

  const viewMatch = path.match(/^\/api\/stories\/([^/]+)\/view$/);
  if (viewMatch && method === 'POST') {
    const storyId = viewMatch[1];
    await env.DB.prepare('INSERT OR IGNORE INTO story_views (story_id,user_id) VALUES (?,?)').bind(storyId, user.id).run();
    return json({ok:true});
  }

  return null;
}

// ─── EVENTS / CALENDAR ───────────────────────────────────────────────────────
async function handleEvents(path, request, env, user) {
  const method = request.method;

  if (path === '/api/events' && method === 'GET') {
    const events = await env.DB.prepare(
      `SELECT e.*, u.name as creator_name,
       (SELECT COUNT(*) FROM event_rsvps WHERE event_id=e.id AND status='going') as going_count,
       (SELECT status FROM event_rsvps WHERE event_id=e.id AND user_id=?) as my_rsvp
       FROM events e JOIN users u ON e.created_by=u.id ORDER BY e.starts_at`
    ).bind(user.id).all();
    return json(events.results);
  }

  if (path === '/api/events' && method === 'POST') {
    const {title, description, starts_at, ends_at, location} = await request.json();
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO events (id,title,description,starts_at,ends_at,location,created_by) VALUES (?,?,?,?,?,?,?)')
      .bind(id, title, description||null, starts_at, ends_at||null, location||null, user.id).run();
    // Notify all users
    const users = await env.DB.prepare('SELECT id FROM users WHERE id!=?').bind(user.id).all();
    for (const u2 of users.results) {
      await createNotif(env, u2.id, 'event', `New event: ${title}`, `${user.name} added an event on ${starts_at.slice(0,10)}`, id, 'event');
    }
    return json({id, ok:true}, 201);
  }

  const rsvpMatch = path.match(/^\/api\/events\/([^/]+)\/rsvp$/);
  if (rsvpMatch && method === 'POST') {
    const eventId = rsvpMatch[1];
    const {status} = await request.json(); // going | maybe | no
    await env.DB.prepare('INSERT OR REPLACE INTO event_rsvps (event_id,user_id,status) VALUES (?,?,?)').bind(eventId, user.id, status).run();
    return json({ok:true});
  }

  return null;
}

// ─── TRANSFERS (fund) ─────────────────────────────────────────────────────────
async function handleTransfers(path, request, env, user) {
  const method = request.method;

  if (path === '/api/transfers' && method === 'GET') {
    const transfers = await env.DB.prepare(
      `SELECT t.*,
       uf.name as from_name, uf.avatar_color as from_color,
       ut.name as to_name, ut.avatar_color as to_color
       FROM transfers t
       JOIN users uf ON t.from_user_id=uf.id
       JOIN users ut ON t.to_user_id=ut.id
       WHERE t.from_user_id=? OR t.to_user_id=?
       ORDER BY t.created_at DESC LIMIT 50`
    ).bind(user.id, user.id).all();
    return json(transfers.results);
  }

  if (path === '/api/transfers/balance' && method === 'GET') {
    const sent = await env.DB.prepare("SELECT SUM(amount) as s FROM transfers WHERE from_user_id=? AND status='confirmed'").bind(user.id).first();
    const received = await env.DB.prepare("SELECT SUM(amount) as s FROM transfers WHERE to_user_id=? AND status='confirmed'").bind(user.id).first();
    // Per-user breakdown
    const balances = await env.DB.prepare(
      `SELECT
        CASE WHEN t.from_user_id=? THEN t.to_user_id ELSE t.from_user_id END as other_id,
        CASE WHEN t.from_user_id=? THEN -t.amount ELSE t.amount END as net,
        u.name as other_name
       FROM transfers t
       JOIN users u ON u.id = CASE WHEN t.from_user_id=? THEN t.to_user_id ELSE t.from_user_id END
       WHERE (t.from_user_id=? OR t.to_user_id=?) AND t.status='confirmed'`
    ).bind(user.id, user.id, user.id, user.id, user.id).all();
    // Aggregate by other_id
    const agg = {};
    for (const row of balances.results) {
      if (!agg[row.other_id]) agg[row.other_id] = {other_id:row.other_id, other_name:row.other_name, net:0};
      agg[row.other_id].net += row.net;
    }
    return json({total_sent: sent?.s||0, total_received: received?.s||0, balances: Object.values(agg)});
  }

  if (path === '/api/transfers' && method === 'POST') {
    const {to_user_id, amount, note, currency} = await request.json();
    if (!to_user_id || !amount || amount <= 0) return err('Invalid transfer');
    if (to_user_id === user.id) return err('Cannot transfer to yourself');
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO transfers (id,from_user_id,to_user_id,amount,currency,note,status) VALUES (?,?,?,?,?,?,?)')
      .bind(id, user.id, to_user_id, amount, currency||'EUR', note||null, 'pending').run();
    await createNotif(env, to_user_id, 'transfer', `${user.name} sent you €${amount}`, note||'Tap to confirm or reject', id, 'transfer');
    return json({id, ok:true}, 201);
  }

  const actionMatch = path.match(/^\/api\/transfers\/([^/]+)\/(confirm|reject)$/);
  if (actionMatch && method === 'POST') {
    const [, transferId, action] = actionMatch;
    const transfer = await env.DB.prepare('SELECT * FROM transfers WHERE id=?').bind(transferId).first();
    if (!transfer) return err('Not found', 404);
    if (transfer.to_user_id !== user.id) return err('Not your transfer', 403);
    if (transfer.status !== 'pending') return err('Already processed');
    await env.DB.prepare('UPDATE transfers SET status=? WHERE id=?').bind(action==='confirm'?'confirmed':'rejected', transferId).run();
    await createNotif(env, transfer.from_user_id, 'transfer', `Transfer ${action}ed`, `${user.name} ${action}ed your €${transfer.amount} transfer`, transferId, 'transfer');
    return json({ok:true});
  }

  return null;
}

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
// ─── NOTIFICATION PREFS ──────────────────────────────────────────────────────
async function handleNotifPrefs(path, request, env, user) {
  if (path === '/api/notification-prefs') {
    if (request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT type, enabled FROM notification_prefs WHERE user_id=?').bind(user.id).all();
      // Default all types to enabled if no row exists
      const types = ['post','comment','reaction','event','message','expense','transfer','chore','birthday','kk'];
      const map = Object.fromEntries(types.map(t => [t, 1]));
      for (const r of rows.results) map[r.type] = r.enabled;
      return json(map);
    }
    if (request.method === 'PUT') {
      const prefs = await request.json();
      for (const [type, enabled] of Object.entries(prefs)) {
        await env.DB.prepare('INSERT OR REPLACE INTO notification_prefs (user_id,type,enabled) VALUES (?,?,?)').bind(user.id, type, enabled ? 1 : 0).run();
      }
      return json({ok:true});
    }
  }
  return null;
}

async function handleNotifications(path, request, env, user) {
  const method = request.method;

  if (path === '/api/notifications' && method === 'GET') {
    const notifs = await env.DB.prepare(
      'SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50'
    ).bind(user.id).all();
    const unread = await env.DB.prepare('SELECT COUNT(*) as c FROM notifications WHERE user_id=? AND read=0').bind(user.id).first();
    return json({items: notifs.results, unread: unread?.c||0});
  }

  if (path === '/api/notifications/read-all' && method === 'POST') {
    await env.DB.prepare('UPDATE notifications SET read=1 WHERE user_id=?').bind(user.id).run();
    return json({ok:true});
  }

  const readMatch = path.match(/^\/api\/notifications\/([^/]+)\/read$/);
  if (readMatch && method === 'POST') {
    await env.DB.prepare('UPDATE notifications SET read=1 WHERE id=? AND user_id=?').bind(readMatch[1], user.id).run();
    return json({ok:true});
  }

  return null;
}

// ─── DOCUMENTS VAULT ─────────────────────────────────────────────────────────
async function handleDocuments(path, request, env, user) {
  const method = request.method;

  if (path === '/api/documents' && method === 'GET') {
    const mine = new URL(request.url).searchParams.get('mine') === '1';
    let docs;
    if (mine) {
      docs = await env.DB.prepare('SELECT id,name,doc_type,size_bytes,owner_id,created_at FROM documents WHERE owner_id=? ORDER BY created_at DESC').bind(user.id).all();
    } else {
      docs = await env.DB.prepare('SELECT d.id,d.name,d.doc_type,d.size_bytes,d.owner_id,d.created_at,u.name as owner_name FROM documents d JOIN users u ON d.owner_id=u.id WHERE d.shared=1 OR d.owner_id=? ORDER BY d.created_at DESC').bind(user.id).all();
    }
    return json(docs.results);
  }

  if (path === '/api/documents/upload' && method === 'POST') {
    const fd = await request.formData();
    const file = fd.get('file');
    const name = fd.get('name') || file?.name || 'Untitled';
    const shared = fd.get('shared') === '1' ? 1 : 0;
    const doc_type = fd.get('doc_type') || 'other';
    if (!file) return err('No file');

    const docId = crypto.randomUUID();
    const fileBytes = await file.arrayBuffer();
    const encrypted = await encryptDoc(new Uint8Array(fileBytes), docId, env.ENCRYPTION_KEY||'fallback-key');
    const key = `documents/${user.id}/${docId}`;
    await env.PHOTOS.put(key, encrypted, {httpMetadata:{contentType:'application/octet-stream'}});

    await env.DB.prepare('INSERT INTO documents (id,name,doc_type,r2_key,owner_id,shared,size_bytes) VALUES (?,?,?,?,?,?,?)')
      .bind(docId, name, doc_type, key, user.id, shared, file.size).run();

    return json({id:docId, ok:true}, 201);
  }

  const dlMatch = path.match(/^\/api\/documents\/([^/]+)\/download$/);
  if (dlMatch && method === 'GET') {
    const docId = dlMatch[1];
    const doc = await env.DB.prepare('SELECT * FROM documents WHERE id=?').bind(docId).first();
    if (!doc) return err('Not found', 404);
    if (doc.owner_id !== user.id && !doc.shared) return err('Forbidden', 403);
    const obj = await env.PHOTOS.get(doc.r2_key);
    if (!obj) return err('File not found', 404);
    const encrypted = new Uint8Array(await obj.arrayBuffer());
    const decrypted = await decryptDoc(encrypted, docId, env.ENCRYPTION_KEY||'fallback-key');
    if (!decrypted) return err('Decryption failed', 500);
    return new Response(decrypted, {headers:{
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="${doc.name}"`,
      'access-control-allow-origin': '*'
    }});
  }

  return null;
}


// Family Hub v2 - Part 3: Birthdays, Gifts, KK Draw, Expenses

async function handleBirthdays(path, request, env, user) {
  const method = request.method;

  if (path === '/api/birthdays' && method === 'GET') {
    const bdays = await env.DB.prepare(
      `SELECT b.*, u.name, u.avatar_color FROM birthdays b JOIN users u ON b.user_id=u.id ORDER BY
       CASE WHEN strftime('%m-%d', b.date) >= strftime('%m-%d','now')
       THEN strftime('%m-%d', b.date)
       ELSE strftime('%m-%d', b.date, '+1 year') END`
    ).all();
    return json(bdays.results);
  }

  if (path === '/api/birthdays' && method === 'POST') {
    const {date} = await request.json();
    await env.DB.prepare('INSERT OR REPLACE INTO birthdays (user_id,date) VALUES (?,?)').bind(user.id, date).run();
    return json({ok:true});
  }

  return null;
}

async function handleGifts(path, request, env, user) {
  const method = request.method;

  if (path === '/api/gifts' && method === 'GET') {
    const for_user = new URL(request.url).searchParams.get('user');
    let gifts;
    if (for_user) {
      // Don't show claimed_by to the person whose list it is
      if (for_user === user.id) {
        gifts = await env.DB.prepare('SELECT id,user_id,title,description,url,price,status FROM gifts WHERE user_id=? ORDER BY created_at DESC').bind(for_user).all();
      } else {
        gifts = await env.DB.prepare(
          `SELECT g.*, CASE WHEN g.claimed_by=? THEN 'you' WHEN g.claimed_by IS NOT NULL THEN 'someone' ELSE NULL END as claimed_by_label
           FROM gifts g WHERE g.user_id=? ORDER BY g.created_at DESC`
        ).bind(user.id, for_user).all();
      }
    } else {
      gifts = await env.DB.prepare('SELECT g.*,u.name as owner_name FROM gifts g JOIN users u ON g.user_id=u.id ORDER BY g.created_at DESC').all();
    }
    return json(gifts.results);
  }

  if (path === '/api/gifts' && method === 'POST') {
    const {title, description, url, price} = await request.json();
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO gifts (id,user_id,title,description,url,price) VALUES (?,?,?,?,?,?)').bind(id, user.id, title, description||null, url||null, price||null).run();
    return json({id, ok:true}, 201);
  }

  const claimMatch = path.match(/^\/api\/gifts\/([^/]+)\/claim$/);
  if (claimMatch && method === 'POST') {
    const giftId = claimMatch[1];
    const gift = await env.DB.prepare('SELECT * FROM gifts WHERE id=?').bind(giftId).first();
    if (!gift) return err('Not found', 404);
    if (gift.user_id === user.id) return err('Cannot claim your own gift');
    if (gift.claimed_by && gift.claimed_by !== user.id) return err('Already claimed');
    if (gift.claimed_by === user.id) {
      await env.DB.prepare("UPDATE gifts SET claimed_by=NULL,status='available' WHERE id=?").bind(giftId).run();
    } else {
      await env.DB.prepare("UPDATE gifts SET claimed_by=?,status='claimed' WHERE id=?").bind(user.id, giftId).run();
    }
    return json({ok:true});
  }

  const deleteGiftMatch = path.match(/^\/api\/gifts\/([^/]+)$/);
  if (deleteGiftMatch && method === 'DELETE') {
    const giftId = deleteGiftMatch[1];
    const gift = await env.DB.prepare('SELECT * FROM gifts WHERE id=?').bind(giftId).first();
    if (!gift) return err('Not found', 404);
    if (gift.user_id !== user.id) return err('Forbidden', 403);
    await env.DB.prepare('DELETE FROM gifts WHERE id=?').bind(giftId).run();
    return json({ok:true});
  }

  return null;
}

async function handleKK(path, request, env, user) {
  const method = request.method;

  if (path === '/api/kk' && method === 'GET') {
    const year = new URL(request.url).searchParams.get('year') || new Date().getFullYear();
    const draw = await env.DB.prepare('SELECT * FROM kk_draws WHERE year=?').bind(year).first();
    if (!draw) return json(null);
    const participants = await env.DB.prepare(
      'SELECT kp.*,u.name,u.avatar_color FROM kk_participants kp JOIN users u ON kp.user_id=u.id WHERE kp.draw_id=?'
    ).bind(draw.id).all();
    let my_assignment = null;
    if (draw.drawn) {
      const assign = await env.DB.prepare('SELECT * FROM kk_assignments WHERE draw_id=? AND giver_id=?').bind(draw.id, user.id).first();
      if (assign) {
        const recipient = await env.DB.prepare('SELECT id,name,avatar_color FROM users WHERE id=?').bind(assign.recipient_id).first();
        my_assignment = recipient;
      }
    }
    return json({...draw, participants: participants.results, my_assignment});
  }

  if (path === '/api/kk' && method === 'POST') {
    const {year, budget} = await request.json();
    const existing = await env.DB.prepare('SELECT id FROM kk_draws WHERE year=?').bind(year).first();
    if (existing) return err('Draw for this year exists');
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO kk_draws (id,year,budget,created_by) VALUES (?,?,?,?)').bind(id, year, budget||50, user.id).run();
    return json({id, ok:true}, 201);
  }

  if (path === '/api/kk/join' && method === 'POST') {
    const {draw_id, wish} = await request.json();
    await env.DB.prepare('INSERT OR REPLACE INTO kk_participants (draw_id,user_id,wish) VALUES (?,?,?)').bind(draw_id, user.id, wish||null).run();
    return json({ok:true});
  }

  if (path === '/api/kk/draw' && method === 'POST') {
    const {draw_id} = await request.json();
    const draw = await env.DB.prepare('SELECT * FROM kk_draws WHERE id=?').bind(draw_id).first();
    if (!draw) return err('Draw not found', 404);
    if (draw.drawn) return err('Already drawn');

    const participants = await env.DB.prepare('SELECT user_id FROM kk_participants WHERE draw_id=?').bind(draw_id).all();
    const ids = participants.results.map(p => p.user_id);
    if (ids.length < 2) return err('Need at least 2 participants');

    // Shuffle with Fisher-Yates
    const shuffled = [...ids];
    for (let i = shuffled.length-1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i+1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    // Assign: person[i] gives to person[i+1], last gives to first
    for (let i=0; i<ids.length; i++) {
      const giver = ids[i];
      const recipient = shuffled[(i+1) % shuffled.length] === giver ? shuffled[i] : shuffled[(i+1) % shuffled.length];
      // Simple valid assignment
      await env.DB.prepare('INSERT INTO kk_assignments (draw_id,giver_id,recipient_id) VALUES (?,?,?)').bind(draw_id, ids[i], shuffled[i===ids.length-1?0:i+1]).run();
      await createNotif(env, ids[i], 'kk', '🎅 KK Draw Complete!', `You have your secret santa assignment! Check the KK tab.`, draw_id, 'kk');
    }
    await env.DB.prepare('UPDATE kk_draws SET drawn=1 WHERE id=?').bind(draw_id).run();
    return json({ok:true});
  }

  return null;
}

async function handleExpenses(path, request, env, user) {
  const method = request.method;

  if (path === '/api/expenses' && method === 'GET') {
    const expenses = await env.DB.prepare(
      `SELECT e.*,u.name as paid_by_name,u.avatar_color
       FROM expenses e JOIN users u ON e.paid_by=u.id
       ORDER BY e.created_at DESC LIMIT 100`
    ).all();
    const results = await Promise.all(expenses.results.map(async exp => {
      const splits = await env.DB.prepare(
        'SELECT es.*,u.name FROM expense_splits es JOIN users u ON es.user_id=u.id WHERE es.expense_id=?'
      ).bind(exp.id).all();
      return {...exp, splits: splits.results};
    }));
    return json(results);
  }

  if (path === '/api/expenses/summary' && method === 'GET') {
    const owed_to_me = await env.DB.prepare(
      "SELECT SUM(amount) as s FROM expense_splits WHERE user_id!=? AND expense_id IN (SELECT id FROM expenses WHERE paid_by=?) AND settled=0"
    ).bind(user.id, user.id).first();
    const i_owe = await env.DB.prepare(
      "SELECT SUM(amount) as s FROM expense_splits WHERE user_id=? AND settled=0 AND expense_id NOT IN (SELECT id FROM expenses WHERE paid_by=?)"
    ).bind(user.id, user.id).first();
    return json({owed_to_me: owed_to_me?.s||0, i_owe: i_owe?.s||0});
  }

  if (path === '/api/expenses' && method === 'POST') {
    const {description, amount, currency, category, splits} = await request.json();
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO expenses (id,description,amount,currency,category,paid_by) VALUES (?,?,?,?,?,?)')
      .bind(id, description, amount, currency||'EUR', category||'other', user.id).run();
    for (const split of (splits||[])) {
      await env.DB.prepare('INSERT INTO expense_splits (expense_id,user_id,amount) VALUES (?,?,?)').bind(id, split.user_id, split.amount).run();
      if (split.user_id !== user.id) {
        await createNotif(env, split.user_id, 'expense', `${user.name} added an expense`, `You owe €${split.amount} for "${description}"`, id, 'expense');
      }
    }
    return json({id, ok:true}, 201);
  }

  const settleMatch = path.match(/^\/api\/expenses\/([^/]+)\/settle$/);
  if (settleMatch && method === 'POST') {
    const expId = settleMatch[1];
    await env.DB.prepare('UPDATE expense_splits SET settled=1 WHERE expense_id=? AND user_id=?').bind(expId, user.id).run();
    return json({ok:true});
  }

  return null;
}


function getSPA() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Family Hub">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#6366f1">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<title>Family Hub 🏠</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1e;color:#f0f4ff;min-height:100vh}
:root{--primary:#818cf8;--primary-dark:#6366f1;--primary-glow:rgba(129,140,248,.25);--surface:#141b2d;--surface2:#1e2942;--surface3:#253352;--border:#2a3a5c;--text:#f0f4ff;--muted:#7e8fb5;--danger:#f87171;--success:#34d399;--warning:#fbbf24;--card-shadow:0 2px 12px rgba(0,0,0,.35);--glow-shadow:0 0 20px rgba(129,140,248,.15)}
.app{max-width:480px;margin:0 auto;min-height:100vh;display:flex;flex-direction:column;position:relative}
/* NAV */
.bottom-nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);width:100%;max-width:480px;background:rgba(14,19,36,.92);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-top:1px solid var(--border);display:flex;z-index:100;padding-bottom:env(safe-area-inset-bottom)}
.nav-item{flex:1;display:flex;flex-direction:column;align-items:center;padding:10px 0 8px;cursor:pointer;color:var(--muted);font-size:10px;gap:3px;transition:all .2s;position:relative}
.nav-item.active{color:var(--primary)}
.nav-item.active svg{filter:drop-shadow(0 0 6px var(--primary))}
.nav-item svg{width:22px;height:22px}
.nav-badge{position:absolute;top:4px;right:calc(50% - 18px);background:var(--danger);color:#fff;font-size:9px;border-radius:99px;padding:1px 4px;min-width:16px;text-align:center}
/* HEADER */
.header{position:sticky;top:0;background:rgba(14,19,36,.92);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);z-index:50;padding:12px 16px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border)}
.header h1{font-size:18px;font-weight:700;flex:1}
.header-actions{display:flex;gap:8px}
/* SCREENS */
.screen{display:none;flex:1;flex-direction:column;padding-bottom:70px}
.screen.active{display:flex}
/* CARDS */
.card{background:var(--surface2);border-radius:16px;padding:16px;margin:0 12px 12px;border:1px solid var(--border);box-shadow:var(--card-shadow)}
.card-header{display:flex;align-items:center;gap:10px;margin-bottom:12px}
/* AVATAR */
.avatar{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:16px;flex-shrink:0;overflow:hidden;box-shadow:0 0 0 2px rgba(255,255,255,.06)}
.avatar img{width:100%;height:100%;object-fit:cover}
.avatar-sm{width:30px;height:30px;font-size:12px}
.avatar-lg{width:56px;height:56px;font-size:22px}
/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 18px;border-radius:12px;border:none;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s}
.btn-primary{background:linear-gradient(135deg,#818cf8,#6366f1);color:#fff;box-shadow:0 4px 14px rgba(99,102,241,.4)}
.btn-primary:hover{background:linear-gradient(135deg,#9aa5fb,#818cf8);transform:translateY(-1px);box-shadow:0 6px 20px rgba(99,102,241,.5)}
.btn-primary:active{transform:translateY(0)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
.btn-danger{background:var(--danger);color:#fff}
.btn-sm{padding:6px 12px;font-size:13px}
.btn-full{width:100%;justify-content:center}
.btn:disabled{opacity:.5;cursor:not-allowed}
/* INPUTS */
.input-group{margin-bottom:14px}
.input-group label{display:block;font-size:13px;color:var(--muted);margin-bottom:4px}
input,textarea,select,.input{width:100%;padding:10px 12px;background:var(--surface2);border:1.5px solid var(--border);border-radius:10px;color:var(--text);font-size:15px;font-family:inherit;outline:none;transition:all .15s}
input:focus,textarea:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);background:var(--surface3)}
textarea{resize:vertical;min-height:80px}
/* MODAL */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;display:flex;align-items:flex-end;justify-content:center;opacity:0;pointer-events:none;transition:opacity .25s}
.modal-overlay.open{opacity:1;pointer-events:all}
.modal{background:var(--surface2);border-radius:24px 24px 0 0;width:100%;max-width:480px;padding:20px 16px;max-height:90vh;overflow-y:auto;transform:translateY(100%);transition:transform .3s cubic-bezier(.32,.72,0,1);border:1px solid var(--border);border-bottom:none}
.modal-overlay.open .modal{transform:translateY(0)}
.modal-handle{width:40px;height:4px;background:var(--border);border-radius:2px;margin:0 auto 16px}
.modal h2{font-size:18px;font-weight:700;margin-bottom:16px}
/* CHAT */
.chat-list .chat-item{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;transition:background .15s;border-bottom:1px solid var(--border)}
.chat-item:hover{background:var(--surface2)}
.chat-meta{flex:1;min-width:0}
.chat-meta h3{font-size:15px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-meta p{font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-time{font-size:11px;color:var(--muted)}
/* MESSAGES */
.msg-bubble{max-width:75%;padding:10px 14px;border-radius:18px;font-size:15px;line-height:1.4;word-break:break-word}
.msg-bubble.mine{background:linear-gradient(135deg,#818cf8,#6366f1);color:#fff;border-bottom-right-radius:4px;align-self:flex-end;box-shadow:0 2px 8px rgba(99,102,241,.4)}
.msg-bubble.theirs{background:var(--surface3);border-bottom-left-radius:4px;align-self:flex-start;border:1px solid var(--border)}
.msg-row{display:flex;flex-direction:column;margin-bottom:4px;padding:0 12px}
.msg-sender{font-size:11px;color:var(--muted);margin-bottom:2px}
.msg-reactions{display:flex;gap:4px;margin-top:4px;flex-wrap:wrap}
.reaction-pill{background:var(--surface2);border-radius:99px;padding:2px 8px;font-size:12px;cursor:pointer;border:1px solid transparent}
.reaction-pill:hover{border-color:var(--primary)}
/* STORIES */
.stories-strip{display:flex;gap:10px;overflow-x:auto;padding:12px 16px;scrollbar-width:none}
.stories-strip::-webkit-scrollbar{display:none}
.story-item{display:flex;flex-direction:column;align-items:center;gap:4px;cursor:pointer;flex-shrink:0}
.story-ring{width:58px;height:58px;border-radius:50%;padding:2px;background:linear-gradient(45deg,#f09433,#e6683c,#dc2743,#cc2366,#bc1888);position:relative}
.story-ring.seen{background:var(--border)}
.story-ring .avatar{width:100%;height:100%;border:2px solid var(--surface)}
.story-item span{font-size:11px;color:var(--muted);max-width:60px;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* FEED POST */
.post-card{background:var(--surface2);margin:8px 12px;border-radius:16px;border:1px solid var(--border);box-shadow:var(--card-shadow);overflow:hidden}
.post-header{display:flex;align-items:center;gap:12px;padding:14px 16px 8px}
.post-content{padding:0 16px;font-size:15px;line-height:1.5;margin-bottom:10px}
.post-media{display:grid;gap:2px;margin-bottom:10px}
.post-media.count-1 img{width:100%;max-height:400px;object-fit:cover}
.post-media.count-2{grid-template-columns:1fr 1fr}
.post-media img{width:100%;height:180px;object-fit:cover;cursor:pointer}
.post-actions{display:flex;gap:0;border-top:1px solid var(--border);padding:2px 8px 2px;flex-wrap:wrap;position:relative;background:rgba(0,0,0,.15)}
.post-delete-btn{background:none;border:none;cursor:pointer;font-size:16px;color:var(--muted);padding:4px 8px;border-radius:6px;opacity:.5;transition:opacity .15s;margin-left:auto}
.post-delete-btn:hover{opacity:1;color:#ef4444}
.react-picker{display:flex;gap:4px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:24px;box-shadow:0 4px 16px rgba(0,0,0,.2);margin:4px 8px;z-index:100;width:calc(100% - 16px)}
.react-picker span{font-size:22px;cursor:pointer;transition:transform .1s;flex:1;text-align:center}
.react-picker span:hover{transform:scale(1.3)}
.post-action{flex:1;display:flex;align-items:center;justify-content:center;gap:6px;padding:8px;border-radius:8px;cursor:pointer;font-size:13px;color:var(--muted);transition:all .15s}
.post-action:hover{background:var(--surface2);color:var(--text)}
.comment-sheet{position:fixed;inset:0;z-index:200;display:flex;flex-direction:column;justify-content:flex-end;background:rgba(0,0,0,.5);opacity:0;pointer-events:none;transition:opacity .25s}
.comment-sheet.open{opacity:1;pointer-events:all}
.comment-sheet-inner{background:var(--surface2);border-radius:20px 20px 0 0;display:flex;flex-direction:column;max-height:85vh;transform:translateY(100%);transition:transform .3s cubic-bezier(.32,.72,0,1);border:1px solid var(--border);border-bottom:none}
.comment-sheet.open .comment-sheet-inner{transform:translateY(0)}
.comment-list{flex:1;overflow-y:auto;padding:12px 16px}
.comment-bubble{display:flex;gap:10px;margin-bottom:14px}
.comment-bubble-body{background:var(--surface2);border-radius:0 12px 12px 12px;padding:8px 12px;flex:1}
.comment-bubble-name{font-size:12px;font-weight:700;color:var(--primary);margin-bottom:2px}
.comment-bubble-text{font-size:14px;line-height:1.4}
.comment-bubble-time{font-size:11px;color:var(--muted);margin-top:2px}
.comment-input-row{display:flex;gap:8px;padding:12px 16px;border-top:1px solid var(--border);background:var(--surface)}
.post-action.liked{color:#ef4444}
/* PILLS / TABS */
.tabs{display:flex;gap:6px;padding:12px 16px 0;overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{padding:6px 14px;border-radius:99px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;border:1px solid var(--border);color:var(--muted);transition:all .15s}
.tab.active{background:var(--primary);color:#fff;border-color:var(--primary)}
/* EXPENSE / TRANSFER */
.amount-badge{font-weight:700;font-size:15px}
.amount-badge.positive{color:var(--success)}
.amount-badge.negative{color:var(--danger)}
/* UTILITIES */
.flex{display:flex}.flex-col{flex-direction:column}.items-center{align-items:center}.justify-between{justify-content:space-between}.gap-2{gap:8px}.gap-3{gap:12px}.mt-2{margin-top:8px}.mt-3{margin-top:12px}.text-muted{color:var(--muted)}.text-sm{font-size:13px}.text-xs{font-size:11px}.font-bold{font-weight:700}.p-4{padding:16px}.px-4{padding-left:16px;padding-right:16px}.py-2{padding-top:8px;padding-bottom:8px}.rounded-lg{border-radius:12px}.w-full{width:100%}
.empty-state{display:flex;flex-direction:column;align-items:center;gap:12px;padding:48px 16px;color:var(--muted);text-align:center}
.empty-state .icon{font-size:48px}
.spinner{width:24px;height:24px;border:3px solid var(--border);border-top-color:var(--primary);border-radius:50%;animation:spin .8s linear infinite;margin:32px auto}
@keyframes spin{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:80px;left:50%;transform:translateX(-50%) translateY(4px);background:rgba(20,27,45,.96);backdrop-filter:blur(12px);color:#f0f4ff;padding:11px 22px;border-radius:14px;font-size:14px;font-weight:500;z-index:500;box-shadow:0 4px 24px rgba(0,0,0,.5),0 0 0 1px var(--border);opacity:0;transition:opacity .3s,transform .3s;pointer-events:none}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
/* AUTH */
.auth-screen{position:fixed;inset:0;background:radial-gradient(ellipse at 30% 20%,#1e1b4b 0%,#0a0f1e 55%,#1a0f3b 100%);z-index:300;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;overflow-y:auto}
.auth-screen h1{font-size:30px;font-weight:800;margin-bottom:4px}
.auth-screen>p{color:var(--muted);margin-bottom:24px;text-align:center;font-size:14px}
.auth-card{background:rgba(20,27,45,.75);backdrop-filter:blur(20px);border:1px solid rgba(129,140,248,.25);border-radius:24px;padding:28px 22px;width:100%;max-width:380px;box-shadow:0 16px 48px rgba(0,0,0,.5),var(--glow-shadow)}
.auth-tabs{display:flex;background:rgba(15,23,42,.6);border-radius:12px;padding:4px;margin-bottom:24px;gap:4px}
.auth-tab{flex:1;text-align:center;padding:10px;border-radius:9px;cursor:pointer;font-size:14px;font-weight:600;color:var(--muted);transition:all .2s;-webkit-tap-highlight-color:transparent;user-select:none}
.auth-tab.active{background:var(--primary);color:#fff;box-shadow:0 2px 8px rgba(99,102,241,.4)}
.auth-field{margin-bottom:16px}
.auth-field label{display:block;font-size:11px;font-weight:700;color:#94a3b8;margin-bottom:6px;text-transform:uppercase;letter-spacing:.6px}
.auth-field-inner{position:relative}
.auth-field input{width:100%;padding:14px 16px;background:rgba(15,23,42,.8);border:1.5px solid rgba(99,102,241,.2);border-radius:12px;color:var(--text);font-size:16px;outline:none;-webkit-appearance:none;transition:border .2s}
.auth-field input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,.12)}
.auth-field input::placeholder{color:#475569}
.auth-eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:#64748b;cursor:pointer;font-size:18px;padding:4px;line-height:1;-webkit-tap-highlight-color:transparent}
.auth-error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);border-radius:10px;color:#fca5a5;font-size:13px;padding:10px 14px;margin-bottom:14px;display:none;line-height:1.4}
.auth-btn{width:100%;padding:15px;background:var(--primary);color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer;-webkit-tap-highlight-color:transparent;margin-top:4px;box-shadow:0 4px 14px rgba(99,102,241,.35);transition:transform .1s,opacity .15s}
.auth-btn:active{transform:scale(.97);opacity:.9}
.auth-btn:disabled{opacity:.55;cursor:not-allowed}
.auth-divider{text-align:center;color:#475569;font-size:12px;margin:12px 0 16px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
/* CHAT SCREEN */
.chat-screen{position:fixed;inset:0;background:#0a0f1e;z-index:200;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .3s cubic-bezier(.32,.72,0,1)}
.chat-screen.open{transform:translateX(0)}
.chat-messages{flex:1;overflow-y:auto;padding:12px 0;display:flex;flex-direction:column}
.chat-messages.photo-mode { display:grid; grid-template-columns:1fr 1fr; gap:3px; padding:3px; align-content:start; }
.photo-grid-item { position:relative; aspect-ratio:1; overflow:hidden; cursor:pointer; background:var(--surface2); border-radius:4px; }
.photo-grid-item img { width:100%; height:100%; object-fit:cover; display:block; }
.photo-grid-caption { position:absolute; bottom:0; left:0; right:0; padding:4px 6px; background:linear-gradient(transparent,rgba(0,0,0,.65)); color:#fff; font-size:10px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.chat-input-bar{padding:8px 12px;background:rgba(14,19,36,.92);backdrop-filter:blur(16px);border-top:1px solid var(--border);display:flex;gap:8px;align-items:flex-end;padding-bottom:calc(8px + env(safe-area-inset-bottom))}
.chat-input-bar textarea{flex:1;min-height:38px;max-height:120px;border-radius:20px;padding:8px 14px;font-size:15px;resize:none;line-height:1.4}
.send-btn{width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,#818cf8,#6366f1);border:none;color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 2px 8px rgba(99,102,241,.4);transition:transform .1s,box-shadow .1s}
.send-btn:active{transform:scale(.92)}
/* STORY VIEWER */
.story-viewer{position:fixed;inset:0;background:#000;z-index:400;display:flex;flex-direction:column}
.story-progress{display:flex;gap:3px;padding:12px}
.story-progress .bar{flex:1;height:3px;background:rgba(255,255,255,.3);border-radius:2px}
.story-progress .bar.done{background:#fff}
.story-progress .bar.active{background:#fff;animation:progress-fill linear forwards}
@keyframes progress-fill{from{transform-origin:left;transform:scaleX(0)}to{transform-origin:left;transform:scaleX(1)}}
.story-content{flex:1;display:flex;align-items:center;justify-content:center;padding:20px;text-align:center;font-size:20px;font-weight:600;word-break:break-word}
/* EVENTS */
.event-card{background:var(--surface2);border-radius:14px;padding:14px;margin:0 12px 10px;border-left:4px solid var(--primary);border:1px solid var(--border);border-left:4px solid var(--primary);box-shadow:var(--card-shadow)}
.event-date{font-size:12px;color:var(--primary);font-weight:700;text-transform:uppercase;margin-bottom:4px}
/* TRANSFERS */
.transfer-item{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border)}
/* VAULT */
.doc-item{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border);cursor:pointer}
.doc-icon{width:40px;height:40px;border-radius:10px;background:var(--primary);display:flex;align-items:center;justify-content:center;font-size:20px}
/* EXPENSE */
.expense-item{padding:14px 16px;border-bottom:1px solid var(--border)}

/* TOGGLE SWITCH */
.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)}
.toggle-row:last-child{border-bottom:none}
.toggle-label{font-size:14px;color:var(--text)}
.toggle{position:relative;width:44px;height:24px}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;cursor:pointer;inset:0;background:var(--surface2);border-radius:24px;transition:.2s}
.toggle-slider:before{content:'';position:absolute;width:18px;height:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.toggle input:checked+.toggle-slider{background:var(--primary)}
.toggle input:checked+.toggle-slider:before{transform:translateX(20px)}
/* TABS SCROLLABLE */
#moreTabs{overflow-x:auto;white-space:nowrap;scrollbar-width:none;-ms-overflow-style:none;display:flex;gap:4px;padding-bottom:2px}
#moreTabs::-webkit-scrollbar{display:none}
#moreTabs .tab{display:inline-block;flex-shrink:0}
/* TIMELINE */
.timeline{position:relative;padding-left:24px}
.timeline::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}
.timeline-item{position:relative;margin-bottom:20px}
.timeline-dot{position:absolute;left:-20px;top:4px;width:12px;height:12px;border-radius:50%;background:var(--primary);border:2px solid var(--surface)}
/* RECIPE GRID */
.recipe-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.recipe-card{background:var(--surface);border-radius:12px;padding:14px;cursor:pointer;border:1px solid var(--border)}
.recipe-card h4{font-size:14px;font-weight:600;margin-bottom:4px}
.recipe-card p{font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.recipe-expanded{background:var(--surface);border-radius:12px;padding:16px;margin-top:8px}
.recipe-expanded h3{font-size:16px;font-weight:700;margin-bottom:8px}
.recipe-expanded pre{white-space:pre-wrap;font-family:inherit;font-size:13px;color:var(--muted)}
/* MEAL ROTA */
.meal-grid{display:grid;grid-template-columns:1fr;gap:8px}
.meal-day{background:var(--surface);border-radius:10px;padding:12px;display:flex;align-items:center;gap:12px;cursor:pointer}
.meal-day-name{width:36px;font-size:12px;font-weight:700;color:var(--primary);flex-shrink:0}
.meal-day-content{flex:1}
.meal-day-meal{font-size:14px;font-weight:500}
.meal-day-cook{font-size:12px;color:var(--muted)}
.meal-edit-form{background:var(--surface2);border-radius:8px;padding:12px;margin-top:4px}
/* SHOPPING */
.shopping-item{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)}
.shopping-item.done .shopping-title{text-decoration:line-through;color:var(--muted)}
.shopping-cb{width:20px;height:20px;cursor:pointer;accent-color:var(--primary)}
.shopping-title{flex:1;font-size:14px}
.cat-badge{font-size:10px;padding:2px 6px;border-radius:99px;background:var(--surface2);color:var(--muted)}
/* CHORE */
.chore-card{background:var(--surface2);border-radius:12px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px;border:1px solid var(--border)}
.chore-info{flex:1}
.chore-title{font-size:14px;font-weight:600}
.chore-meta{font-size:12px;color:var(--muted);margin-top:2px}
.points-badge{background:#fbbf24;color:#000;font-size:11px;padding:2px 7px;border-radius:99px;font-weight:700}
.done-btn{background:var(--success);color:#fff;border:none;border-radius:8px;padding:7px 12px;font-size:12px;cursor:pointer;white-space:nowrap}
/* KINDNESS */
.kindness-card{background:var(--surface);border-radius:12px;padding:14px;margin-bottom:10px;border-left:3px solid #fbbf24}
.kindness-card.done{border-left-color:var(--surface2);opacity:.6}
/* FAMILY SETTINGS OVERLAY */
#familySettingsScreen{position:fixed;inset:0;background:#0a0f1e;z-index:200;display:none;flex-direction:column;overflow-y:auto}
#familySettingsScreen.open{display:flex}
.fs-header{display:flex;align-items:center;padding:16px;gap:12px;border-bottom:1px solid var(--border);position:sticky;top:0;background:rgba(10,15,30,.92);backdrop-filter:blur(16px);z-index:10}
.fs-section{padding:16px;border-bottom:1px solid var(--border)}
.fs-section h3{font-size:16px;font-weight:700;margin-bottom:12px}
/* AVATAR UPLOAD */
.avatar-wrap{position:relative;cursor:pointer;display:inline-block}
.avatar-cam{position:absolute;bottom:0;right:0;background:var(--primary);border-radius:50%;width:20px;height:20px;display:flex;align-items:center;justify-content:center;font-size:11px}
/* PARTY PLANNER */
.bring-list{margin-top:10px;background:var(--surface2);border-radius:10px;padding:12px}
.bring-item{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px}
.bring-item:last-child{border-bottom:none}
.bring-claimed{font-size:11px;color:var(--success);font-weight:600}
/* EMERGENCY */
.emergency-card{background:#7f1d1d22;border:1px solid #ef444433;border-radius:12px;padding:14px}
.emergency-row{display:flex;gap:8px;margin-bottom:6px;font-size:13px}
.emergency-label{color:var(--muted);width:90px;flex-shrink:0}
.invite-code-box{background:var(--surface2);border-radius:8px;padding:10px 14px;font-family:monospace;font-size:18px;letter-spacing:3px;display:flex;align-items:center;justify-content:space-between}
/* FEED DIGEST HEADER */
.feed-digest{background:linear-gradient(135deg,rgba(99,102,241,.15),rgba(168,85,247,.08));border:1px solid rgba(129,140,248,.2);border-radius:16px;margin:10px 12px 4px;padding:12px 14px;backdrop-filter:blur(8px)}
.feed-digest-title{font-size:11px;font-weight:700;color:var(--primary);text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px;display:flex;align-items:center;gap:6px}
.digest-row{display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);cursor:pointer}
.digest-row:last-child{border-bottom:none}
.digest-date-pill{background:rgba(129,140,248,.2);color:var(--primary);border-radius:7px;padding:3px 8px;text-align:center;min-width:38px;flex-shrink:0}
.digest-date-pill .mo{font-size:9px;font-weight:700;text-transform:uppercase}
.digest-date-pill .dy{font-size:16px;font-weight:800;line-height:1.1}
/* LEADERBOARD */
.leaderboard{background:linear-gradient(135deg,rgba(251,191,36,.08),rgba(251,191,36,.03));border:1px solid rgba(251,191,36,.2);border-radius:14px;padding:12px 14px;margin-bottom:14px}
.leaderboard-title{font-size:12px;font-weight:700;color:#fbbf24;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.lb-row{display:flex;align-items:center;gap:10px;padding:4px 0}
.lb-rank{width:22px;height:22px;border-radius:50%;background:rgba(251,191,36,.15);color:#fbbf24;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.lb-rank.gold{background:#fbbf24;color:#000}
.lb-pts{margin-left:auto;font-weight:700;font-size:13px;color:#fbbf24}
/* SHOPPING CATEGORIES */
.shop-cat-header{font-size:11px;font-weight:700;color:var(--primary);text-transform:uppercase;letter-spacing:.5px;padding:10px 0 4px;border-bottom:1px solid var(--border);margin-bottom:4px}
/* CLEAR DONE BTN */
.clear-done-btn{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.25);color:#f87171;border-radius:8px;padding:5px 12px;font-size:12px;font-weight:600;cursor:pointer;transition:all .15s}
.clear-done-btn:hover{background:rgba(248,113,113,.2)}
/* REACTION LIKED */
.post-action.liked span:first-child{filter:drop-shadow(0 0 4px rgba(248,113,113,.8))}
/* SCROLL INERTIA */
#feedList,#chatMessages,.comment-list{-webkit-overflow-scrolling:touch}
/* SHIMMER SKELETON */
@keyframes shimmer{0%{background-position:-200%}100%{background-position:200%}}
.skeleton{background:linear-gradient(90deg,var(--surface2) 25%,var(--surface3) 50%,var(--surface2) 75%);background-size:200%;animation:shimmer 1.2s infinite;border-radius:8px}
</style>
</head>
<body>
<div class="app" id="app">
  <!-- AUTH -->
  <div class="auth-screen" id="authScreen">
    <div style="font-size:54px;margin-bottom:10px;filter:drop-shadow(0 4px 16px rgba(99,102,241,.5))">🏠</div>
    <h1>Family Hub</h1>
    <p>Your private family space</p>
    <div class="auth-card">
      <div class="auth-tabs">
        <div class="auth-tab active" onclick="switchAuthTab('login')">Log In</div>
        <div class="auth-tab" onclick="switchAuthTab('invite')">Join Family</div>
      </div>
      <div id="loginForm">
        <div id="loginError" class="auth-error"></div>
        <div class="auth-field">
          <label>Email</label>
          <div class="auth-field-inner">
            <input type="email" id="loginEmail" placeholder="your@email.com" autocomplete="email" autocapitalize="none" spellcheck="false" onkeydown="if(event.key==='Enter')document.getElementById('loginPass').focus()">
          </div>
        </div>
        <div class="auth-field">
          <label>Password</label>
          <div class="auth-field-inner">
            <input type="password" id="loginPass" placeholder="Your password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()" style="padding-right:44px">
            <button class="auth-eye" type="button" onclick="togglePwd('loginPass',this)" tabindex="-1">👁</button>
          </div>
        </div>
        <button class="auth-btn" id="loginBtn" onclick="doLogin()">Log In</button>
      </div>
      <div id="inviteForm" style="display:none">
        <div id="inviteError" class="auth-error"></div>
        <div class="auth-field">
          <label>Invite Link or Code</label>
          <div class="auth-field-inner">
            <input type="text" id="inviteCode" placeholder="Paste your invite link here" autocomplete="off" autocapitalize="none" spellcheck="false">
          </div>
        </div>
        <div id="inviteNameRow" style="display:none">
          <div class="auth-divider">Set up your account</div>
          <div class="auth-field">
            <label>Your Name</label>
            <div class="auth-field-inner">
              <input type="text" id="inviteName" placeholder="As the family knows you" autocapitalize="words" autocomplete="name">
            </div>
          </div>
          <div class="auth-field">
            <label>Email <span style="font-weight:400;color:#64748b">(to log in later)</span></label>
            <div class="auth-field-inner">
              <input type="email" id="inviteEmail" placeholder="your@email.com" autocomplete="email" autocapitalize="none" spellcheck="false">
            </div>
          </div>
          <div class="auth-field">
            <label>Choose Password</label>
            <div class="auth-field-inner">
              <input type="password" id="invitePass" placeholder="Min 6 characters" autocomplete="new-password" onkeydown="if(event.key==='Enter')doInviteNext()" style="padding-right:44px">
              <button class="auth-eye" type="button" onclick="togglePwd('invitePass',this)" tabindex="-1">👁</button>
            </div>
          </div>
        </div>
        <button class="auth-btn" onclick="doInviteNext()" id="inviteBtn">Check Code →</button>
      </div>
    </div>
    <p style="margin-top:16px;font-size:11px;color:#334155">hub.luckdragon.io</p>
  </div>

  <!-- MAIN APP -->
  <div id="mainApp" style="display:none;flex:1;flex-direction:column">
    <!-- Stories strip (shown above feed) -->
    <div id="storiesWrap" style="background:var(--surface);border-bottom:1px solid var(--border);display:none">
      <div class="stories-strip" id="storiesStrip"></div>
    </div>

    <!-- FEED -->
    <div class="screen active" id="screenFeed">
      <div class="header">
        <div style="font-size:22px">🏠</div>
        <h1>Family Hub</h1>
        <div class="header-actions">
          <button class="btn btn-sm btn-ghost" onclick="openModal('newPostModal')">+ Post</button>
        </div>
      </div>
      <div id="feedList" style="flex:1;overflow-y:auto"></div>
    </div>

    <!-- CHATS -->
    <div class="screen" id="screenChats">
      <div class="header">
        <h1>💬 Chats</h1>
        <button class="btn btn-sm btn-ghost" onclick="openModal('newChatModal')">+ New</button>
      </div>
      <div class="chat-list" id="chatList" style="flex:1;overflow-y:auto"></div>
    </div>

    <!-- EVENTS -->
    <div class="screen" id="screenEvents">
      <div class="header">
        <h1>📅 Events</h1>
        <button class="btn btn-sm btn-ghost" onclick="openModal('newEventModal')">+ Add</button>
      </div>
      <div id="eventsList" style="flex:1;overflow-y:auto;padding:12px 0"></div>
    </div>

    <!-- MORE (Birthdays, Gifts, KK, Expenses, Transfers, Vault) -->
    <div class="screen" id="screenMore">
      <div class="header"><h1>⋯ More</h1></div>
      <div class="tabs" id="moreTabs">
        <div class="tab active" onclick="switchMoreTab('birthdays')">🎂 Birthdays</div>
        <div class="tab" onclick="switchMoreTab('gifts')">🎁 Gifts</div>
        <div class="tab" onclick="switchMoreTab('kk')">🎅 KK Draw</div>
        <div class="tab" onclick="switchMoreTab('expenses')">💸 Expenses</div>
        <div class="tab" onclick="switchMoreTab('transfers')">💳 Transfers</div>
        <div class="tab" onclick="switchMoreTab('vault')">🔐 Vault</div>
        <div class="tab" onclick="switchMoreTab('shopping')">🛒 Shopping</div>
        <div class="tab" onclick="switchMoreTab('chores')">✅ Chores</div>
        <div class="tab" onclick="switchMoreTab('meals')">🍽️ Meals</div>
        <div class="tab" onclick="switchMoreTab('milestones')">🏆 Milestones</div>
        <div class="tab" onclick="switchMoreTab('recipes')">📖 Recipes</div>
        <div class="tab" onclick="switchMoreTab('kindness')">💛 Kindness</div>
        <div class="tab" onclick="switchMoreTab('photos')">📸 Photos</div>
      </div>
      <div id="moreContent" style="flex:1;overflow-y:auto;padding:12px 0"></div>
    </div>

    <!-- PROFILE -->
    <div class="screen" id="screenProfile">
    <div style="padding:16px;display:flex;gap:10px;flex-wrap:wrap"><button class="btn" onclick="openFamilySettings()">⚙️ Family Settings</button></div>
      <div class="header"><h1>👤 Profile</h1></div>
      <div id="profileContent" style="padding:16px"></div>
    </div>

    <!-- BOTTOM NAV -->
    <nav class="bottom-nav">
      <div class="nav-item active" onclick="switchScreen('Feed')" id="navFeed">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
        Feed
      </div>
      <div class="nav-item" onclick="switchScreen('Chats')" id="navChats">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        Chats
        <span class="nav-badge" id="chatBadge" style="display:none">0</span>
      </div>
      <div class="nav-item" onclick="switchScreen('Events')" id="navEvents">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
        Events
      </div>
      <div class="nav-item" onclick="switchScreen('More')" id="navMore">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>
        More
      </div>
      <div class="nav-item" onclick="switchScreen('Profile')" id="navProfile">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        Me
        <span class="nav-badge" id="notifBadge" style="display:none">0</span>
      </div>
    </nav>
  </div>

  <!-- CHAT SCREEN -->
  <div class="chat-screen" id="chatScreen">
    <div class="header">
      <button class="btn btn-ghost btn-sm" onclick="closeChat()" style="padding:6px 10px">←</button>
      <div style="flex:1">
        <div id="chatScreenName" style="font-weight:700;font-size:16px"></div>
        <div id="chatScreenMembers" style="font-size:12px;color:var(--muted)"></div>
      </div>
    </div>
    <div class="chat-messages" id="chatMessages"></div>
    <div class="chat-input-bar">
      <label id="chatTextAttach" style="cursor:pointer;color:var(--muted);display:flex;align-items:center">
        📎
        <input type="file" id="chatFileInput" style="display:none" accept="image/*,video/*,application/pdf" onchange="sendChatFile()">
      </label>
      <textarea id="chatMsgInput" placeholder="Message..." onkeydown="handleMsgKey(event)" rows="1"></textarea>
      <button id="chatSendBtn" class="send-btn" onclick="sendMsg()">
        <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>
      </button>
      <label id="chatPhotoOnlyBtn" style="display:none;cursor:pointer;background:var(--primary);color:#fff;border-radius:50%;width:48px;height:48px;align-items:center;justify-content:center;font-size:22px;flex-shrink:0">
        📷
        <input type="file" style="display:none" accept="image/*" multiple onchange="sendChatFile(this)">
      </label>
    </div>
  </div>

  <!-- STORY VIEWER -->
  <div class="story-viewer" id="storyViewer" style="display:none">
    <div style="display:flex;align-items:center;gap:10px;padding:12px 16px">
      <div class="story-progress" id="storyProgressBars" style="flex:1"></div>
      <button onclick="closeStoryViewer()" style="background:none;border:none;color:#fff;font-size:22px;cursor:pointer">×</button>
    </div>
    <div style="display:flex;align-items:center;gap:10px;padding:0 16px 12px">
      <div class="avatar avatar-sm" id="storyViewerAvatar"></div>
      <span id="storyViewerName" style="font-weight:600;color:#fff"></span>
      <span id="storyViewerTime" style="font-size:12px;color:rgba(255,255,255,.6);margin-left:auto"></span>
    </div>
    <div class="story-content" id="storyViewerContent"></div>
    <div style="padding:20px;text-align:center;color:rgba(255,255,255,.4);font-size:13px" id="storyViewerViews"></div>
  </div>

  <!-- MODALS -->
  <!-- COMMENT SHEET -->
  <div class="comment-sheet" id="commentSheet" onclick="closeCommentSheet(event)">
    <div class="comment-sheet-inner">
      <div style="text-align:center;padding:10px 16px 0"><div style="width:40px;height:4px;background:var(--border);border-radius:2px;display:inline-block"></div></div>
      <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 16px">
        <h3 id="commentSheetTitle" style="font-size:16px;font-weight:700;margin:0">Comments</h3>
        <button onclick="closeCommentSheet()" style="background:none;border:none;color:var(--muted);font-size:24px;cursor:pointer;line-height:1;padding:4px">&#215;</button>
      </div>
      <div class="comment-list" id="commentList"></div>
      <div class="comment-input-row">
        <input type="text" id="commentInput" placeholder="Add a comment..." style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:10px 14px;color:var(--text);font-size:14px" onkeydown="if(event.key==='Enter')submitComment()">
        <button class="btn btn-primary" onclick="submitComment()" style="border-radius:20px;padding:10px 18px;min-width:auto">Send</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="newPostModal" onclick="handleOverlayClick(event,'newPostModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>New Post</h2>
      <textarea id="postContent" placeholder="What's happening in the family?" rows="3" style="margin-bottom:4px;resize:none" oninput="this.style.height='auto';this.style.height=this.scrollHeight+'px';qs('#postCharCount').textContent=this.value.length+'/500'" maxlength="500"></textarea>
      <div id="postCharCount" style="text-align:right;font-size:11px;color:var(--muted);margin-bottom:8px">0/500</div>
      <div style="margin-bottom:12px">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--muted);font-size:14px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21,15 16,10 5,21"/></svg>
          Add photos
          <input type="file" id="postMediaInput" multiple accept="image/*,video/*" style="display:none" onchange="previewPostMedia()">
        </label>
        <div id="postMediaPreview" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px"></div>
      </div>
      <button class="btn btn-primary btn-full" onclick="submitPost()">Post</button>
    </div>
  </div>

  <div class="modal-overlay" id="newChatModal" onclick="handleOverlayClick(event,'newChatModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>New Chat</h2>
      <div class="input-group"><label>Name (optional)</label><input type="text" id="newChatName" placeholder="e.g. Holidays, Baby pics..."></div>
      <div class="input-group"><label>Type</label><div style="display:flex;gap:8px"><button id="chatTypeBtnText" class="btn btn-primary btn-sm" style="flex:1" onclick="selectChatType('text')">💬 Chat</button><button id="chatTypeBtnPhoto" class="btn btn-sm" style="flex:1;background:var(--surface2)" onclick="selectChatType('photo')">📷 Photo Album</button></div></div>
      <div class="input-group"><label>Members</label><div id="userCheckboxes" style="display:flex;flex-direction:column;gap:8px;max-height:200px;overflow-y:auto"></div></div>
      <button class="btn btn-primary btn-full mt-3" onclick="createChat()">Start Chat</button>
    </div>
  </div>

  <div class="modal-overlay" id="newEventModal" onclick="handleOverlayClick(event,'newEventModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>New Event</h2>
      <div class="input-group"><label>Title</label><input type="text" id="eventTitle" placeholder="Family BBQ..."></div>
      <div class="input-group"><label>When</label><input type="datetime-local" id="eventStart"></div>
      <div class="input-group"><label>Location</label><input type="text" id="eventLocation" placeholder="Address or link..."></div>
      <div class="input-group"><label>Notes</label><textarea id="eventDesc" placeholder="Details..."></textarea></div>
      <button class="btn btn-primary btn-full" onclick="createEvent()">Add Event</button>
    </div>
  </div>

  <div class="modal-overlay" id="newTransferModal" onclick="handleOverlayClick(event,'newTransferModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>Send Money Request</h2>
      <div class="input-group"><label>To</label><select id="transferTo"></select></div>
      <div class="input-group"><label>Amount (€)</label><input type="number" id="transferAmount" placeholder="0.00" step="0.01" min="0.01"></div>
      <div class="input-group"><label>Note</label><input type="text" id="transferNote" placeholder="e.g. Insurance, Dinner..."></div>
      <button class="btn btn-primary btn-full" onclick="createTransfer()">Send Request</button>
    </div>
  </div>

  <div class="modal-overlay" id="newExpenseModal" onclick="handleOverlayClick(event,'newExpenseModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>Add Expense</h2>
      <div class="input-group"><label>Description</label><input type="text" id="expDesc" placeholder="Hotel, dinner, gift..."></div>
      <div class="input-group"><label>Total Amount (€)</label><input type="number" id="expAmount" placeholder="0.00" step="0.01" min="0.01" oninput="updateExpSplits()"></div>
      <div class="input-group"><label>Split with</label><div id="expSplitUsers" style="display:flex;flex-direction:column;gap:6px;max-height:160px;overflow-y:auto"></div></div>
      <button class="btn btn-primary btn-full mt-3" onclick="submitExpense()">Add Expense</button>
    </div>
  </div>

  <div class="modal-overlay" id="newGiftModal" onclick="handleOverlayClick(event,'newGiftModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>Add to Wish List</h2>
      <div class="input-group"><label>Item</label><input type="text" id="giftTitle" placeholder="AirPods, book..."></div>
      <div class="input-group"><label>Link (optional)</label><input type="url" id="giftUrl" placeholder="https://..."></div>
      <div class="input-group"><label>Price (optional)</label><input type="number" id="giftPrice" placeholder="€0"></div>
      <button class="btn btn-primary btn-full" onclick="addGift()">Add</button>
    </div>
  </div>

  <div class="modal-overlay" id="uploadDocModal" onclick="handleOverlayClick(event,'uploadDocModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>Upload Document</h2>
      <div class="input-group"><label>Name</label><input type="text" id="docName" placeholder="Passport, Insurance..."></div>
      <div class="input-group"><label>Type</label>
        <select id="docType">
          <option value="id">ID / Passport</option>
          <option value="insurance">Insurance</option>
          <option value="medical">Medical</option>
          <option value="finance">Finance</option>
          <option value="other">Other</option>
        </select>
      </div>
      <div class="input-group"><label>File</label><input type="file" id="docFile" accept="*/*"></div>
      <div class="input-group">
        <label style="display:flex;gap:8px;align-items:center;cursor:pointer">
          <input type="checkbox" id="docShared" style="width:auto">
          Share with family
        </label>
      </div>
      <button class="btn btn-primary btn-full" onclick="uploadDoc()">Upload (Encrypted)</button>
    </div>
  </div>

  <div class="modal-overlay" id="storyModal" onclick="handleOverlayClick(event,'storyModal')">
    <div class="modal">
      <div class="modal-handle"></div>
      <h2>Add Story</h2>
      <div id="storyTypeToggle" style="display:flex;gap:8px;margin-bottom:12px">
        <button class="tab active" onclick="setStoryType('text',this)">Text</button>
        <button class="tab" onclick="setStoryType('image',this)">Photo</button>
      </div>
      <div id="storyTextInput">
        <textarea id="storyContent" placeholder="Share something with the family... (lasts 24h)"></textarea>
        <div class="input-group mt-2"><label>Background</label>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px" id="bgPicker">
            <div style="width:32px;height:32px;border-radius:8px;background:#6366f1;cursor:pointer;border:2px solid white" onclick="selectBg('#6366f1',this)"></div>
            <div style="width:32px;height:32px;border-radius:8px;background:#ec4899;cursor:pointer" onclick="selectBg('#ec4899',this)"></div>
            <div style="width:32px;height:32px;border-radius:8px;background:#f59e0b;cursor:pointer" onclick="selectBg('#f59e0b',this)"></div>
            <div style="width:32px;height:32px;border-radius:8px;background:#22c55e;cursor:pointer" onclick="selectBg('#22c55e',this)"></div>
            <div style="width:32px;height:32px;border-radius:8px;background:#0ea5e9;cursor:pointer" onclick="selectBg('#0ea5e9',this)"></div>
            <div style="width:32px;height:32px;border-radius:8px;background:#1e293b;cursor:pointer;border:1px solid #334155" onclick="selectBg('#1e293b',this)"></div>
          </div>
        </div>
      </div>
      <div id="storyImageInput" style="display:none">
        <input type="file" id="storyFile" accept="image/*,video/*">
      </div>
      <button class="btn btn-primary btn-full mt-3" onclick="postStory()">Share Story</button>
    </div>
  </div>


  <!-- FAMILY SETTINGS OVERLAY -->
  <div id="familySettingsScreen">
    <div class="fs-header">
      <button onclick="closeFamilySettings()" style="background:none;border:none;color:var(--text);font-size:22px;cursor:pointer;padding:4px 8px">←</button>
      <h2 style="flex:1;margin:0;font-size:18px">⚙️ Family Settings</h2>
    </div>
    <div style="padding:16px;max-width:520px;margin:0 auto">

      <div style="background:var(--surface);border-radius:12px;padding:16px;margin-bottom:14px">
        <h3 style="font-size:15px;margin:0 0 12px">🏠 Family Info</h3>
        <div class="input-group"><label>Family Name</label><input type="text" id="familyNameInput" placeholder="The Gallivans..."></div>
        <div class="input-group"><label>Description</label><input type="text" id="familyDescInput" placeholder="Our family app"></div>
        <button class="btn btn-primary" onclick="saveFamilyInfo()">Save</button>
      </div>

      <div style="background:var(--surface);border-radius:12px;padding:16px;margin-bottom:14px">
        <h3 style="font-size:15px;margin:0 0 8px">🔗 Invite Code</h3>
        <p style="font-size:12px;color:var(--muted);margin:0 0 10px">Share this link so family can join</p>
        <div class="invite-code-box">
          <span id="familyInviteCode" style="font-size:22px;letter-spacing:3px;font-family:monospace">------</span>
          <button class="btn-sm" onclick="copyInviteCode()">Copy</button>
        </div>
        <p style="font-size:11px;color:var(--muted);margin:8px 0 0">Link: hub.luckdragon.io/?invite=<span id="inviteCodeDisplay">...</span></p>
      </div>

      <div style="background:var(--surface);border-radius:12px;padding:16px;margin-bottom:14px">
        <h3 style="font-size:15px;margin:0 0 12px">👥 Members</h3>
        <div id="familyMembersList"></div>
      </div>

      <div style="background:var(--surface);border-radius:12px;padding:16px;margin-bottom:14px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <h3 style="font-size:15px;margin:0">📨 Pending Invites</h3>
          <button class="btn-sm" onclick="toggleNewInviteForm()">+ New</button>
        </div>
        <div id="newInviteForm" style="display:none;background:var(--surface2);border-radius:8px;padding:12px;margin-bottom:10px">
          <div class="input-group" style="margin-bottom:8px"><label style="font-size:12px">Name</label><input type="text" id="newInviteName" placeholder="e.g. Kelly"></div>
          <div class="input-group" style="margin-bottom:8px"><label style="font-size:12px">Email</label><input type="email" id="newInviteEmail" placeholder="their@email.com"></div>
          <div class="input-group" style="margin-bottom:10px"><label style="font-size:12px">Role</label><input type="text" id="newInviteRole" placeholder="e.g. Sister, Partner..."></div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary btn-sm" onclick="createAndSendInvite()">Send Invite</button>
            <button class="btn-sm" onclick="toggleNewInviteForm()">Cancel</button>
          </div>
        </div>
        <div id="pendingInvitesList"><div style="color:var(--muted);font-size:13px">Loading...</div></div>
      </div>

      <div style="background:var(--surface);border-radius:12px;padding:16px;margin-bottom:14px">
        <h3 style="font-size:15px;margin:0 0 12px">🎛️ Features</h3>
        <div id="featureToggles"></div>
      </div>

      <div style="background:var(--surface);border-radius:12px;padding:16px;margin-bottom:14px">
        <h3 style="font-size:15px;margin:0 0 12px">📋 Family Rules</h3>
        <div id="familyRulesList"></div>
        <div style="display:flex;gap:8px;margin-top:10px">
          <input type="text" id="newRuleInput" placeholder="Add a rule..." style="flex:1;padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
          <button class="btn btn-primary btn-sm" onclick="addFamilyRule()">Add</button>
        </div>
      </div>

    </div>
  </div>

  <div class="toast" id="toast"></div>
</div>

<script>
// ─── STATE ────────────────────────────────────────────────────────────────────
let session = JSON.parse(localStorage.getItem('fh_session')||'null');
let currentUser = null;
let allUsers = [];
let currentChatId = null;
let currentChatName = '';
let currentChatType = 'text';
let chatPollInterval = null;
let lastMsgTime = null;
let currentMoreTab = 'birthdays';
let storyBg = '#6366f1';
let storyType = 'text';
let currentStories = [];
let storyIdx = 0;
let storyTimer = null;

// ─── UTILS ────────────────────────────────────────────────────────────────────
function api(path, opts={}) {
  const headers = {'content-type':'application/json'};
  if (session?.token) headers['x-session-token'] = session.token;
  if (opts.headers) Object.assign(headers, opts.headers);
  if (opts.body instanceof FormData) delete headers['content-type'];
  return fetch(path, {...opts, headers}).then(r => r.json());
}
function apiForm(path, formData) {
  const headers = {};
  if (session?.token) headers['x-session-token'] = session.token;
  return fetch(path, {method:'POST', headers, body:formData}).then(r => r.json());
}
function toast(msg, dur=2500) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), dur);
}
function timeAgo(ts) {
  if (!ts) return '';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
  return Math.floor(diff/86400000) + 'd ago';
}
function initials(name) { return (name||'?').split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2); }
function esc(s) { return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function avatarEl(u, size='') {
  if (u.avatar_url) return \`<div class="avatar \${size}"><img src="\${u.avatar_url}" alt="\${u.name}"></div>\`;
  return \`<div class="avatar \${size}" style="background:\${u.avatar_color||'#6366f1'}">\${initials(u.name)}</div>\`;
}
function openModal(id) {
  document.getElementById(id).classList.add('open');
  const needsUsers = id === 'newChatModal' || id === 'newExpenseModal' || id === 'newTransferModal';
  if (!needsUsers) return;
  const populate = (users) => {
    const others = (users||[]).filter(u => u.id !== currentUser?.id);
    const boxes = qs('#userCheckboxes');
    const expUsers = qs('#expSplitUsers');
    const transferTo = qs('#transferTo');
    if (boxes) boxes.innerHTML = others.length
      ? others.map(u => \`<label style="display:flex;gap:8px;align-items:center;cursor:pointer;padding:6px;background:var(--surface2);border-radius:8px"><input type="checkbox" value="\${u.id}" style="width:auto;flex-shrink:0"> <span style="flex:1">\${esc(u.name)}</span><span style="color:var(--muted);font-size:12px">\${u.role||''}</span></label>\`).join('')
      : '<p style="color:var(--muted);font-size:13px">No family members yet</p>';
    if (expUsers) expUsers.innerHTML = others.map(u => \`<label style="display:flex;gap:8px;align-items:center;cursor:pointer;padding:6px;background:var(--surface2);border-radius:8px"><input type="checkbox" value="\${u.id}" style="width:auto"> \${esc(u.name)}</label>\`).join('');
    if (transferTo) transferTo.innerHTML = others.map(u => \`<option value="\${u.id}">\${esc(u.name)}</option>\`).join('');
  };
  if (allUsers.length) { populate(allUsers); }
  else { api('/api/users').then(u => { allUsers = u||[]; populate(allUsers); }); }
}
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function handleOverlayClick(e, id) { if (e.target === e.currentTarget) closeModal(id); }
function qs(sel) { return document.querySelector(sel); }

// ─── AUTH ──────────────────────────────────────────────────────────────────────
function switchAuthTab(tab) {
  document.querySelectorAll('.auth-tab').forEach((t,i) => t.classList.toggle('active', (tab==='login'&&i===0)||(tab==='invite'&&i===1)));
  qs('#loginForm').style.display = tab==='login'?'block':'none';
  qs('#inviteForm').style.display = tab==='invite'?'block':'none';
}

let inviteToken = null;
function togglePwd(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
}
function showAuthError(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}
function clearAuthErrors() {
  ['loginError','inviteError'].forEach(id => { const el=document.getElementById(id); if(el) el.style.display='none'; });
}
async function doInviteNext() {
  clearAuthErrors();
  let raw = (qs('#inviteCode').value || '').trim();
  // Extract token from full URL
  try { const u = new URL(raw); raw = u.searchParams.get('token') || u.searchParams.get('invite') || raw; } catch(e){}
  raw = raw.replace(/.*[?&](token|invite)=/,'').trim();
  if (!raw) { showAuthError('inviteError', 'Paste your invite link here first'); return; }
  const btn = document.getElementById('inviteBtn');
  if (!inviteToken) {
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    const data = await api('/api/auth/invite?token=' + encodeURIComponent(raw));
    if (btn) { btn.disabled = false; }
    if (!data || data.error) {
      showAuthError('inviteError', 'Invalid or expired invite — ask for a new link');
      if (btn) btn.textContent = 'Check Code →';
      return;
    }
    if (data.registered) {
      showAuthError('inviteError', 'Already registered — use Log In instead');
      if (btn) btn.textContent = 'Check Code →';
      return;
    }
    inviteToken = raw;
    qs('#inviteName').value = data.name || '';
    qs('#inviteNameRow').style.display = 'block';
    if (btn) btn.textContent = 'Create Account';
  } else {
    const name = (qs('#inviteName').value || '').trim();
    const email = (qs('#inviteEmail').value || '').trim();
    const password = qs('#invitePass').value || '';
    if (!name) { showAuthError('inviteError', 'Enter your name'); return; }
    if (!email) { showAuthError('inviteError', "Enter your email — you'll need it to log in"); qs('#inviteEmail').focus(); return; }
    if (password.length < 6) { showAuthError('inviteError', 'Password must be at least 6 characters'); return; }
    if (btn) { btn.disabled = true; btn.textContent = 'Creating account…'; }
    const data = await api('/api/auth/register', {method:'POST', body:JSON.stringify({token:inviteToken, name, email, password})});
    if (btn) { btn.disabled = false; btn.textContent = 'Create Account'; }
    if (!data || data.error) { showAuthError('inviteError', data?.error || 'Registration failed'); return; }
    localStorage.setItem('fh_last_email', email);
    session = {token: data.token, user: data.user};
    localStorage.setItem('fh_session', JSON.stringify(session));
    startApp();
  }
}

async function doLogin() {
  clearAuthErrors();
  const email = (qs('#loginEmail').value || '').trim();
  const password = qs('#loginPass').value || '';
  if (!email) { showAuthError('loginError', 'Enter your email'); qs('#loginEmail').focus(); return; }
  if (!password) { showAuthError('loginError', 'Enter your password'); qs('#loginPass').focus(); return; }
  const btn = document.getElementById('loginBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Logging in…'; }
  localStorage.setItem('fh_last_email', email);
  const data = await api('/api/auth/login', {method:'POST', body:JSON.stringify({email, password})});
  if (btn) { btn.disabled = false; btn.textContent = 'Log In'; }
  if (!data || data.error) {
    const msg = data?.error === 'No account found with that email' ? 'No account found — check your email'
              : data?.error === 'Wrong password' ? 'Wrong password — try again'
              : 'Login failed — try again';
    showAuthError('loginError', msg);
    return;
  }
  session = {token: data.token, user: data.user};
  localStorage.setItem('fh_session', JSON.stringify(session));
  startApp();
}

// Pre-fill saved name; check invite URL param
const _savedEmail = localStorage.getItem('fh_last_email') || localStorage.getItem('fh_last_name');
if (_savedEmail && document.getElementById('loginEmail')) {
  document.getElementById('loginEmail').value = _savedEmail;
}
const _urlParams = new URLSearchParams(location.search);
const urlInvite = _urlParams.get('token') || _urlParams.get('invite');
if (urlInvite) {
  switchAuthTab('invite');
  document.getElementById('inviteCode').value = urlInvite;
}

// ─── APP INIT ────────────────────────────────────────────────────────────────
async function startApp() {
  // Apply feature toggles after a short delay (after allUsers loads)
  setTimeout(applyAllFeatureToggles, 2000);
  const me = await api('/api/auth/me');
  if (me.error) { session = null; localStorage.removeItem('fh_session'); return; }
  currentUser = me;
  qs('#authScreen').style.display = 'none';
  qs('#mainApp').style.display = 'flex';
  qs('#mainApp').style.flexDirection = 'column';
  qs('#mainApp').style.flex = '1';

  // Load users
  allUsers = (await api('/api/users')) || [];
  loadFeed();
  loadStories();
  pollNotifs();
  setInterval(pollNotifs, 15000);
}

if (session?.token) startApp();
else qs('#authScreen').style.display = 'flex';

// ─── NAV ────────────────────────────────────────────────────────────────────
function showTab(name) {
  const map = {feed:'Feed',chats:'Chats',events:'Events',more:'More',profile:'Profile'};
  if (map[name]) switchScreen(map[name]);
}
function switchScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('screen'+name).classList.add('active');
  document.getElementById('nav'+name).classList.add('active');
  // lazy load
  if (name==='Chats') loadChats();
  if (name==='Events') loadEvents();
  if (name==='More') loadMoreTab(currentMoreTab);
  if (name==='Profile') loadProfile();
}

// ─── STORIES ────────────────────────────────────────────────────────────────
async function loadStories() {
  const stories = await api('/api/stories');
  currentStories = stories || [];
  const strip = qs('#storiesStrip');
  const wrap = qs('#storiesWrap');
  // Add "my story" button
  strip.innerHTML = \`<div class="story-item" onclick="openModal('storyModal')">
    <div style="width:58px;height:58px;border-radius:50%;background:var(--surface2);display:flex;align-items:center;justify-content:center;border:2px dashed var(--primary)">
      <span style="font-size:24px;color:var(--primary)">+</span>
    </div>
    <span>My Story</span>
  </div>\`;

  // Group by user
  const byUser = {};
  for (const s of currentStories) {
    if (!byUser[s.user_id]) byUser[s.user_id] = [];
    byUser[s.user_id].push(s);
  }
  for (const [uid, stories] of Object.entries(byUser)) {
    const first = stories[0];
    const seen = stories.every(s => s.seen);
    strip.innerHTML += \`<div class="story-item" onclick="viewStories(\${JSON.stringify(stories).replace(/"/g,'&quot;')})">
      <div class="story-ring \${seen?'seen':''}">
        <div class="avatar" style="width:100%;height:100%;border:2px solid var(--surface);background:\${first.avatar_color||'#6366f1'}">\${initials(first.name)}</div>
      </div>
      <span>\${first.name}</span>
    </div>\`;
  }
  wrap.style.display = currentStories.length > 0 ? 'block' : 'none';
}

function viewStories(stories) {
  currentStories = Array.isArray(stories) ? stories : [stories];
  storyIdx = 0;
  showStory(0);
  qs('#storyViewer').style.display = 'flex';
  qs('#storyViewer').style.flexDirection = 'column';
}

function showStory(idx) {
  if (idx >= currentStories.length) { closeStoryViewer(); return; }
  const s = currentStories[idx];
  // Progress bars
  const bars = qs('#storyProgressBars');
  bars.innerHTML = currentStories.map((_,i) => \`<div class="bar \${i<idx?'done':i===idx?'active':''}"></div>\`).join('');
  if (storyTimer) clearTimeout(storyTimer);
  qs('#storyViewerAvatar').style.background = s.avatar_color || '#6366f1';
  qs('#storyViewerAvatar').textContent = initials(s.name);
  qs('#storyViewerName').textContent = s.name;
  qs('#storyViewerTime').textContent = timeAgo(s.created_at);
  const content = qs('#storyViewerContent');
  const viewer = qs('#storyViewer');
  if (s.media_key) {
    content.innerHTML = \`<img src="/api/photos/\${encodeURIComponent(s.media_key)}" style="max-width:100%;max-height:60vh;border-radius:12px">\`;
    viewer.style.background = '#000';
  } else {
    content.textContent = s.content;
    content.style.fontSize = s.content?.length < 50 ? '28px' : '20px';
    viewer.style.background = s.bg_color || '#6366f1';
  }
  // Mark seen
  api('/api/stories/' + s.id + '/view', {method:'POST'});
  storyTimer = setTimeout(() => showStory(idx+1), 5000);
}

function closeStoryViewer() {
  if (storyTimer) clearTimeout(storyTimer);
  qs('#storyViewer').style.display = 'none';
  loadStories();
}

function setStoryType(type, btn) {
  storyType = type;
  document.querySelectorAll('#storyTypeToggle .tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  qs('#storyTextInput').style.display = type==='text'?'block':'none';
  qs('#storyImageInput').style.display = type==='image'?'block':'none';
}
function selectBg(color, el) {
  storyBg = color;
  document.querySelectorAll('#bgPicker div').forEach(d => d.style.border = 'none');
  el.style.border = '2px solid white';
}
async function postStory() {
  const fd = new FormData();
  if (storyType === 'image') {
    const file = qs('#storyFile').files[0];
    if (!file) { toast('Pick a photo first'); return; }
    fd.append('media', file);
    fd.append('type', 'image');
  } else {
    const content = qs('#storyContent').value.trim();
    if (!content) { toast('Write something!'); return; }
    fd.append('content', content);
    fd.append('bg_color', storyBg);
    fd.append('type', 'text');
  }
  const r = await apiForm('/api/stories', fd);
  if (r.error) { toast('❌ ' + r.error); return; }
  closeModal('storyModal');
  qs('#storyContent').value = '';
  toast('Story shared! 📖');
  loadStories();
}

// ─── FEED ────────────────────────────────────────────────────────────────────
let _feedOffset = 0, _feedLoading = false, _feedDone = false;

async function loadFeed(append=false) {
  if (append && (_feedLoading || _feedDone)) return;
  if (!append) { _feedOffset = 0; _feedDone = false; }
  _feedLoading = true;
  const [posts, events] = await Promise.all([
    api('/api/posts?limit=20&offset=' + _feedOffset),
    append ? Promise.resolve(null) : api('/api/events')
  ]);
  _feedLoading = false;
  if (!posts || posts.length < 20) _feedDone = true;
  _feedOffset += (posts?.length || 0);
  const list = qs('#feedList');
  // Upcoming events banner (next 3 within 30 days)
  const now = Date.now();
  const upcoming = (events||[]).filter(e => {
    const t = new Date(e.starts_at).getTime();
    return t >= now && t <= now + 30*24*3600*1000;
  }).slice(0,3);
  let evHtml = '';
  if (upcoming.length) {
    const eventCards = upcoming.map(e => {
      const d = new Date(e.starts_at);
      const mo = d.toLocaleString('en',{month:'short'});
      const dy = d.getDate();
      const hr = d.toLocaleString('en',{hour:'numeric',minute:'2-digit'});
      return \`<div class="digest-row" onclick="showTab('events')">
        <div class="digest-date-pill"><div class="mo">\${mo}</div><div class="dy">\${dy}</div></div>
        <div style="flex:1;min-width:0">
          <div style="font-weight:700;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">\${esc(e.title)}</div>
          <div style="font-size:12px;color:var(--muted)">\${hr}\${e.location?' · '+esc(e.location):''}</div>
        </div>
      </div>\`;
    }).join('');
    evHtml = \`<div class="feed-digest">
      <div class="feed-digest-title">📅 Coming Up</div>
      \${eventCards}
      <div style="text-align:right;margin-top:6px"><button class="btn btn-sm btn-ghost" style="font-size:12px" onclick="showTab('events')">See all →</button></div>
    </div>\`;
  }
  if (!posts?.length && !evHtml) {
    list.innerHTML = \`<div class="empty-state">
      <div class="icon">👋</div>
      <h3 style="margin:0 0 8px;font-size:18px">Welcome to Family Hub!</h3>
      <p style="margin:0 0 16px;color:var(--muted);font-size:14px">Share a moment with your family to get started.</p>
      <button class="btn btn-primary" onclick="openModal('newPostModal')" style="width:auto;padding:10px 24px">📸 Post something</button>
    </div>\`;
    return;
  }
  if (append) {
    list.insertAdjacentHTML('beforeend', (posts||[]).map(p => renderPost(p)).join(''));
    if (_feedDone) list.insertAdjacentHTML('beforeend', '<div style="text-align:center;padding:24px;color:var(--muted);font-size:13px">All caught up ✓</div>');
  } else {
    list.innerHTML = evHtml + (posts||[]).map(p => renderPost(p)).join('');
    list.onscroll = () => { if (list.scrollHeight - list.scrollTop - list.clientHeight < 250) loadFeed(true); };
  }
}
function renderPost(p) {
  const mediaHtml = p.media?.length ? \`<div class="post-media count-\${Math.min(p.media.length,4)}">\${p.media.slice(0,4).map(m=>\`<img src="/api/photos/\${encodeURIComponent(m.r2_key)}" onclick="viewImg('\${m.r2_key}')" loading="lazy">\`).join('')}</div>\` : '';
  const isOwn = p.user_id === currentUser?.id;
  const reactionEmoji = p.my_reaction || '❤️';
  const deleteBtn = isOwn ? \`<button class="post-delete-btn" onclick="deletePost('\${p.id}')" title="Delete post">🗑</button>\` : '';
  return \`<div class="post-card" data-post-id="\${p.id}">
    <div class="post-header">
      <div class="avatar" style="background:\${p.avatar_color||'#6366f1'}">\${initials(p.author_name)}</div>
      <div style="flex:1">
        <div style="font-weight:700;font-size:15px">\${p.author_name}</div>
        <div class="text-xs text-muted">\${timeAgo(p.created_at)}</div>
      </div>
      \${deleteBtn}
    </div>
    \${p.content ? \`<div class="post-content">\${p.content}</div>\` : ''}
    \${mediaHtml}
    <div class="post-actions">
      <div class="post-action \${p.my_reaction?'liked':''}" onclick="showReactPicker('\${p.id}',this)" style="position:relative">
        <span>\${reactionEmoji}</span> <span>\${p.reaction_count||0}</span>
      </div>
      <div class="post-action" onclick="loadComments('\${p.id}','\${p.author_name}')">
        <span>💬</span> <span>\${p.comment_count||0}</span>
      </div>
    </div>
  </div>\`;
}
function showReactPicker(postId, el) {
  // If already reacted, clicking again un-reacts
  const card = el.closest('.post-card');
  const existing = card.querySelector('.react-picker');
  if (existing) { existing.remove(); return; }
  const picker = document.createElement('div');
  picker.className = 'react-picker';
  picker.innerHTML = ['❤️','😂','🔥','👍','😮','😢'].map(e =>
    \`<span onclick="reactPost('\${postId}','\${e}',this.closest('.post-actions').querySelector('.post-action'));this.closest('.react-picker').remove()" title="\${e}">\${e}</span>\`
  ).join('');
  el.parentNode.insertBefore(picker, el.nextSibling);
  setTimeout(() => { document.addEventListener('click', function rm(ev) { if (!picker.contains(ev.target) && ev.target !== el) { picker.remove(); document.removeEventListener('click', rm); } }, {once:false}); }, 10);
}
async function deletePost(postId) {
  if (!confirm('Delete this post?')) return;
  const r = await api('/api/posts/' + postId, {method:'DELETE'});
  if (!r.error) {
    const card = document.querySelector(\`[data-post-id="\${postId}"]\`);
    if (card) card.remove();
    toast('Post deleted');
  }
}
async function reactPost(postId, reaction, el) {
  const r = await api('/api/posts/' + postId + '/react', {method:'POST', body:JSON.stringify({reaction})});
  if (!r.error) loadFeed();
}
function viewImg(key) {
  window.open('/api/photos/' + encodeURIComponent(key), '_blank');
}
let commentPostId = null;
function _renderComments(comments) {
  if (!comments || !comments.length) return \`<div style="text-align:center;padding:40px;color:var(--muted)"><div style="font-size:32px;margin-bottom:8px">💬</div><p>No comments yet</p></div>\`;
  return comments.map(c => \`<div class="comment-bubble">
    <div class="avatar avatar-sm" style="background:\${c.avatar_color||'#6366f1'};flex-shrink:0">\${initials(c.name)}</div>
    <div class="comment-bubble-body">
      <div class="comment-bubble-name">\${esc(c.name)}</div>
      <div class="comment-bubble-text">\${esc(c.content)}</div>
      <div class="comment-bubble-time">\${timeAgo(c.created_at)}</div>
    </div>
  </div>\`).join('');
}
async function loadComments(postId, authorName) {
  commentPostId = postId;
  const sheet = document.getElementById('commentSheet');
  const list = document.getElementById('commentList');
  if (!sheet) return;
  document.getElementById('commentSheetTitle').textContent = 'Comments';
  list.innerHTML = '<div style="text-align:center;padding:32px;color:var(--muted)">Loading...</div>';
  sheet.classList.add('open');
  setTimeout(() => document.getElementById('commentInput')?.focus(), 350);
  const comments = await api('/api/posts/' + postId + '/comments');
  list.innerHTML = _renderComments(comments);
  list.scrollTop = list.scrollHeight;
}
function closeCommentSheet(e) {
  if (e && e.target !== document.getElementById('commentSheet')) return;
  document.getElementById('commentSheet')?.classList.remove('open');
}
async function submitComment() {
  const input = document.getElementById('commentInput');
  const content = input?.value.trim();
  if (!content) return;
  input.value = '';
  const r = await api('/api/posts/' + commentPostId + '/comments', {method:'POST', body:JSON.stringify({content})});
  if (r?.error) { toast('\u274c ' + r.error); return; }
  const comments = await api('/api/posts/' + commentPostId + '/comments');
  const list = document.getElementById('commentList');
  if (list) { list.innerHTML = _renderComments(comments); list.scrollTop = list.scrollHeight; }
  const card = document.querySelector(\`[data-post-id="\${commentPostId}"]\`);
  if (card) {
    const cnt = card.querySelectorAll('.post-action')[1]?.querySelector('span:last-child');
    if (cnt) cnt.textContent = parseInt(cnt.textContent||'0') + 1;
  }
}
let postMediaFiles = [];
function previewPostMedia() {
  const files = Array.from(qs('#postMediaInput').files);
  postMediaFiles = files;
  const preview = qs('#postMediaPreview');
  preview.innerHTML = files.map((f,i) => \`<div style="position:relative"><img src="\${URL.createObjectURL(f)}" style="width:64px;height:64px;object-fit:cover;border-radius:8px"><button onclick="removePostMedia(\${i})" style="position:absolute;top:-4px;right:-4px;background:var(--danger);border:none;color:#fff;width:18px;height:18px;border-radius:50%;font-size:11px;cursor:pointer">×</button></div>\`).join('');
}
function removePostMedia(i) { postMediaFiles.splice(i,1); previewPostMedia(); }
async function submitPost() {
  const content = qs('#postContent').value.trim();
  const fd = new FormData();
  fd.append('content', content);
  for (const f of postMediaFiles) fd.append('media', f);
  if (!content && postMediaFiles.length === 0) { toast('Empty post'); return; }
  const r = await apiForm('/api/posts', fd);
  if (r.error) { toast('❌ ' + r.error); return; }
  closeModal('newPostModal');
  const _pc = qs('#postContent'); if (_pc) { _pc.value=''; _pc.style.height=''; }
  const _pcc = qs('#postCharCount'); if (_pcc) _pcc.textContent='0/500';
  postMediaFiles = [];
  qs('#postMediaPreview').innerHTML = '';
  toast('Posted! 🎉');
  _feedOffset=0; _feedDone=false;
  loadFeed();
}

// ─── CHATS ────────────────────────────────────────────────────────────────────
async function loadChats() {
  const chats = await api('/api/chats');
  const list = qs('#chatList');
  if (!chats?.length) { list.innerHTML = '<div class="empty-state"><div class="icon">💬</div><p>No chats yet</p></div>'; const _b=document.getElementById('chatBadge'); if(_b)_b.style.display='none'; return; }
  const _seen = JSON.parse(localStorage.getItem('fh_chat_seen')||'{}');
  let _unreadCount = 0;
  list.innerHTML = chats.map(c => {
    const name = c.name || c.members?.filter(m=>m.id!==currentUser?.id).map(m=>m.name).join(', ') || 'Chat';
    const avatarColor = c.members?.find(m=>m.id!==currentUser?.id)?.avatar_color || '#6366f1';
    const avatarTxt = c.chat_type === 'photo' ? '📷' : (c.is_group ? '👨‍👩‍👧‍👦' : initials(name));
    const isUnread = c.last_msg_at && c.last_sender && c.last_sender !== currentUser?.name && (!_seen[c.id] || c.last_msg_at > _seen[c.id]);
    if (isUnread) _unreadCount++;
    return \`<div class="chat-item" onclick="openChat('\${c.id}',\${JSON.stringify(name).replace(/"/g,'&quot;')},'\${c.chat_type||'text'}')">
      <div class="avatar" style="background:\${c.is_group?'#4f46e5':avatarColor}">\${c.is_group?'👨‍👩‍👧‍👦':initials(name)}</div>
      <div class="chat-meta">
        <h3 style="\${isUnread?'font-weight:800;color:var(--text)':''}">\${name}\${isUnread?'<span style="display:inline-block;width:7px;height:7px;background:var(--primary);border-radius:50%;margin-left:6px;vertical-align:middle"></span>':''}</h3>
        <p style="\${isUnread?'color:var(--text);font-weight:500':''}">\${c.last_msg || (c.last_sender?c.last_sender+': ...':'No messages')}</p>
      </div>
      <div class="chat-time">\${timeAgo(c.last_msg_at||c.created_at)}</div>
    </div>\`;
  }).join('');
  const _cb = document.getElementById('chatBadge');
  if (_cb) { _cb.textContent = _unreadCount > 9 ? '9+' : _unreadCount; _cb.style.display = _unreadCount > 0 ? 'flex' : 'none'; }
  // Pre-load users so new chat modal is ready
  if (!allUsers.length) { api('/api/users').then(u => { allUsers = u||[]; }); }
}

function selectChatType(type) {
  window._newChatType = type;
  const isPhoto = type === 'photo';
  const tb = qs('#chatTypeBtnText'), pb = qs('#chatTypeBtnPhoto');
  if (tb) { tb.className = isPhoto ? 'btn btn-sm' : 'btn btn-primary btn-sm'; tb.style.background = isPhoto ? 'var(--surface2)' : ''; }
  if (pb) { pb.className = isPhoto ? 'btn btn-primary btn-sm' : 'btn btn-sm'; pb.style.background = isPhoto ? '' : 'var(--surface2)'; }
}
async function createChat() {
  const name = qs('#newChatName').value.trim();
  const selected = Array.from(document.querySelectorAll('#userCheckboxes input:checked')).map(i=>i.value);
  if (!selected.length) { toast('Pick at least one person'); return; }
  const chat_type = window._newChatType || 'text';
  window._newChatType = 'text';
  const r = await api('/api/chats', {method:'POST', body:JSON.stringify({name: name||null, member_ids:selected, is_group: selected.length>1||chat_type==='photo', chat_type})});
  if (r.error) { toast('❌ ' + r.error); return; }
  closeModal('newChatModal');
  toast('Chat created!');
  loadChats();
  openChat(r.id, name || 'Chat');
}
function openChat(chatId, chatName, chatType) {
  const _s = JSON.parse(localStorage.getItem('fh_chat_seen')||'{}');
  _s[chatId] = new Date().toISOString();
  localStorage.setItem('fh_chat_seen', JSON.stringify(_s));
  const _cb = document.getElementById('chatBadge');
  if (_cb) { const n = Math.max(0, parseInt(_cb.textContent||'0')-1); _cb.textContent=n; _cb.style.display=n>0?'flex':'none'; }
  currentChatId = chatId;
  currentChatName = chatName;
  currentChatType = chatType || 'text';
  lastMsgTime = null;
  qs('#chatScreenName').textContent = chatName;
  const _isPhoto = currentChatType === 'photo';
  qs('#chatMessages').className = 'chat-messages' + (_isPhoto ? ' photo-mode' : '');
  if (qs('#chatMsgInput')) qs('#chatMsgInput').style.display = _isPhoto ? 'none' : '';
  if (qs('#chatSendBtn')) qs('#chatSendBtn').style.display = _isPhoto ? 'none' : '';
  if (qs('#chatTextAttach')) qs('#chatTextAttach').style.display = _isPhoto ? 'none' : 'flex';
  if (qs('#chatPhotoOnlyBtn')) qs('#chatPhotoOnlyBtn').style.display = _isPhoto ? 'flex' : 'none';
  qs('#chatScreen').classList.add('open');
  loadMessages(chatId);
  if (chatPollInterval) clearInterval(chatPollInterval);
  chatPollInterval = setInterval(() => pollMessages(chatId), 3000);
}
function closeChat() {
  qs('#chatScreen').classList.remove('open');
  if (chatPollInterval) clearInterval(chatPollInterval);
  currentChatId = null;
}
async function loadMessages(chatId) {
  const msgs = await api('/api/chats/'+chatId+'/messages?limit=50');
  if (msgs?.length) lastMsgTime = msgs[msgs.length-1].created_at;
  renderMessages(msgs||[], true);
}
async function pollMessages(chatId) {
  if (!lastMsgTime) return;
  const since = new URL('/', location.href);
  const newMsgs = await api('/api/chats/'+chatId+'/stream?since='+encodeURIComponent(lastMsgTime));
  if (newMsgs?.length) {
    lastMsgTime = newMsgs[newMsgs.length-1].created_at;
    appendMessages(newMsgs);
  }
}
function renderMessages(msgs, scroll=false) {
  const container = qs('#chatMessages');
  container.innerHTML = msgs.map(m => renderMsg(m)).join('');
  if (scroll) container.scrollTop = container.scrollHeight;
}
function appendMessages(msgs) {
  const container = qs('#chatMessages');
  const atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 100;
  msgs.forEach(m => container.insertAdjacentHTML('beforeend', renderMsg(m)));
  if (atBottom) container.scrollTop = container.scrollHeight;
}
function renderMsg(m) {
  if (currentChatType === 'photo' && m.msg_type === 'image' && m.media_key) {
    return \`<div class="photo-grid-item" onclick="viewImg('\${m.media_key}')"><img src="/api/photos/\${encodeURIComponent(m.media_key)}" loading="lazy"><div class="photo-grid-caption">\${esc(m.sender_name)}\${m.content?' · '+esc(m.content):''}</div></div>\`;
  }
  const mine = m.user_id === currentUser?.id;
  let content = '';
  if (m.msg_type === 'image' && m.media_key) {
    content = \`<img src="/api/photos/\${encodeURIComponent(m.media_key)}" style="max-width:220px;border-radius:12px;display:block" onclick="viewImg('\${m.media_key}')">\`;
  } else if (m.msg_type === 'file' && m.media_key) {
    content = \`<a href="/api/photos/\${encodeURIComponent(m.media_key)}" target="_blank" style="color:\${mine?'#fff':'var(--primary)'}">📎 \${m.media_key.split('/').pop()}</a>\`;
  } else {
    content = m.content?.replace(/\\n/g,'<br>') || '';
  }
  const reactions = (m.reactions||[]).map(r => \`<span class="reaction-pill" onclick="reactMsg('\${m.id}','\${r.reaction}')">\${r.reaction} \${r.c}</span>\`).join('');
  return \`<div class="msg-row" style="\${mine?'align-items:flex-end':'align-items:flex-start'}">
    \${!mine ? \`<div class="msg-sender">\${m.sender_name}</div>\` : ''}
    <div class="msg-bubble \${mine?'mine':'theirs'}" ondblclick="reactMsg('\${m.id}','❤️')">\${content}</div>
    \${reactions ? \`<div class="msg-reactions">\${reactions}</div>\` : ''}
  </div>\`;
}
async function reactMsg(msgId, reaction) {
  if (!currentChatId) return;
  await api('/api/chats/'+currentChatId+'/messages/'+msgId+'/react', {method:'POST', body:JSON.stringify({reaction})});
}
async function sendMsg() {
  if (!currentChatId) return;
  const input = qs('#chatMsgInput');
  const content = input.value.trim();
  if (!content) return;
  input.value = '';
  input.style.height = 'auto';
  const r = await api('/api/chats/'+currentChatId+'/messages', {method:'POST', body:JSON.stringify({content})});
  if (!r.error) {
    const now = new Date().toISOString();
    appendMessages([{id:r.id, user_id:currentUser.id, content, msg_type:'text', created_at:now, sender_name:currentUser.name}]);
    lastMsgTime = now;
  }
}
async function sendChatFile(inputEl) {
  const input = inputEl || qs('#chatFileInput');
  if (!input?.files?.length || !currentChatId) return;
  const headers = {};
  if (session?.token) headers['x-session-token'] = session.token;
  for (const file of Array.from(input.files)) {
    const fd = new FormData();
    fd.append('file', file);
    const r = await fetch('/api/chats/'+currentChatId+'/messages', {method:'POST', headers, body:fd}).then(r=>r.json());
    if (r.error) { toast('❌ ' + r.error); break; }
  }
  input.value = '';
  lastMsgTime = new Date().toISOString();
  loadMessages(currentChatId);
}
function handleMsgKey(e) {
  if (e.key==='Enter' && !e.shiftKey) { e.preventDefault(); sendMsg(); }
  // Auto-resize
  const ta = e.target;
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
}

// Load users for new chat & transfer
async function loadUsersForSelects() {
  if (!allUsers.length) allUsers = await api('/api/users') || [];
  const select = qs('#transferTo');
  if (select) select.innerHTML = allUsers.filter(u=>u.id!==currentUser?.id).map(u=>\`<option value="\${u.id}">\${u.name}</option>\`).join('');
  const expUsers = qs('#expSplitUsers');
  if (expUsers) expUsers.innerHTML = allUsers.filter(u=>u.id!==currentUser?.id).map(u=>\`<label style="display:flex;gap:8px;align-items:center;cursor:pointer;padding:6px;background:var(--surface2);border-radius:8px"><input type="checkbox" value="\${u.id}" style="width:auto"> \${u.name}</label>\`).join('');
}

// ─── EVENTS ────────────────────────────────────────────────────────────────────
async function loadEvents() {
  const events = await api('/api/events');
  const list = qs('#eventsList');
  if (!events?.length) { list.innerHTML = '<div class="empty-state"><div class="icon">📅</div><p>No events yet</p></div>'; return; }
  list.innerHTML = events.map(e => {
    const d = new Date(e.starts_at);
    return \`<div class="event-card">
      <div class="event-date">\${d.toLocaleDateString('en-IE',{weekday:'short',month:'short',day:'numeric'})} · \${d.toLocaleTimeString('en-IE',{hour:'2-digit',minute:'2-digit'})}</div>
      <div style="font-weight:700;font-size:16px;margin-bottom:4px">\${e.title}</div>
      \${e.location?\`<div style="font-size:13px;color:var(--muted)">📍 \${e.location}</div>\`:''}
      \${e.description?\`<div style="font-size:14px;color:var(--muted);margin-top:4px">\${e.description}</div>\`:''}
      <div style="display:flex;gap:8px;margin-top:10px">
        <button class="btn btn-sm \${e.my_rsvp==='going'?'btn-primary':'btn-ghost'}" onclick="rsvp('\${e.id}','going')">✅ Going\${e.going_count?\` (\${e.going_count})\`:''}</button>
        <button class="btn btn-sm \${e.my_rsvp==='maybe'?'btn-primary':'btn-ghost'}" onclick="rsvp('\${e.id}','maybe')">🤔 Maybe</button>
        <button class="btn btn-sm \${e.my_rsvp==='no'?'btn-danger':'btn-ghost'}" onclick="rsvp('\${e.id}','no')">❌ No</button>
      </div>
    </div>\`;
  }).join('');
}
async function createEvent() {
  const title = qs('#eventTitle').value.trim();
  const starts_at = qs('#eventStart').value;
  if (!title || !starts_at) { toast('Title and date required'); return; }
  const r = await api('/api/events', {method:'POST', body:JSON.stringify({title, starts_at, location:qs('#eventLocation').value||null, description:qs('#eventDesc').value||null})});
  if (r.error) { toast('❌ ' + r.error); return; }
  closeModal('newEventModal'); toast('Event added! 📅'); loadEvents();
}
async function rsvp(eventId, status) {
  await api('/api/events/'+eventId+'/rsvp', {method:'POST', body:JSON.stringify({status})});
  loadEvents();
}

// ─── MORE TABS ────────────────────────────────────────────────────────────────
function switchMoreTab(tab) {
  currentMoreTab = tab;
  document.querySelectorAll('#moreTabs .tab').forEach(t => t.classList.remove('active'));
  document.querySelector(\`#moreTabs .tab[onclick*="\${tab}"]\`)?.classList.add('active');
  loadMoreTab(tab);
}
function loadMoreTab(tab) {
  const c = qs('#moreContent');
  c.innerHTML = '<div class="spinner"></div>';
  if (tab==='birthdays') loadBirthdays();
  if (tab==='gifts') loadGifts();
  if (tab==='kk') loadKK();
  if (tab==='expenses') loadExpenses();
  if (tab==='transfers') loadTransfers();
  if (tab==='vault') loadVault();
  if (tab==='shopping') loadShopping();
  if (tab==='chores') loadChores();
  if (tab==='meals') loadMeals();
  if (tab==='milestones') loadMilestones();
  if (tab==='recipes') loadRecipes();
  if (tab==='kindness') loadKindness();
  if (tab==='photos') loadAlbum();
}

async function loadBirthdays() {
  const bdays = await api('/api/birthdays');
  const c = qs('#moreContent');
  const today = new Date();
  c.innerHTML = \`<div style="padding:16px">
    <div style="margin-bottom:16px">
      <p style="color:var(--muted);font-size:13px;margin-bottom:8px">Your birthday</p>
      <div style="display:flex;gap:8px">
        <input type="date" id="myBday" style="flex:1">
        <button class="btn btn-primary btn-sm" onclick="saveBday()">Save</button>
      </div>
    </div>
    <h3 style="margin-bottom:12px">Family Birthdays</h3>
    \${!bdays?.length ? '<p style="color:var(--muted)">No birthdays added yet</p>' : ''}
    \${(bdays||[]).map(b => {
      const d = new Date(b.date+'T12:00:00');
      const thisYear = new Date(today.getFullYear(), d.getMonth(), d.getDate());
      const daysUntil = Math.ceil((thisYear - today) / 86400000);
      const upcoming = daysUntil >= 0 && daysUntil <= 30;
      return \`<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)">
        <div class="avatar" style="background:\${b.avatar_color||'#6366f1'}">\${initials(b.name)}</div>
        <div style="flex:1">
          <div style="font-weight:600">\${b.name}</div>
          <div style="font-size:13px;color:var(--muted)">\${d.toLocaleDateString('en-IE',{day:'numeric',month:'long'})}</div>
        </div>
        \${upcoming ? \`<span style="background:var(--warning);color:#000;border-radius:99px;padding:2px 10px;font-size:12px;font-weight:700">🎂 \${daysUntil===0?'Today!':daysUntil+'d'}</span>\` : ''}
      </div>\`;
    }).join('')}
  </div>\`;
  // Pre-fill user's own birthday
  const myBday = bdays?.find(b=>b.user_id===currentUser?.id);
  if (myBday) qs('#myBday').value = myBday.date;
}
async function saveBday() {
  const date = qs('#myBday').value;
  if (!date) return;
  await api('/api/birthdays', {method:'POST', body:JSON.stringify({date})});
  toast('Birthday saved! 🎂'); loadBirthdays();
}

async function loadGifts() {
  const c = qs('#moreContent');
  const users = allUsers.length ? allUsers : await api('/api/users');
  const myGifts = await api('/api/gifts?user=' + currentUser?.id);
  c.innerHTML = \`<div style="padding:12px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3>My Wish List</h3>
      <button class="btn btn-sm btn-primary" onclick="openModal('newGiftModal')">+ Add</button>
    </div>
    \${!myGifts?.length ? '<p style="color:var(--muted);margin-bottom:16px">Nothing on your list yet</p>' : ''}
    \${(myGifts||[]).map(g => \`<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)">
      <div style="flex:1">
        <div style="font-weight:600">\${g.title}</div>
        \${g.url?\`<a href="\${g.url}" target="_blank" style="font-size:13px;color:var(--primary)">View item</a>\`:''}
        \${g.price?\`<span style="font-size:13px;color:var(--muted)"> · €\${g.price}</span>\`:''}
      </div>
      <span style="font-size:12px;color:\${g.status==='claimed'?'var(--warning)':'var(--muted)'}">\${g.status==='claimed'?'🎁 Claimed':'Available'}</span>
      <button onclick="deleteGift('\${g.id}')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px">×</button>
    </div>\`).join('')}
    <h3 style="margin:16px 0 10px">Family Wish Lists</h3>
    \${users.filter(u=>u.id!==currentUser?.id).map(u => \`<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="viewGifts('\${u.id}','\${u.name}')">
      <div class="avatar avatar-sm" style="background:\${u.avatar_color||'#6366f1'}">\${initials(u.name)}</div>
      <span style="font-weight:600">\${u.name}</span>
      <span style="margin-left:auto;color:var(--primary);font-size:13px">View →</span>
    </div>\`).join('')}
  </div>\`;
}
async function deleteGift(id) {
  await api('/api/gifts/'+id, {method:'DELETE'});
  loadGifts();
}
async function viewGifts(userId, userName) {
  const gifts = await api('/api/gifts?user='+userId);
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:12px">
    <button onclick="loadGifts()" style="background:none;border:none;color:var(--primary);cursor:pointer;margin-bottom:12px">← Back</button>
    <h3>\${userName}'s Wish List</h3>
    \${!gifts?.length ? '<p style="color:var(--muted);margin-top:12px">Nothing on their list yet</p>' : ''}
    \${(gifts||[]).map(g => \`<div style="display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid var(--border)">
      <div style="flex:1">
        <div style="font-weight:600">\${g.title}</div>
        \${g.url?\`<a href="\${g.url}" target="_blank" style="font-size:13px;color:var(--primary)">View →</a>\`:''}
        \${g.price?\`<span style="font-size:13px;color:var(--muted)"> · €\${g.price}</span>\`:''}
      </div>
      <button class="btn btn-sm \${g.claimed_by_label==='you'?'btn-danger':'btn-ghost'}" onclick="claimGift('\${g.id}')">
        \${g.claimed_by_label==='you'?'Unclaim':g.claimed_by_label==='someone'?'🔒 Taken':'🎁 Claim'}
      </button>
    </div>\`).join('')}
  </div>\`;
}
async function claimGift(id) {
  const r = await api('/api/gifts/'+id+'/claim', {method:'POST'});
  if (r.error) toast('❌ ' + r.error);
  else toast(r.ok ? 'Claimed!' : 'Unclaimed');
}
async function addGift() {
  const title = qs('#giftTitle').value.trim();
  if (!title) { toast('Enter an item'); return; }
  await api('/api/gifts', {method:'POST', body:JSON.stringify({title, url:qs('#giftUrl').value||null, price:qs('#giftPrice').value||null})});
  closeModal('newGiftModal'); toast('Added to wish list! 🎁'); loadGifts();
}

async function loadKK() {
  const year = new Date().getFullYear();
  const data = await api('/api/kk?year='+year);
  const c = qs('#moreContent');
  if (!data) {
    c.innerHTML = \`<div style="padding:16px;text-align:center">
      <div style="font-size:48px;margin-bottom:12px">🎅</div>
      <h3 style="margin-bottom:8px">No KK Draw for \${year}</h3>
      <p style="color:var(--muted);margin-bottom:20px">Set up the Secret Santa for this year</p>
      <button class="btn btn-primary" onclick="createKK(\${year})">Create \${year} KK Draw</button>
    </div>\`;
    return;
  }
  const amIn = data.participants?.some(p=>p.user_id===currentUser?.id);
  c.innerHTML = \`<div style="padding:16px">
    <div style="text-align:center;margin-bottom:20px">
      <div style="font-size:40px">🎅</div>
      <h2>KK Draw \${year}</h2>
      <p style="color:var(--muted)">Budget: €\${data.budget||50}</p>
    </div>
    \${data.my_assignment ? \`<div style="background:var(--primary);border-radius:16px;padding:20px;text-align:center;margin-bottom:16px">
      <div style="font-size:13px;opacity:.8;margin-bottom:4px">🎁 You're buying a gift for...</div>
      <div style="font-size:28px;font-weight:800">\${data.my_assignment.name}</div>
    </div>\` : ''}
    \${!data.drawn ? \`<div style="margin-bottom:16px">
      \${!amIn ? \`<button class="btn btn-primary btn-full mb-3" onclick="joinKK('\${data.id}')">Join the Draw</button>\` : '<p style="color:var(--success);text-align:center;margin-bottom:12px">✅ You&#39;re in!</p>'}
      <p style="color:var(--muted);font-size:13px;text-align:center;margin-bottom:12px">\${data.participants?.length||0} participants joined</p>
      \${data.participants?.length >= 2 ? \`<button class="btn btn-primary btn-full" onclick="doDraw('\${data.id}')">🎲 Do the Draw!</button>\` : '<p style="color:var(--muted);font-size:13px;text-align:center">Need at least 2 participants</p>'}
    </div>\` : '<p style="color:var(--success);text-align:center;margin-bottom:12px">✅ Draw complete!</p>'}
    <h3 style="margin-bottom:10px">Participants (\${data.participants?.length||0})</h3>
    \${(data.participants||[]).map(p=>\`<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
      <div class="avatar avatar-sm" style="background:\${p.avatar_color||'#6366f1'}">\${initials(p.name)}</div>
      <span>\${p.name}</span>
      \${p.wish?\`<span style="color:var(--muted);font-size:13px;margin-left:auto">💭 \${p.wish}</span>\`:''}
    </div>\`).join('')}
  </div>\`;
}
async function createKK(year) {
  const r = await api('/api/kk', {method:'POST', body:JSON.stringify({year, budget:50})});
  if (r.error) { toast('❌ '+r.error); return; }
  // Auto-join
  await api('/api/kk/join', {method:'POST', body:JSON.stringify({draw_id:r.id})});
  loadKK();
}
async function joinKK(drawId) {
  const wish = prompt('Any gift wishes? (optional)');
  await api('/api/kk/join', {method:'POST', body:JSON.stringify({draw_id:drawId, wish: wish||null})});
  toast('Joined! 🎅'); loadKK();
}
async function doDraw(drawId) {
  if (!confirm('Do the draw now? Everyone will get their assignment.')) return;
  const r = await api('/api/kk/draw', {method:'POST', body:JSON.stringify({draw_id:drawId})});
  if (r.error) { toast('❌ '+r.error); return; }
  toast('🎅 Draw done! Check your assignment!'); loadKK();
}

async function loadExpenses() {
  const [expenses, summary] = await Promise.all([api('/api/expenses'), api('/api/expenses/summary')]);
  const c = qs('#moreContent');
  await loadUsersForSelects();
  const owe = summary?.i_owe || 0;
  const owed = summary?.owed_to_me || 0;
  c.innerHTML = \`<div style="padding:12px">
    <div style="display:flex;gap:10px;margin-bottom:16px">
      <div style="flex:1;background:var(--surface);border-radius:12px;padding:14px;text-align:center">
        <div class="text-xs text-muted" style="margin-bottom:4px">You owe</div>
        <div class="amount-badge negative">€\${owe.toFixed(2)}</div>
      </div>
      <div style="flex:1;background:var(--surface);border-radius:12px;padding:14px;text-align:center">
        <div class="text-xs text-muted" style="margin-bottom:4px">Owed to you</div>
        <div class="amount-badge positive">€\${owed.toFixed(2)}</div>
      </div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3>Expenses</h3>
      <button class="btn btn-sm btn-primary" onclick="openModal('newExpenseModal')">+ Add</button>
    </div>
    \${!expenses?.length ? '<p style="color:var(--muted)">No expenses yet</p>' : ''}
    \${(expenses||[]).map(e=>\`<div class="expense-item">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <div style="font-weight:600">\${e.description}</div>
          <div style="font-size:12px;color:var(--muted)">\${e.paid_by_name} · \${timeAgo(e.created_at)}</div>
        </div>
        <div style="font-weight:700">€\${parseFloat(e.amount).toFixed(2)}</div>
      </div>
      \${e.splits?.filter(s=>s.user_id===currentUser?.id&&!s.settled&&e.paid_by!==currentUser?.id).length?
        \`<button class="btn btn-sm btn-ghost mt-2" onclick="settleExpense('\${e.id}')">Mark as paid</button>\`:''}
    </div>\`).join('')}
  </div>\`;
}
async function settleExpense(id) {
  await api('/api/expenses/'+id+'/settle', {method:'POST'});
  toast('Marked as paid ✅'); loadExpenses();
}
function updateExpSplits() {} // placeholder
async function submitExpense() {
  const desc = qs('#expDesc').value.trim();
  const amount = parseFloat(qs('#expAmount').value);
  if (!desc || !amount) { toast('Fill in description and amount'); return; }
  const selected = Array.from(document.querySelectorAll('#expSplitUsers input:checked')).map(i=>i.value);
  const everyone = [currentUser.id, ...selected];
  const split = amount / everyone.length;
  const splits = everyone.map(uid=>({user_id:uid, amount:parseFloat(split.toFixed(2))}));
  const r = await api('/api/expenses', {method:'POST', body:JSON.stringify({description:desc, amount, splits})});
  if (r.error) { toast('❌ '+r.error); return; }
  closeModal('newExpenseModal'); toast('Expense added! 💸'); loadExpenses();
}

async function loadTransfers() {
  const [transfers, balance] = await Promise.all([api('/api/transfers'), api('/api/transfers/balance')]);
  await loadUsersForSelects();
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:12px">
    \${balance?.balances?.length ? \`<div style="margin-bottom:16px">
      <h3 style="margin-bottom:8px">Net Balances</h3>
      \${balance.balances.filter(b=>Math.abs(b.net)>0.01).map(b=>\`<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
        <span>\${b.other_name}</span>
        <span class="amount-badge \${b.net>0?'positive':'negative'}">\${b.net>0?'+':b.net<0?'-':''}€\${Math.abs(b.net).toFixed(2)}</span>
      </div>\`).join('')}
    </div>\` : ''}
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3>Transfers</h3>
      <button class="btn btn-sm btn-primary" onclick="openModal('newTransferModal')">+ Request</button>
    </div>
    \${!transfers?.length ? '<p style="color:var(--muted)">No transfers yet</p>' : ''}
    \${(transfers||[]).map(t=>{
      const isTo = t.to_user_id===currentUser?.id;
      const isPending = t.status==='pending';
      return \`<div class="transfer-item">
        <div class="avatar avatar-sm" style="background:\${isTo?t.from_color||'#6366f1':t.to_color||'#6366f1'}">\${initials(isTo?t.from_name:t.to_name)}</div>
        <div style="flex:1">
          <div style="font-weight:600">\${isTo?'From '+t.from_name:'To '+t.to_name}</div>
          <div style="font-size:13px;color:var(--muted)">\${t.note||''} · \${timeAgo(t.created_at)}</div>
        </div>
        <div>
          <div class="amount-badge \${isTo?'positive':'negative'}" style="display:block;text-align:right">\${isTo?'+':'-'}€\${parseFloat(t.amount).toFixed(2)}</div>
          <div style="font-size:12px;color:var(--muted);text-align:right">\${t.status}</div>
        </div>
        \${isPending&&isTo?\`<div style="display:flex;gap:6px">
          <button class="btn btn-sm btn-primary" onclick="actionTransfer('\${t.id}','confirm')">✅</button>
          <button class="btn btn-sm btn-danger" onclick="actionTransfer('\${t.id}','reject')">❌</button>
        </div>\`:''}
      </div>\`;
    }).join('')}
  </div>\`;
}
async function createTransfer() {
  const to = qs('#transferTo').value;
  const amount = parseFloat(qs('#transferAmount').value);
  const note = qs('#transferNote').value;
  if (!to || !amount) { toast('Fill in all fields'); return; }
  const r = await api('/api/transfers', {method:'POST', body:JSON.stringify({to_user_id:to, amount, note})});
  if (r.error) { toast('❌ '+r.error); return; }
  closeModal('newTransferModal'); toast('Transfer request sent! 💳'); loadTransfers();
}
async function actionTransfer(id, action) {
  const r = await api('/api/transfers/'+id+'/'+action, {method:'POST'});
  if (r.error) { toast('❌ '+r.error); return; }
  toast(action==='confirm'?'Confirmed! ✅':'Rejected'); loadTransfers();
}

async function loadVault() {
  const docs = await api('/api/documents');
  const c = qs('#moreContent');
  const typeIcon = {id:'🪪', insurance:'🛡️', medical:'🏥', finance:'💰', other:'📄'};
  c.innerHTML = \`<div style="padding:12px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div>
        <h3>Document Vault</h3>
        <p style="font-size:12px;color:var(--muted)">Files are encrypted end-to-end</p>
      </div>
      <button class="btn btn-sm btn-primary" onclick="openModal('uploadDocModal')">+ Upload</button>
    </div>
    \${!docs?.length ? '<div class="empty-state"><div class="icon">🔐</div><p>No documents yet</p></div>' : ''}
    \${(docs||[]).map(d=>\`<div class="doc-item" onclick="downloadDoc('\${d.id}','\${d.name}')">
      <div class="doc-icon">\${typeIcon[d.doc_type]||'📄'}</div>
      <div style="flex:1">
        <div style="font-weight:600">\${d.name}</div>
        <div style="font-size:12px;color:var(--muted)">\${d.owner_name||'You'} · \${(d.size_bytes/1024).toFixed(1)}KB</div>
      </div>
      <span style="font-size:20px;color:var(--muted)">⬇</span>
    </div>\`).join('')}
  </div>\`;
}
async function downloadDoc(id, name) {
  const headers = {};
  if (session?.token) headers['x-session-token'] = session.token;
  const r = await fetch('/api/documents/'+id+'/download', {headers});
  if (!r.ok) { toast('Error downloading'); return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}
async function uploadDoc() {
  const name = qs('#docName').value.trim();
  const file = qs('#docFile').files[0];
  if (!file) { toast('Pick a file'); return; }
  const fd = new FormData();
  fd.append('file', file);
  fd.append('name', name || file.name);
  fd.append('doc_type', qs('#docType').value);
  fd.append('shared', qs('#docShared').checked?'1':'0');
  const r = await apiForm('/api/documents/upload', fd);
  if (r.error) { toast('❌ '+r.error); return; }
  closeModal('uploadDocModal'); toast('Uploaded & encrypted! 🔐'); loadVault();
}

// ─── PROFILE ────────────────────────────────────────────────────────────────────
async function loadProfile() {
  const [notifs, families] = await Promise.all([api('/api/notifications'), api('/api/families')]);
  const activeFamId = localStorage.getItem('fh_active_family');
  const fam = (families||[]).find(f=>f.id===activeFamId) || (families||[])[0];
  if (fam && !activeFamId) localStorage.setItem('fh_active_family', fam.id);
  const c = qs('#profileContent');
  const avatarHtml = currentUser?.avatar_url
    ? \`<img src="\${currentUser.avatar_url}" style="width:80px;height:80px;border-radius:50%;object-fit:cover">\`
    : \`<div class="avatar avatar-lg" style="background:\${currentUser?.avatar_color||'#6366f1'}">\${initials(currentUser?.name||'')}</div>\`;
  c.innerHTML = \`
    <div style="display:flex;flex-direction:column;align-items:center;margin-bottom:20px;gap:10px">
      <div style="position:relative;cursor:pointer" onclick="qs('#avatarFileInput').click()">
        \${avatarHtml}
        <div style="position:absolute;bottom:0;right:0;background:var(--primary);border-radius:50%;width:24px;height:24px;display:flex;align-items:center;justify-content:center;font-size:14px">✏️</div>
      </div>
      <input type="file" id="avatarFileInput" accept="image/*" style="display:none" onchange="uploadAvatar(this)">
      <div style="text-align:center">
        <h2>\${esc(currentUser?.name||'')}</h2>
        <p style="color:var(--muted);font-size:13px">\${esc(currentUser?.role||'')}\${fam?' · '+esc(fam.name):''}</p>
      </div>
    </div>

    <div style="background:var(--surface2);border-radius:12px;padding:16px;margin-bottom:14px">
      <h3 style="margin-bottom:12px;font-size:15px">✏️ Edit Profile</h3>
      <div class="input-group"><label>Display Name</label><input type="text" id="editName" value="\${esc(currentUser?.name||'')}" placeholder="Your name"></div>
      <div class="input-group"><label>Bio</label><input type="text" id="editBio" value="\${esc(currentUser?.bio||'')}" placeholder="Something about you..."></div>
      <button class="btn btn-primary btn-full" onclick="saveProfile()">Save Changes</button>
    </div>

    <div style="background:var(--surface2);border-radius:12px;padding:16px;margin-bottom:14px">
      <h3 style="margin-bottom:12px;font-size:15px">🔒 Change Password</h3>
      <div class="input-group"><label>New Password</label><input type="password" id="newPwd" placeholder="Min 6 characters"></div>
      <div class="input-group"><label>Confirm</label><input type="password" id="confirmPwd" placeholder="Confirm new password"></div>
      <button class="btn btn-primary btn-full" onclick="changePassword()">Change Password</button>
    </div>

    \${fam ? \`<div style="background:var(--surface2);border-radius:12px;padding:16px;margin-bottom:14px">
      <h3 style="margin-bottom:4px;font-size:15px">🏠 \${esc(fam.name)}</h3>
      <p style="color:var(--muted);font-size:13px;margin-bottom:10px">Invite code: <strong style="font-size:16px;letter-spacing:2px">\${fam.invite_code||''}</strong></p>
      \${(families||[]).length > 1 ? \`<div style="margin:8px 0 10px"><p style="color:var(--muted);font-size:12px;margin-bottom:6px">Switch family:</p><div style="display:flex;flex-wrap:wrap;gap:6px">\${(families||[]).map(f=>\`<button onclick="switchFamily('\${f.id}')" style="padding:5px 12px;border-radius:20px;border:1px solid var(--border);background:\${f.id===fam.id?'var(--primary)':'var(--surface)'};color:\${f.id===fam.id?'#fff':'var(--text)'};cursor:pointer;font-size:13px">\${esc(f.name)}</button>\`).join('')}</div></div>\` : ''}
      <button class="btn btn-ghost btn-sm" onclick="openFamilySettings()">⚙️ Family Settings</button>
    </div>\` : ''}

    <div style="background:var(--surface2);border-radius:12px;padding:16px;margin-bottom:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <h3 style="font-size:15px;margin:0">🔔 Notifications \${notifs?.unread?\`<span style="background:var(--primary);color:white;border-radius:12px;padding:1px 7px;font-size:11px">\${notifs.unread}</span>\`:''}</h3>
        \${notifs?.unread ? '<button class="btn btn-ghost btn-sm" onclick="markAllRead()">Mark read</button>' : ''}
      </div>
      \${!notifs?.items?.length ? '<p style="color:var(--muted);font-size:13px">All caught up! 🎉</p>' : ''}
      \${(notifs?.items||[]).slice(0,8).map(n=>\`<div style="padding:8px 0;border-bottom:1px solid var(--border);opacity:\${n.read?'.5':'1'}">
        <div style="font-weight:\${!n.read?'600':'400'};font-size:13px">\${esc(n.title)}</div>
        <div style="font-size:12px;color:var(--muted)">\${esc(n.body)} · \${timeAgo(n.created_at)}</div>
      </div>\`).join('')}
    </div>

    <div style="background:var(--surface2);border-radius:12px;padding:16px;margin-bottom:14px" id="notifPrefsCard">
      <h3 style="margin-bottom:4px;font-size:15px">⚙️ Notification Settings</h3>
      <p style="color:var(--muted);font-size:12px;margin-bottom:12px">Choose what you get notified about</p>
      <div id="notifPrefToggles" style="display:flex;flex-direction:column;gap:10px">
        <div style="text-align:center;color:var(--muted);font-size:13px">Loading...</div>
      </div>
    </div>

    <button class="btn btn-ghost btn-full" onclick="logout()" style="color:#ef4444;margin-top:4px">Log Out</button>
  \`;
  loadNotifPrefs();
}
const _notifLabels = {
  post: {icon:'📸', label:'New posts', desc:'When someone shares a post'},
  comment: {icon:'💬', label:'Comments', desc:'When someone comments on your post'},
  reaction: {icon:'❤️', label:'Reactions', desc:'When someone reacts to your post'},
  event: {icon:'📅', label:'Events', desc:'When a new event is added'},
  message: {icon:'💬', label:'Messages', desc:'New chat messages'},
  expense: {icon:'💸', label:'Expenses', desc:'When added to an expense'},
  transfer: {icon:'💳', label:'Transfers', desc:'Money requests and confirmations'},
  chore: {icon:'✅', label:'Chores', desc:'Chore reminders and completions'},
  birthday: {icon:'🎂', label:'Birthdays', desc:'Birthday reminders'},
  kk: {icon:'🎅', label:'KK Draw', desc:'Secret Santa assignments'}
};

async function loadNotifPrefs() {
  const prefs = await api('/api/notification-prefs');
  const el = document.getElementById('notifPrefToggles');
  if (!el || !prefs) return;
  el.innerHTML = Object.entries(_notifLabels).map(([type, {icon, label, desc}]) => {
    const on = prefs[type] !== 0;
    return \`<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
      <div>
        <div style="font-size:14px;font-weight:600">\${icon} \${label}</div>
        <div style="font-size:12px;color:var(--muted)">\${desc}</div>
      </div>
      <button onclick="toggleNotifPref('\${type}',this)" style="background:\${on?'var(--primary)':'var(--surface)'};border:2px solid \${on?'var(--primary)':'var(--border)'};border-radius:20px;width:48px;height:26px;cursor:pointer;position:relative;transition:all .2s" data-on="\${on}">
        <span style="position:absolute;top:2px;\${on?'right:2px':'left:2px'};width:18px;height:18px;background:\${on?'#fff':'var(--muted)'};border-radius:50%;transition:all .2s;display:block"></span>
      </button>
    </div>\`;
  }).join('');
}

async function toggleNotifPref(type, btn) {
  const on = btn.dataset.on !== 'true';
  btn.dataset.on = on;
  btn.style.background = on ? 'var(--primary)' : 'var(--surface)';
  btn.style.borderColor = on ? 'var(--primary)' : 'var(--border)';
  const span = btn.querySelector('span');
  if (span) { span.style.right = on ? '2px' : ''; span.style.left = on ? '' : '2px'; span.style.background = on ? '#fff' : 'var(--muted)'; }
  await api('/api/notification-prefs', {method:'PUT', body:JSON.stringify({[type]: on ? 1 : 0})});
  toast(on ? '🔔 ' + (_notifLabels[type]?.label||type) + ' on' : '🔕 ' + (_notifLabels[type]?.label||type) + ' off');
}

function switchFamily(famId) {
  localStorage.setItem('fh_active_family', famId);
  currentFamily = null;
  allUsers = [];
  toast('Switched family ✅');
  loadProfile();
}
async function saveProfile() {
  const name = qs('#editName')?.value.trim();
  const bio = qs('#editBio')?.value.trim();
  if (!name) { toast('Name cannot be empty'); return; }
  const r = await api('/api/auth/profile', {method:'PATCH', body:JSON.stringify({name, bio:bio||null})});
  if (r?.error) { toast('❌ '+r.error); return; }
  currentUser = {...currentUser, name, bio};
  if (session) { session.user = currentUser; localStorage.setItem('fh_session', JSON.stringify(session)); }
  toast('Profile saved! ✅');
  loadProfile();
}
async function changePassword() {
  const pwd = qs('#newPwd')?.value;
  const conf = qs('#confirmPwd')?.value;
  if (!pwd || pwd.length < 6) { toast('Password must be at least 6 characters'); return; }
  if (pwd !== conf) { toast('Passwords do not match'); return; }
  const r = await api('/api/auth/profile', {method:'PATCH', body:JSON.stringify({password: pwd})});
  if (r?.error) { toast('❌ '+r.error); return; }
  if (qs('#newPwd')) qs('#newPwd').value = '';
  if (qs('#confirmPwd')) qs('#confirmPwd').value = '';
  toast('Password changed! 🔒');
}
async function markAllRead() {
  await api('/api/notifications/read-all', {method:'POST'});
  qs('#notifBadge').style.display='none';
  loadProfile();
}
async function pollNotifs() {
  const r = await api('/api/notifications');
  const badge = qs('#notifBadge');
  if (r?.unread > 0) { badge.textContent=r.unread; badge.style.display='block'; }
  else badge.style.display='none';
}
function logout() {
  api('/api/auth/logout', {method:'POST'});
  session=null; localStorage.removeItem('fh_session');
  location.reload();
}

// ═══════════════════════════════════════════
//  v3 FEATURE FUNCTIONS
// ═══════════════════════════════════════════

// ── FAMILY / SETTINGS ─────────────────────
let currentFamily = null;
async function ensureFamily() {
  if (currentFamily) return currentFamily;
  const r = await api('/api/families');
  if (r && r.length > 0) {
    const activeFamId = localStorage.getItem('fh_active_family');
    currentFamily = r.find(f=>f.id===activeFamId) || r[0];
    localStorage.setItem('fh_active_family', currentFamily.id);
    return currentFamily;
  }
  const f = await api('/api/families', {method:'POST', body:JSON.stringify({name:(currentUser?.name||'My')+' Family'})});
  currentFamily = f;
  if (f) localStorage.setItem('fh_active_family', f.id);
  return currentFamily;
}
async function openFamilySettings() {
  document.getElementById('familySettingsScreen').classList.add('open');
  const fam = await ensureFamily();
  if (!fam) return;
  document.getElementById('familyNameInput').value = fam.name||'';
  document.getElementById('familyDescInput').value = fam.description||'';
  document.getElementById('familyInviteCode').textContent = fam.invite_code||'------';
  const codeEl = document.getElementById('inviteCodeDisplay');
  if (codeEl) codeEl.textContent = fam.invite_code||'';
  loadPendingInvites();
  const settings = await api('/api/families/'+fam.id+'/settings')||{};
  const FEATURES = ['Feed','Stories','Chats','Events','Birthdays','Gifts','KK Draw','Expenses','Transfers','Vault','Shopping','Chores','Meals','Milestones','Recipes','Kindness'];
  document.getElementById('featureToggles').innerHTML = FEATURES.map(f=>\`
    <div class="toggle-row">
      <span class="toggle-label">\${f}</span>
      <label class="toggle">
        <input type="checkbox" \${settings[f]!==0?'checked':''} onchange="toggleFeature('\${f}',this.checked)">
        <span class="toggle-slider"></span>
      </label>
    </div>\`).join('');
  loadFamilyRules(fam.id);
  const members = await api('/api/families/'+fam.id+'/members')||[];
  document.getElementById('familyMembersList').innerHTML = members.map(m=>\`
    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
      \${avatarEl(m)}
      <span style="flex:1">\${esc(m.name)}</span>
      <span style="font-size:11px;background:\${m.role==='admin'?'var(--primary)':'var(--surface2)'};color:#fff;padding:2px 8px;border-radius:99px">\${m.role||'member'}</span>
    </div>\`).join('');
}
function closeFamilySettings() { document.getElementById('familySettingsScreen').classList.remove('open'); }
function toggleNewInviteForm() {
  const el = document.getElementById('newInviteForm');
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
async function loadPendingInvites() {
  const el = document.getElementById('pendingInvitesList');
  if (!el) return;
  const invites = await api('/api/admin/invites') || [];
  if (!invites.length) { el.innerHTML = '<div style="color:var(--muted);font-size:13px">All invites accepted ✓</div>'; return; }
  el.innerHTML = invites.map(inv => \`
    <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
      <div style="flex:1">
        <div style="font-size:14px;font-weight:600">\${esc(inv.name)}</div>
        <div style="font-size:11px;color:var(--muted)">\${inv.role||'member'}\${inv.email?' · '+esc(inv.email):''}</div>
      </div>
      <button class="btn-sm" onclick="sendInviteEmail(\${inv.id},'\${inv.name}')" style="font-size:11px">📧 \${inv.email ? 'Resend' : 'Email'}</button>
    </div>
  \`).join('');
}
async function sendInviteEmail(inviteId, name) {
  const el = document.querySelector(\`#pendingInvitesList button[onclick*="sendInviteEmail(\${inviteId}"]\`);
  // Prompt for email if not stored
  let email = prompt(\`Email address for \${name}:\`);
  if (!email) return;
  const r = await api(\`/api/admin/invites/\${inviteId}/email\`, {method:'POST', body:JSON.stringify({email})});
  if (r && r.ok) { toast(\`📧 Invite sent to \${email}!\`); loadPendingInvites(); }
  else toast('❌ ' + (r?.error || 'Failed to send'));
}
async function createAndSendInvite() {
  const name = document.getElementById('newInviteName')?.value.trim();
  const email = document.getElementById('newInviteEmail')?.value.trim();
  const role = document.getElementById('newInviteRole')?.value.trim() || 'member';
  if (!name) { toast('Enter a name'); return; }
  const r = await api('/api/admin/invites', {method:'POST', body:JSON.stringify({name, email, role})});
  if (r?.ok) {
    toast(email ? \`📧 Invite sent to \${email}!\` : '✅ Invite created');
    document.getElementById('newInviteName').value = '';
    document.getElementById('newInviteEmail').value = '';
    document.getElementById('newInviteRole').value = '';
    toggleNewInviteForm();
    loadPendingInvites();
  } else toast('❌ ' + (r?.error || 'Failed'));
}
async function saveFamilyInfo() {
  const fam = await ensureFamily();
  if (!fam) return;
  await api('/api/families/'+fam.id, {method:'PATCH', body:JSON.stringify({name:document.getElementById('familyNameInput').value.trim(), description:document.getElementById('familyDescInput').value.trim()})});
  currentFamily = null;
  toast('Saved! ✅');
}
async function toggleFeature(feature, enabled) {
  const fam = await ensureFamily();
  if (!fam) return;
  await api('/api/families/'+fam.id+'/settings', {method:'PATCH', body:JSON.stringify({feature, enabled:enabled?1:0})});
  applyFeatureToggle(feature, enabled);
}
function applyFeatureToggle(feature, enabled) {
  const navMap = {'Feed':'navFeed','Chats':'navChats','Events':'navEvents'};
  const moreTabMap = {'Birthdays':'birthdays','Gifts':'gifts','KK Draw':'kk','Expenses':'expenses','Transfers':'transfers','Vault':'vault','Shopping':'shopping','Chores':'chores','Meals':'meals','Milestones':'milestones','Recipes':'recipes','Kindness':'kindness','Photos':'photos'};
  if (navMap[feature]) { const el=document.getElementById(navMap[feature]); if(el)el.style.display=enabled?'':'none'; }
  if (moreTabMap[feature]) {
    const tabBtn = document.querySelector(\`#moreTabs .tab[onclick*="\${moreTabMap[feature]}"]\`);
    if (tabBtn) tabBtn.style.display = enabled?'':'none';
  }
}
async function applyAllFeatureToggles() {
  const fam = await ensureFamily();
  if (!fam) return;
  const settings = await api('/api/families/'+fam.id+'/settings')||{};
  Object.entries(settings).forEach(([f,v])=>{ if(v===0) applyFeatureToggle(f,false); });
}
function copyInviteCode() {
  const code = document.getElementById('familyInviteCode').textContent;
  const link = 'https://hub.luckdragon.io/?invite=' + code;
  if (navigator.clipboard) { navigator.clipboard.writeText(link).then(()=>toast('Link copied! 📋')); }
  else { const t=document.createElement('textarea');t.value=code;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);toast('Copied! 📋'); }
}
async function loadFamilyRules(familyId) {
  const rules = await api('/api/families/'+familyId+'/rules')||[];
  document.getElementById('familyRulesList').innerHTML = rules.length
    ? rules.map(r=>\`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px"><span style="flex:1">\${esc(r.rule)}</span><button onclick="deleteFamilyRule('\${familyId}','\${r.id}')" style="background:none;border:none;color:var(--muted);cursor:pointer">🗑</button></div>\`).join('')
    : '<div style="color:var(--muted);font-size:13px">No rules yet</div>';
}
async function addFamilyRule() {
  const fam = await ensureFamily();
  if (!fam) return;
  const r = document.getElementById('ruleInput').value.trim();
  if (!r) return;
  await api('/api/families/'+fam.id+'/rules', {method:'POST', body:JSON.stringify({rule:r})});
  document.getElementById('ruleInput').value='';
  loadFamilyRules(fam.id);
}
async function deleteFamilyRule(fid, rid) {
  await api('/api/families/'+fid+'/rules/'+rid, {method:'DELETE'});
  loadFamilyRules(fid);
}

// ── SHOPPING ──────────────────────────────
async function loadShopping() {
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="font-size:16px;font-weight:700">🛒 Shopping List</h3>
      <div style="display:flex;gap:8px;align-items:center">
        <button class="clear-done-btn" id="clearDoneBtn" style="display:none" onclick="clearDoneShopping()">Clear done</button>
        <button class="btn-sm" onclick="toggleShoppingForm()">+ Add</button>
      </div>
    </div>
    <div id="shoppingAddForm" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:12px">
      <input id="shoppingInput" placeholder="Item name..." style="width:100%;padding:10px 12px;background:var(--surface3);border:1.5px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px;font-size:15px">
      <select id="shoppingCat" style="width:100%;padding:10px 12px;background:var(--surface3);border:1.5px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
        <option value="Groceries">🥦 Groceries</option><option value="Household">🏠 Household</option>
        <option value="Kids">👶 Kids</option><option value="Other">📦 Other</option>
      </select>
      <button class="btn btn-primary" onclick="addShoppingItem()">Add Item</button>
    </div>
    <div id="shoppingList"></div>
  </div>\`;
  renderShoppingItems();
}
function toggleShoppingForm(){const f=document.getElementById('shoppingAddForm');if(f)f.style.display=f.style.display==='none'?'block':'none';}
async function renderShoppingItems() {
  const items = await api('/api/shopping');
  const el = document.getElementById('shoppingList');
  if (!el) return;
  const doneItems = (items||[]).filter(i=>i.done);
  const clearBtn = document.getElementById('clearDoneBtn');
  if (clearBtn) { clearBtn.style.display = doneItems.length ? 'block' : 'none'; if(doneItems.length) clearBtn.textContent = \`Clear done (\${doneItems.length})\`; }
  if (!items||!items.length){el.innerHTML='<div style="text-align:center;color:var(--muted);padding:32px"><div style="font-size:36px;margin-bottom:8px">🛒</div><p>Nothing on the list yet</p></div>';return;}
  const undone = items.filter(i=>!i.done);
  const done = items.filter(i=>i.done);
  // Group undone by category
  const cats = {};
  for (const i of undone) { const c = i.category||'Other'; if(!cats[c]) cats[c]=[]; cats[c].push(i); }
  const catIcons = {Groceries:'🥦',Household:'🏠',Kids:'👶',Other:'📦'};
  let html = '';
  for (const [cat, catItems] of Object.entries(cats)) {
    html += \`<div class="shop-cat-header">\${catIcons[cat]||'📦'} \${cat}</div>\`;
    html += catItems.map(i=>\`<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04)">
      <input type="checkbox" style="width:20px;height:20px;cursor:pointer;accent-color:var(--primary);flex-shrink:0" onchange="toggleShoppingItem('\${i.id}',this.checked)">
      <span style="flex:1;font-size:14px">\${esc(i.title)}</span>
      <button onclick="deleteShoppingItem('\${i.id}')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:15px;padding:2px 4px">🗑</button>
    </div>\`).join('');
  }
  if (done.length) {
    html += \`<div class="shop-cat-header" style="color:var(--muted)">✓ Done</div>\`;
    html += done.map(i=>\`<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04);opacity:.55">
      <input type="checkbox" checked style="width:20px;height:20px;cursor:pointer;accent-color:var(--primary);flex-shrink:0" onchange="toggleShoppingItem('\${i.id}',this.checked)">
      <span style="flex:1;font-size:14px;text-decoration:line-through;color:var(--muted)">\${esc(i.title)}</span>
      <button onclick="deleteShoppingItem('\${i.id}')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:15px;padding:2px 4px">🗑</button>
    </div>\`).join('');
  }
  el.innerHTML = html;
}
async function clearDoneShopping() {
  const items = await api('/api/shopping');
  const done = (items||[]).filter(i=>i.done);
  await Promise.all(done.map(i=>api('/api/shopping/'+i.id,{method:'DELETE'})));
  renderShoppingItems();
  toast(\`Cleared \${done.length} done item\${done.length===1?'':'s'} ✓\`);
}
async function addShoppingItem(){
  const t=document.getElementById('shoppingInput')?.value.trim();
  const cat=document.getElementById('shoppingCat')?.value;
  if(!t)return;
  await api('/api/shopping',{method:'POST',body:JSON.stringify({title:t,category:cat})});
  document.getElementById('shoppingInput').value='';
  renderShoppingItems();
}
async function toggleShoppingItem(id,done){await api('/api/shopping/'+id,{method:'PATCH',body:JSON.stringify({done:done?1:0})});renderShoppingItems();}
async function deleteShoppingItem(id){await api('/api/shopping/'+id,{method:'DELETE'});renderShoppingItems();}

// ── CHORES ────────────────────────────────
async function loadChores() {
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="font-size:16px;font-weight:700">✅ Chores</h3>
      <button class="btn-sm" onclick="toggleChoreForm()">+ Add</button>
    </div>
    <div id="choreLeaderboard" style="margin-bottom:12px"></div>
    <div id="choreAddForm" style="display:none;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:12px">
      <input id="choreTitleInput" placeholder="Chore name..." style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
      <select id="choreAssign" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
        <option value="">Anyone</option>\${(allUsers||[]).map(u=>\`<option value="\${u.id}">\${esc(u.name)}</option>\`).join('')}
      </select>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <select id="chorePoints" style="flex:1;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text)">
          <option value="1">⭐ 1pt</option><option value="2">⭐⭐ 2pt</option><option value="3">⭐⭐⭐ 3pt</option><option value="5">⭐ 5pt</option>
        </select>
        <select id="choreFreq" style="flex:1;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text)">
          <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option>
        </select>
      </div>
      <button class="btn" onclick="addChore()">Add Chore</button>
    </div>
    <div id="choreList"></div>
  </div>\`;
  renderChores();
  renderChoreLeaderboard();
}
async function renderChoreLeaderboard() {
  const el = document.getElementById('choreLeaderboard');
  if (!el) return;
  const chores = await api('/api/chores') || [];
  // Tally points by completer (done_today count * points as proxy)
  const pts = {};
  for (const ch of chores) {
    if (ch.last_done_by && ch.done_today > 0) {
      pts[ch.last_done_by] = (pts[ch.last_done_by]||0) + (ch.points||1) * ch.done_today;
    }
  }
  const sorted = Object.entries(pts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  if (!sorted.length) { el.innerHTML=''; return; }
  const medals = ['🥇','🥈','🥉','4th','5th'];
  el.innerHTML = \`<div class="leaderboard">
    <div class="leaderboard-title">⭐ This Week's Stars</div>
    \${sorted.map(([uid,p],i)=>{
      const u=(allUsers||[]).find(x=>x.id===uid);
      return \`<div class="lb-row">
        <div class="lb-rank \${i===0?'gold':''}">\${medals[i]||i+1}</div>
        <div style="font-size:13px;font-weight:600">\${esc(u?.name||'Unknown')}</div>
        <div class="lb-pts">\${p}pt\${p===1?'':'s'}</div>
      </div>\`;
    }).join('')}
  </div>\`;
}
function toggleChoreForm(){const f=document.getElementById('choreAddForm');if(f)f.style.display=f.style.display==='none'?'block':'none';}
async function renderChores() {
  const chores = await api('/api/chores');
  const el = document.getElementById('choreList');
  if (!el) return;
  if (!chores||!chores.length){el.innerHTML='<div style="text-align:center;color:var(--muted);padding:32px">No chores yet ✅</div>';return;}
  el.innerHTML=chores.map(ch=>{
    const assignee=(allUsers||[]).find(u=>u.id===ch.assigned_to);
    return \`<div style="background:var(--surface);border-radius:12px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px">
      <div style="flex:1">
        <div style="font-weight:600">\${esc(ch.title)}</div>
        <div style="font-size:12px;color:var(--muted);margin-top:2px">\${assignee?'→ '+esc(assignee.name):'Anyone'} · \${ch.frequency} · Done today: \${ch.done_today||0}</div>
      </div>
      <span style="background:#fbbf24;color:#000;font-size:11px;padding:2px 7px;border-radius:99px;font-weight:700">⭐\${ch.points||1}</span>
      <button onclick="completeChore('\${ch.id}')" style="background:var(--success);color:#fff;border:none;border-radius:8px;padding:7px 12px;font-size:12px;cursor:pointer">✓ Done</button>
      <button onclick="deleteChore('\${ch.id}')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px;padding:0 4px" title="Delete">🗑</button>
    </div>\`;
  }).join('');
}
async function addChore(){
  const t=document.getElementById('choreTitleInput')?.value.trim();
  if(!t)return;
  await api('/api/chores',{method:'POST',body:JSON.stringify({title:t,assigned_to:document.getElementById('choreAssign')?.value||null,points:parseInt(document.getElementById('chorePoints')?.value||'1'),frequency:document.getElementById('choreFreq')?.value||'daily'})});
  if(document.getElementById('choreTitleInput'))document.getElementById('choreTitleInput').value='';
  if(document.getElementById('choreAddForm'))document.getElementById('choreAddForm').style.display='none';
  renderChores();
}
async function completeChore(id){await api('/api/chores/'+id+'/complete',{method:'POST'});renderChores();renderChoreLeaderboard();}
async function deleteChore(id){if(!confirm('Delete this chore?'))return;await api('/api/chores/'+id,{method:'DELETE'});renderChores();}

// ── MEALS ─────────────────────────────────
const DAYS=['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
async function loadMeals() {
  const c = qs('#moreContent');
  const weekLabel = mealWeekOffset === 0 ? 'This Week' : mealWeekOffset === -1 ? 'Last Week' : mealWeekOffset === 1 ? 'Next Week' : (mealWeekOffset > 0 ? \`+\${mealWeekOffset}w\` : \`\${mealWeekOffset}w\`);
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h3 style="font-size:16px;font-weight:700;margin:0">🍽️ Meal Rota</h3>
      <div style="display:flex;align-items:center;gap:8px">
        <button class="btn-sm" onclick="mealWeekOffset--;loadMeals()">‹</button>
        <span style="font-size:13px;font-weight:600;min-width:80px;text-align:center">\${weekLabel}</span>
        <button class="btn-sm" onclick="mealWeekOffset++;loadMeals()">›</button>
      </div>
    </div>
    <div id="mealGrid"></div>
  </div>\`;
  const resp = await api('/api/meals?offset=' + mealWeekOffset);
  const meals = (resp && resp.meals) || [];
  const grid = document.getElementById('mealGrid');
  if (!grid) return;
  grid.innerHTML = DAYS.map((day,i)=>{
    const m = meals.find(x=>x.day_of_week===i);
    const cook = m&&m.cook_id?(allUsers||[]).find(u=>u.id===m.cook_id):null;
    return \`<div style="background:var(--surface);border-radius:10px;padding:12px;margin-bottom:8px;cursor:pointer" onclick="editMealDay(\${i})">
      <div style="display:flex;align-items:center;gap:12px">
        <span style="width:36px;font-size:12px;font-weight:700;color:var(--primary)">\${day.slice(0,3)}</span>
        <div style="flex:1">
          <div style="font-size:14px;font-weight:500">\${m?esc(m.meal):'<span style="color:var(--muted)">Not planned</span>'}</div>
          \${cook?\`<div style="font-size:12px;color:var(--muted)">🧑‍🍳 \${esc(cook.name)}</div>\`:''}
        </div>
        <span style="color:var(--muted)">✏️</span>
      </div>
      <div id="mealEdit_\${i}" style="display:none;margin-top:10px;background:var(--surface2);border-radius:8px;padding:10px">
        <input id="mealInput_\${i}" placeholder="What's for dinner?" value="\${m?esc(m.meal):''}" style="width:100%;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);margin-bottom:8px">
        <select id="mealCook_\${i}" style="width:100%;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);margin-bottom:8px">
          <option value="">No cook</option>\${(allUsers||[]).map(u=>\`<option value="\${u.id}"\${m&&m.cook_id===u.id?' selected':''}>\${esc(u.name)}</option>\`).join('')}
        </select>
        <div style="display:flex;gap:8px">
          <button class="btn" onclick="event.stopPropagation();saveMeal(\${i})">Save</button>
          <button class="btn-sm" onclick="event.stopPropagation();document.getElementById('mealEdit_\${i}').style.display='none'">Cancel</button>
        </div>
      </div>
    </div>\`;
  }).join('');
}
function editMealDay(i){
  DAYS.forEach((_,j)=>{const e=document.getElementById('mealEdit_'+j);if(e&&j!==i)e.style.display='none';});
  const el=document.getElementById('mealEdit_'+i);
  if(el)el.style.display=el.style.display==='none'?'block':'none';
}
async function saveMeal(i){
  const meal=document.getElementById('mealInput_'+i)?.value.trim();
  const cook_id=document.getElementById('mealCook_'+i)?.value||null;
  if(!meal)return;
  await api('/api/meals',{method:'POST',body:JSON.stringify({day_of_week:i,meal,cook_id,week_offset:mealWeekOffset})});
  loadMeals();
}

// ── MILESTONES ────────────────────────────
async function loadMilestones() {
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="font-size:16px;font-weight:700">🏆 Milestones</h3>
      <button class="btn-sm" onclick="toggleMilestoneForm()">+ Add</button>
    </div>
    <div id="milestoneAddForm" style="display:none;background:var(--surface);border-radius:10px;padding:12px;margin-bottom:12px">
      <input id="milestoneTitleInput" placeholder="What happened?" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
      <textarea id="milestoneDescInput" placeholder="Tell the story..." rows="2" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px"></textarea>
      <input id="milestoneDateInput" type="date" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
      <button class="btn" onclick="addMilestone()">Add Milestone</button>
    </div>
    <div id="milestoneList" style="position:relative;padding-left:24px"></div>
  </div>\`;
  const ms = await api('/api/milestones');
  const el = document.getElementById('milestoneList');
  if (!el) return;
  if (!ms||!ms.length){el.innerHTML='<div style="color:var(--muted);text-align:center;padding:32px">No milestones yet 🏆</div>';return;}
  el.innerHTML = '<div style="position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)"></div>' +
    ms.map(m=>\`<div style="position:relative;margin-bottom:20px">
      <div style="position:absolute;left:-20px;top:4px;width:12px;height:12px;border-radius:50%;background:var(--primary);border:2px solid var(--surface)"></div>
      <div style="background:var(--surface);border-radius:12px;padding:12px">
        \${m.date?\`<div style="font-size:11px;color:var(--primary);margin-bottom:4px">\${m.date}</div>\`:''}
        <div style="font-weight:600;margin-bottom:4px">\${esc(m.title)}</div>
        \${m.description?\`<div style="font-size:13px;color:var(--muted)">\${esc(m.description)}</div>\`:''}
      </div>
    </div>\`).join('');
}
function toggleMilestoneForm(){const f=document.getElementById('milestoneAddForm');if(f)f.style.display=f.style.display==='none'?'block':'none';}
async function addMilestone(){
  const t=document.getElementById('milestoneTitleInput')?.value.trim();
  if(!t)return;
  await api('/api/milestones',{method:'POST',body:JSON.stringify({title:t,description:document.getElementById('milestoneDescInput')?.value.trim()||null,date:document.getElementById('milestoneDateInput')?.value||null})});
  loadMilestones();
}

// ── RECIPES ───────────────────────────────
async function loadRecipes() {
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="font-size:16px;font-weight:700">📖 Recipes</h3>
      <button class="btn-sm" onclick="toggleRecipeForm()">+ Add</button>
    </div>
    <div id="recipeAddForm" style="display:none;background:var(--surface);border-radius:10px;padding:12px;margin-bottom:12px">
      <input id="recipeTitleInput" placeholder="Recipe name..." style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
      <textarea id="recipeDescInput" placeholder="Description..." rows="2" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px"></textarea>
      <textarea id="recipeIngInput" placeholder="Ingredients (one per line)..." rows="4" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px"></textarea>
      <textarea id="recipeStepsInput" placeholder="Steps..." rows="4" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px"></textarea>
      <button class="btn" onclick="addRecipe()">Save Recipe</button>
    </div>
    <div id="recipeGrid" style="display:grid;grid-template-columns:1fr 1fr;gap:10px"></div>
  </div>\`;
  const recipes = await api('/api/recipes');
  const el = document.getElementById('recipeGrid');
  if (!el) return;
  if (!recipes||!recipes.length){el.style.gridColumn='span 2';el.innerHTML='<div style="color:var(--muted);text-align:center;padding:32px;grid-column:span 2">No recipes yet 📖</div>';return;}
  el.innerHTML=recipes.map(r=>\`<div onclick="expandRecipe('\${r.id}')" style="background:var(--surface);border-radius:12px;padding:14px;cursor:pointer;border:1px solid var(--border)">
    <div style="font-size:14px;font-weight:600;margin-bottom:4px">\${esc(r.title)}</div>
    <div style="font-size:12px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${esc(r.description||'Tap to view')}</div>
  </div>\`).join('');
}
function toggleRecipeForm(){const f=document.getElementById('recipeAddForm');if(f)f.style.display=f.style.display==='none'?'block':'none';}
async function addRecipe(){
  const t=document.getElementById('recipeTitleInput')?.value.trim();
  if(!t)return;
  await api('/api/recipes',{method:'POST',body:JSON.stringify({title:t,description:document.getElementById('recipeDescInput')?.value.trim()||null,ingredients:document.getElementById('recipeIngInput')?.value.trim()||null,steps:document.getElementById('recipeStepsInput')?.value.trim()||null})});
  loadRecipes();
}
async function expandRecipe(id){
  const r=await api('/api/recipes/'+id);
  if(!r)return;
  const c=qs('#moreContent');
  c.innerHTML=\`<div style="padding:16px">
    <button onclick="loadRecipes()" style="background:none;border:none;color:var(--primary);cursor:pointer;font-size:14px;margin-bottom:12px">← Back</button>
    <h2 style="font-size:20px;font-weight:700;margin-bottom:8px">\${esc(r.title)}</h2>
    \${r.description?\`<p style="color:var(--muted);margin-bottom:12px">\${esc(r.description)}</p>\`:''}
    <div style="font-weight:700;margin-bottom:8px">🧂 Ingredients</div>
    <div style="background:var(--surface);border-radius:10px;padding:12px;margin-bottom:12px;white-space:pre-wrap;font-size:13px">\${esc(r.ingredients||'')}</div>
    <div style="font-weight:700;margin-bottom:8px">📝 Steps</div>
    <div style="background:var(--surface);border-radius:10px;padding:12px;white-space:pre-wrap;font-size:13px">\${esc(r.steps||'')}</div>
  </div>\`;
}

// ── KINDNESS ──────────────────────────────
async function loadKindness() {
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 style="font-size:16px;font-weight:700">💛 Kindness Board</h3>
      <button class="btn-sm" onclick="toggleKindnessForm()">+ Add</button>
    </div>
    <div id="kindnessAddForm" style="display:none;background:var(--surface);border-radius:10px;padding:12px;margin-bottom:12px">
      <input id="kindnessTitleInput" placeholder="Act of kindness..." style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px">
      <textarea id="kindnessDescInput" placeholder="Describe it..." rows="2" style="width:100%;padding:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);margin-bottom:8px"></textarea>
      <button class="btn" onclick="addKindness()">Add</button>
    </div>
    <div id="kindnessList"></div>
  </div>\`;
  renderKindness();
}
function toggleKindnessForm(){const f=document.getElementById('kindnessAddForm');if(f)f.style.display=f.style.display==='none'?'block':'none';}

// ── PHOTO ALBUM ────────────────────────────────────────────────
let viewingAlbumPhoto = null;
async function loadAlbum() {
  const c = qs('#moreContent');
  c.innerHTML = \`<div style="padding:16px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <h3 style="font-size:16px;font-weight:700">📸 Family Photos</h3>
      <label style="background:var(--primary);color:#fff;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600">
        + Upload <input type="file" accept="image/*" style="display:none" onchange="uploadAlbumPhoto(this)">
      </label>
    </div>
    <div id="albumGrid" style="display:grid;grid-template-columns:repeat(3,1fr);gap:3px"></div>
    <div id="albumViewer" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:200;flex-direction:column;align-items:center;justify-content:center" onclick="closeAlbumViewer(event)">
      <button onclick="closeAlbumViewer()" style="position:absolute;top:16px;right:16px;background:none;border:none;color:#fff;font-size:28px;cursor:pointer;line-height:1">&#x2715;</button>
      <img id="albumViewerImg" style="max-width:95vw;max-height:62vh;border-radius:8px;object-fit:contain">
      <div style="background:#111;border-radius:12px;padding:14px;margin-top:12px;max-width:360px;width:90%">
        <div id="albumViewerCaption" style="color:#fff;font-size:14px;margin-bottom:4px"></div>
        <div id="albumViewerMeta" style="color:#888;font-size:12px;margin-bottom:10px"></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
          <button onclick="reactAlbum('❤️')" style="background:#222;border:none;color:#fff;padding:6px 12px;border-radius:20px;cursor:pointer;font-size:15px">❤️ <span id="albumReact_heart">0</span></button>
          <button onclick="reactAlbum('😂')" style="background:#222;border:none;color:#fff;padding:6px 12px;border-radius:20px;cursor:pointer;font-size:15px">😂 <span id="albumReact_laugh">0</span></button>
          <button onclick="reactAlbum('🔥')" style="background:#222;border:none;color:#fff;padding:6px 12px;border-radius:20px;cursor:pointer;font-size:15px">🔥 <span id="albumReact_fire">0</span></button>
          <div style="flex:1"></div>
          <button id="albumDeleteBtn" style="display:none;background:#ef4444;border:none;color:#fff;padding:6px 12px;border-radius:8px;cursor:pointer;font-size:12px" onclick="deleteAlbumPhoto()">Delete</button>
        </div>
      </div>
    </div>
  </div>\`;
  renderAlbumGrid();
}
async function renderAlbumGrid() {
  const photos = await api('/api/album');
  const grid = document.getElementById('albumGrid');
  if (!grid) return;
  if (!photos||!photos.length) {
    grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--muted);padding:40px 20px">No photos yet 📸<br><span style="font-size:13px">Tap + Upload to share one!</span></div>';
    return;
  }
  grid.innerHTML = photos.map(p=>\`<div onclick="openAlbumPhoto(\${JSON.stringify(p).replace(/"/g,'&quot;')})" style="aspect-ratio:1;overflow:hidden;cursor:pointer;background:var(--surface2)">
    <img src="/api/photos/\${encodeURIComponent(p.r2_key)}" style="width:100%;height:100%;object-fit:cover" loading="lazy">
  </div>\`).join('');
}
async function uploadAlbumPhoto(input) {
  const file = input.files[0];
  if (!file) return;
  const caption = prompt('Caption (optional):') || '';
  toast('Uploading... 📸');
  const fd = new FormData();
  fd.append('file', file);
  fd.append('folder', 'album');
  const up = await fetch('/api/photos/upload', {method:'POST', headers:{'X-Session-Token':session?.token||''}, body:fd});
  const upData = await up.json();
  if (!upData.key) { toast('Upload failed ❌'); return; }
  await api('/api/album', {method:'POST', body:JSON.stringify({r2_key:upData.key, caption:caption||null})});
  toast('Photo shared! 📸');
  renderAlbumGrid();
}
function openAlbumPhoto(p) {
  viewingAlbumPhoto = p;
  const v = document.getElementById('albumViewer');
  if (!v) return;
  v.style.display = 'flex';
  document.getElementById('albumViewerImg').src = '/api/photos/' + encodeURIComponent(p.r2_key);
  document.getElementById('albumViewerCaption').textContent = p.caption || '';
  document.getElementById('albumViewerMeta').textContent = (p.uploader_name||'Someone') + ' · ' + timeAgo(p.created_at);
  document.getElementById('albumDeleteBtn').style.display = p.user_id === currentUser?.id ? 'block' : 'none';
  const counts = p.reaction_counts || {};
  document.getElementById('albumReact_heart').textContent = counts['❤️']||0;
  document.getElementById('albumReact_laugh').textContent = counts['😂']||0;
  document.getElementById('albumReact_fire').textContent = counts['🔥']||0;
}
function closeAlbumViewer(e) {
  if (e && e.target.id !== 'albumViewer') return;
  const v = document.getElementById('albumViewer');
  if (v) v.style.display = 'none';
  viewingAlbumPhoto = null;
}
async function reactAlbum(emoji) {
  if (!viewingAlbumPhoto) return;
  await api('/api/album/'+viewingAlbumPhoto.id+'/react', {method:'POST', body:JSON.stringify({reaction:emoji})});
  const photos = await api('/api/album');
  const updated = (photos||[]).find(p=>p.id===viewingAlbumPhoto.id);
  if (updated) openAlbumPhoto(updated);
  renderAlbumGrid();
}
async function deleteAlbumPhoto() {
  if (!viewingAlbumPhoto || !confirm('Delete this photo?')) return;
  await api('/api/album/'+viewingAlbumPhoto.id, {method:'DELETE'});
  const v = document.getElementById('albumViewer');
  if (v) v.style.display = 'none';
  viewingAlbumPhoto = null;
  renderAlbumGrid();
}

async function renderKindness(){
  const acts=await api('/api/kindness');
  const el=document.getElementById('kindnessList');
  if(!el)return;
  if(!acts||!acts.length){el.innerHTML='<div style="text-align:center;color:var(--muted);padding:32px">Be the first to spread kindness 💛</div>';return;}
  el.innerHTML=acts.map(a=>\`<div style="background:var(--surface);border-radius:12px;padding:14px;margin-bottom:10px;border-left:3px solid \${a.done?'var(--surface2)':'#fbbf24'};\${a.done?'opacity:.6':''}">
    <div style="font-weight:600;margin-bottom:4px">\${esc(a.title)}</div>
    \${a.description?\`<div style="font-size:13px;color:var(--muted);margin-bottom:8px">\${esc(a.description)}</div>\`:''}
    \${a.done?\`<div style="font-size:12px;color:var(--success)">✓ Done\${a.done_by_name?' by '+esc(a.done_by_name):''}</div>\`
      :\`<button onclick="markKindnessDone('\${a.id}')" style="background:var(--success);color:#fff;border:none;border-radius:8px;padding:7px 12px;font-size:12px;cursor:pointer">✓ I did this!</button>\`}
  </div>\`).join('');
}
async function addKindness(){
  const t=document.getElementById('kindnessTitleInput')?.value.trim();
  if(!t)return;
  await api('/api/kindness',{method:'POST',body:JSON.stringify({title:t,description:document.getElementById('kindnessDescInput')?.value.trim()||null})});
  document.getElementById('kindnessTitleInput').value='';
  if(document.getElementById('kindnessAddForm'))document.getElementById('kindnessAddForm').style.display='none';
  renderKindness();
}
async function markKindnessDone(id){await api('/api/kindness/'+id+'/done',{method:'PATCH'});renderKindness();}

// ── CHAT RENAME ───────────────────────────
async function renameChat(){
  const newName=prompt('Rename chat:',document.getElementById('chatName')?.textContent||'');
  if(!newName||!currentChatId)return;
  await api('/api/chats/'+currentChatId,{method:'PATCH',body:JSON.stringify({name:newName.trim()})});
  if(document.getElementById('chatName'))document.getElementById('chatName').textContent=newName.trim();
  currentChatName=newName.trim();
  loadChats();
}

// ── AVATAR UPLOAD ─────────────────────────
async function uploadAvatar(input){
  if(!input.files[0])return;
  const fd=new FormData();fd.append('file',input.files[0]);
  const headers={'x-session-token':session?.token||''};
  const r=await fetch('/api/avatar',{method:'POST',headers,body:fd}).then(r=>r.json());
  if(r.avatar_url){currentUser.avatar_url=r.avatar_url;session.user=currentUser;localStorage.setItem('fh_session',JSON.stringify(session));loadProfile();}
}

// ── PARTY PLANNER ─────────────────────────
async function toggleBringList(eventId){
  const el=document.getElementById('bringList_'+eventId);
  if(!el)return;
  if(el.style.display==='none'||!el.style.display){
    el.style.display='block';
    const items=await api('/api/events/'+eventId+'/items')||[];
    el.innerHTML=\`<div style="background:var(--surface2);border-radius:10px;padding:12px;margin-top:4px">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">Who's bringing what?</div>
      \${items.map(i=>\`<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px">
        <span>\${esc(i.title)}</span>
        \${i.claimed_by?(i.claimed_by===currentUser?.id
          ?\`<span style="color:var(--success);font-size:11px;font-weight:600">✓ You <button onclick="claimItem('\${eventId}','\${i.id}')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:11px">unclaim</button></span>\`
          :\`<span style="color:var(--success);font-size:11px;font-weight:600">✓ \${esc(i.claimer_name||'Someone')}</span>\`)
          :\`<button onclick="claimItem('\${eventId}','\${i.id}')" style="background:var(--primary);color:#fff;border:none;border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer">I'll bring it</button>\`}
      </div>\`).join('')}
      <div style="display:flex;gap:8px;margin-top:8px">
        <input id="bringInput_\${eventId}" placeholder="Add item..." style="flex:1;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text)">
        <button onclick="addBringItem('\${eventId}')" style="background:var(--primary);color:#fff;border:none;border-radius:6px;padding:8px 12px;cursor:pointer">Add</button>
      </div>
    </div>\`;
  } else { el.style.display='none'; }
}
async function addBringItem(eventId){
  const t=document.getElementById('bringInput_'+eventId)?.value.trim();
  if(!t)return;
  await api('/api/events/'+eventId+'/items',{method:'POST',body:JSON.stringify({title:t})});
  document.getElementById('bringList_'+eventId).style.display='none';
  toggleBringList(eventId);
}
async function claimItem(eventId,itemId){
  await api('/api/events/'+eventId+'/items/'+itemId+'/claim',{method:'POST'});
  document.getElementById('bringList_'+eventId).style.display='none';
  toggleBringList(eventId);
}

// ── EMERGENCY INFO ─────────────────────────
async function loadEmergencyInfo(){
  const el=document.getElementById('emergencyCard');
  if(!el)return;
  const info=await api('/api/emergency');
  if(!info||!info.name){el.innerHTML=\`<div style="color:var(--muted);font-size:13px;margin-bottom:10px">No emergency info saved yet.</div><button class="btn-sm" onclick="showEmergencyForm()">+ Add Info</button>\`;return;}
  el.innerHTML=[['Blood Type',info.blood_type],['Allergies',info.allergies],['Medications',info.medications],['Contact',info.name+(info.relationship?' ('+info.relationship+')':'')],['Phone',info.phone],['Notes',info.notes]]
    .filter(([,v])=>v).map(([l,v])=>\`<div style="display:flex;gap:8px;margin-bottom:6px;font-size:13px"><span style="color:var(--muted);width:90px;flex-shrink:0">\${l}</span><span>\${esc(String(v))}</span></div>\`).join('')
    +\`<button class="btn-sm" onclick="showEmergencyForm()" style="margin-top:8px">✏️ Edit</button>\`;
}
async function showEmergencyForm(){
  const info=await api('/api/emergency')||{};
  const el=document.getElementById('emergencyCard');
  if(!el)return;
  el.innerHTML=\`<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
    <input id="emName" placeholder="Contact name" value="\${esc(String(info.name||''))}" style="padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
    <input id="emRel" placeholder="Relationship" value="\${esc(String(info.relationship||''))}" style="padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
    <input id="emPhone" placeholder="Phone" value="\${esc(String(info.phone||''))}" style="padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
    <input id="emBlood" placeholder="Blood type (e.g. A+)" value="\${esc(String(info.blood_type||''))}" style="padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text)">
  </div>
  <textarea id="emAllergies" placeholder="Allergies..." rows="2" style="width:100%;padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);margin-bottom:8px">\${esc(String(info.allergies||''))}</textarea>
  <textarea id="emMeds" placeholder="Medications..." rows="2" style="width:100%;padding:8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);margin-bottom:8px">\${esc(String(info.medications||''))}</textarea>
  <button class="btn" onclick="saveEmergencyInfo()">Save</button>\`;
}
async function saveEmergencyInfo(){
  await api('/api/emergency',{method:'POST',body:JSON.stringify({name:document.getElementById('emName')?.value.trim(),relationship:document.getElementById('emRel')?.value.trim(),phone:document.getElementById('emPhone')?.value.trim(),blood_type:document.getElementById('emBlood')?.value.trim(),allergies:document.getElementById('emAllergies')?.value.trim(),medications:document.getElementById('emMeds')?.value.trim()})});
  loadEmergencyInfo();
  toast('Saved! ✅');
}

// ── START APP HOOK ────────────────────────
const _origStartApp = window.startApp || startApp;
window.startApp = function() {
  _origStartApp();
  setTimeout(applyAllFeatureToggles, 2000);
};


// ─── AUTO-POLLING (no hard refreshes ever) ───────────────────────────────────
let _pollIntervals = {};
let _lastChatMsgId = null;
let _lastFeedTs = null;

function initPullToRefresh() {
  const list = document.getElementById('feedList');
  if (!list || list._ptr) return;
  list._ptr = true;
  let startY = 0, pulling = false, ind = null;
  list.addEventListener('touchstart', e => { if (list.scrollTop === 0) { startY = e.touches[0].clientY; pulling = true; } }, {passive:true});
  list.addEventListener('touchmove', e => {
    if (!pulling) return;
    const dy = e.touches[0].clientY - startY;
    if (dy > 8 && dy < 90) {
      if (!ind) { ind = document.createElement('div'); ind.style.cssText='text-align:center;padding:10px;color:var(--primary);font-size:13px;font-weight:600'; ind.textContent='\u2193 Pull to refresh'; list.prepend(ind); }
      ind.style.opacity = Math.min(1, dy/60);
      ind.textContent = dy > 60 ? '\u2191 Release to refresh' : '\u2193 Pull to refresh';
    }
  }, {passive:true});
  list.addEventListener('touchend', e => {
    if (!pulling) return; pulling = false;
    const dy = e.changedTouches[0].clientY - startY;
    if (ind) { ind.remove(); ind = null; }
    if (dy > 60) { if (navigator.vibrate) navigator.vibrate(30); loadFeed(); toast('Refreshed ✓'); }
  }, {passive:true});
}
function startPolling() {
  stopPolling();
  // Chat: every 5s when chat screen visible
  _pollIntervals.chat = setInterval(async () => {
    if (!currentChatId) return;
    const screen = document.getElementById('chatScreen');
    if (!screen || !screen.classList.contains('open')) return;
    const msgs = await api(\`/api/chats/\${currentChatId}/messages\`);
    if (!msgs || !Array.isArray(msgs)) return;
    const lastId = msgs[msgs.length-1]?.id;
    if (lastId && lastId !== _lastChatMsgId) {
      _lastChatMsgId = lastId;
      if (navigator.vibrate) navigator.vibrate([30,15,30]);
      renderMessages(msgs);
      // Auto-scroll to bottom only if already near bottom
      const ml = document.getElementById('messageList');
      if (ml && ml.scrollHeight - ml.scrollTop - ml.clientHeight < 120) {
        ml.scrollTop = ml.scrollHeight;
      }
    }
  }, 5000);

  // Feed: every 15s when feed screen active
  _pollIntervals.feed = setInterval(async () => {
    const screen = document.getElementById('screenFeed');
    if (!screen || !screen.classList.contains('active')) return;
    const posts = await api('/api/posts?limit=20');
    if (!posts || !Array.isArray(posts) || !posts.length) return;
    const newTs = posts[0]?.created_at;
    if (newTs && newTs !== _lastFeedTs) {
      if (_lastFeedTs) toast('\u2728 New post from the family!');
      _lastFeedTs = newTs;
      _feedOffset=0; _feedDone=false;
      loadFeed();
    }
  }, 15000);

  // Notifications: every 20s always
  let _lastNotifCount = 0;
  _pollIntervals.notif = setInterval(async () => {
    if (!currentUser) return;
    const n = await api('/api/notifications');
    if (!n) return;
    const unread = (n.items||[]).filter(x=>!x.read).length;
    const badge = document.getElementById('notifBadge');
    if (badge) { badge.textContent = unread > 0 ? unread : ''; badge.style.display = unread > 0 ? 'flex' : 'none'; }
    if (unread > _lastNotifCount && _lastNotifCount >= 0) {
      const newest = n.items?.find(x=>!x.read);
      if (newest) toast('\U0001F514 ' + newest.title);
    }
    _lastNotifCount = unread;
  }, 20000);

  // Events: every 30s when events screen active
  _pollIntervals.events = setInterval(async () => {
    const screen = document.getElementById('screenEvents');
    if (!screen || !screen.classList.contains('active')) return;
    const evs = await api('/api/events');
    if (!evs) return;
    const el = document.getElementById('eventsList');
    const newSig = evs.map(e=>e.id+e.going_count).join(',');
    if (el && el.dataset.sig !== newSig) { el.dataset.sig = newSig; loadEvents(); }
  }, 30000);

  // Chat list: every 20s — update badge always, full list only when on chats screen
  _pollIntervals.chatList = setInterval(async () => {
    if (!currentUser) return;
    const chats = await api('/api/chats');
    if (!chats) return;
    // Always update badge
    const _seen = JSON.parse(localStorage.getItem('fh_chat_seen')||'{}');
    const unread = chats.filter(c => c.last_msg_at && c.last_sender && c.last_sender !== currentUser?.name && (!_seen[c.id] || c.last_msg_at > _seen[c.id])).length;
    const _cb = document.getElementById('chatBadge');
    if (_cb) { _cb.textContent = unread > 9 ? '9+' : unread; _cb.style.display = unread > 0 ? 'flex' : 'none'; }
    // Re-render list if on chats screen
    const screen = document.getElementById('screenChats');
    if (screen && screen.classList.contains('active')) loadChats();
  }, 20000);

  // More tab: every 30s when visible
  _pollIntervals.more = setInterval(async () => {
    const screen = document.getElementById('screenMore');
    if (!screen || !screen.classList.contains('active')) return;
    const tab = currentMoreTab;
    if (tab === 'shopping') renderShoppingItems();
    else if (tab === 'chores') renderChores();
    else if (tab === 'expenses') loadExpenses();
    else if (tab === 'photos') loadAlbum();
  }, 30000);

  // Stories: every 30s when feed active
  _pollIntervals.stories = setInterval(async () => {
    const screen = document.getElementById('screenFeed');
    if (!screen || !screen.classList.contains('active')) return;
    loadStories();
  }, 30000);
}

function stopPolling() {
  Object.values(_pollIntervals).forEach(id => clearInterval(id));
  _pollIntervals = {};
}

// Refresh on visibility change (user returns to tab/app)
let _lastHidden = 0;
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    _lastHidden = Date.now();
  } else if (document.visibilityState === 'visible' && currentUser) {
    const away = Date.now() - _lastHidden;
    if (away > 30000) { // away > 30s → refresh active screen
      const active = document.querySelector('.screen.active');
      if (!active) return;
      const id = active.id;
      if (id === 'screenFeed') { _feedOffset=0; _feedDone=false; loadFeed(); loadStories(); }
      else if (id === 'screenChats') loadChats();
      else if (id === 'screenEvents') loadEvents();
      else if (id === 'screenMore') loadMoreTab(currentMoreTab);
    }
  }
});

// Hook: start polling after login
const _origInit = typeof initApp === 'function' ? initApp : null;
// Patch: start polling whenever currentUser is set
const _pollOnLogin = setInterval(() => {
  if (currentUser && !_pollIntervals.notif) {
    startPolling();
    initPullToRefresh();
    clearInterval(_pollOnLogin);
  }
}, 1000);

</script>
</body>
</html>`;
}



// ─── MAIN ROUTER ──────────────────────────────────────────────────────────────
// ─── ALBUM ────────────────────────────────────────────────────────────────────
async function handleAlbum(path, request, env, user) {
  const method = request.method;

  if (path === '/api/album' && method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT ap.*, u.name as uploader_name,
       (SELECT json_group_object(reaction, cnt) FROM
         (SELECT reaction, COUNT(*) as cnt FROM album_reactions WHERE photo_id=ap.id GROUP BY reaction)
       ) as reaction_counts_json
       FROM album_photos ap JOIN users u ON u.id=ap.user_id
       ORDER BY ap.created_at DESC LIMIT 200`
    ).all();
    return json((rows.results||[]).map(r => ({
      ...r, reaction_counts: r.reaction_counts_json ? JSON.parse(r.reaction_counts_json) : {}
    })));
  }

  if (path === '/api/album' && method === 'POST') {
    const {r2_key, caption} = await request.json();
    if (!r2_key) return err('No photo key');
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO album_photos (id,user_id,caption,r2_key) VALUES (?,?,?,?)')
      .bind(id, user.id, caption||null, r2_key).run();
    return json({id, ok:true}, 201);
  }

  const photoDelMatch = path.match(/^\/api\/album\/([^/]+)$/);
  if (photoDelMatch && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM album_photos WHERE id=? AND user_id=?')
      .bind(photoDelMatch[1], user.id).run();
    await env.DB.prepare('DELETE FROM album_reactions WHERE photo_id=?')
      .bind(photoDelMatch[1]).run();
    return json({ok:true});
  }

  const albumReactMatch = path.match(/^\/api\/album\/([^/]+)\/react$/);
  if (albumReactMatch && method === 'POST') {
    const {reaction} = await request.json();
    const photoId = albumReactMatch[1];
    const existing = await env.DB.prepare('SELECT reaction FROM album_reactions WHERE photo_id=? AND user_id=?')
      .bind(photoId, user.id).first();
    if (existing) {
      if (existing.reaction === reaction)
        await env.DB.prepare('DELETE FROM album_reactions WHERE photo_id=? AND user_id=?').bind(photoId, user.id).run();
      else
        await env.DB.prepare('UPDATE album_reactions SET reaction=? WHERE photo_id=? AND user_id=?').bind(reaction, photoId, user.id).run();
    } else {
      await env.DB.prepare('INSERT INTO album_reactions (photo_id,user_id,reaction) VALUES (?,?,?)').bind(photoId, user.id, reaction).run();
    }
    return json({ok:true});
  }

  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight

  // v3 tables
  const v3tables = [
    `CREATE TABLE IF NOT EXISTS families (id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT, logo_key TEXT, invite_code TEXT UNIQUE, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS family_members (family_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT DEFAULT 'member', joined_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (family_id, user_id))`,
    `CREATE TABLE IF NOT EXISTS family_settings (family_id TEXT NOT NULL, feature TEXT NOT NULL, enabled INTEGER DEFAULT 1, PRIMARY KEY (family_id, feature))`,
    `CREATE TABLE IF NOT EXISTS family_rules (id TEXT PRIMARY KEY, family_id TEXT NOT NULL, rule TEXT NOT NULL, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS chores (id TEXT PRIMARY KEY, title TEXT NOT NULL, assigned_to TEXT, points INTEGER DEFAULT 1, frequency TEXT DEFAULT 'daily', created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS chore_completions (id TEXT PRIMARY KEY, chore_id TEXT NOT NULL, user_id TEXT NOT NULL, completed_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS shopping_items (id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT, added_by TEXT, done INTEGER DEFAULT 0, done_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS event_items (id TEXT PRIMARY KEY, event_id TEXT NOT NULL, title TEXT NOT NULL, added_by TEXT, claimed_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS milestones (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, date TEXT, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS recipes (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, ingredients TEXT, steps TEXT, image_key TEXT, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS kindness (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, done INTEGER DEFAULT 0, done_by TEXT, created_by TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS emergency_contacts (id TEXT PRIMARY KEY, user_id TEXT UNIQUE NOT NULL, name TEXT, relationship TEXT, phone TEXT, blood_type TEXT, allergies TEXT, medications TEXT, notes TEXT)`,
    `CREATE TABLE IF NOT EXISTS album_photos (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, caption TEXT, r2_key TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS album_reactions (photo_id TEXT NOT NULL, user_id TEXT NOT NULL, reaction TEXT NOT NULL, PRIMARY KEY (photo_id,user_id))`,
    `CREATE TABLE IF NOT EXISTS meal_rota (id TEXT PRIMARY KEY, week_date TEXT NOT NULL, day_of_week INTEGER NOT NULL, meal TEXT NOT NULL, cook_id TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(week_date, day_of_week))`,
    `ALTER TABLE invites ADD COLUMN user_id TEXT`,
    `ALTER TABLE invites ADD COLUMN email TEXT`,
    `CREATE TABLE IF NOT EXISTS story_views (story_id TEXT NOT NULL, user_id TEXT NOT NULL, viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (story_id, user_id))`,
    `ALTER TABLE chats ADD COLUMN chat_type TEXT NOT NULL DEFAULT 'text'`,
  ];
  for (const sql of v3tables) { try { await env.DB.exec(sql); } catch(e) {} }

    if (method === 'OPTIONS') {
      return new Response(null, {headers:{
        'access-control-allow-origin':'*',
        'access-control-allow-methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS',
        'access-control-allow-headers':'content-type,x-session-token',
        'access-control-max-age':'86400'
      }});
    }

    // Serve SPA
    if (path === '/' || path === '/index.html' || (!path.startsWith('/api/'))) {
      // PWA manifest
      // iOS apple-touch-icon
  if (url.pathname === '/apple-touch-icon.png' || url.pathname === '/apple-touch-icon-precomposed.png') {
    const b64 = 'iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAYAAAA9zQYyAAACx0lEQVR42u3bMWpDQRQEwbmrwff3CWwUKDEIlBjWvTXQB/hvKxPaDt/H59e3zmkGLPAAC3CIBTfIAhtkXQHbIykD28MogdpjKAPbAyiD2uGVQe3gyqB2aGVQO7AyqB1WGdQOqgxqh1QKtSMqA9oBlUHtcEqhdjRlQDuYUqgdSxnQDqUUakdSBrQDKYXacQS0dCJoh1EKtaMIaAlo6Y9BO4hSqB1DQEtAS0BLQAtoCWjpKNAOoRRqRxDQEtAS0BLQAloCWgJaAloCWkBLQOuNHnMHoDOYn3MPoDOYoQY6hxlqoHOYoQY6BRlsoLOYoQY6hxlqoHOYoQY6hxlqoFOQwQY6ixlqoHOYoQY6hxlqoHOYoQY6BRlsoLOYoQY6hxlqoHOYoQY6hxlqoFOQwQY6ixlqoHOYob4cdHlAwww10CCDDTTMUAMNM9RAw3wd6sEMNdAggw00zFADDTPU94I2qAezlVAPZCvBHsxWQj2YrYR6MFsJ9WC2EuqBbCXYg9lKqAezlVAPZiuhHsxWQj2QrQR7MFsJ9WC2EurBbCXUg9lKqAeylWD7C5b5CxbQQAMNNNBAAw000AY00EADDTTQQAMNNNBAAw20AQ000EADDTTQQAMNNNBAA21AA33W4wMNNNBAAw000ED7JqA9vm8CGmiggQYaaKCBBhpo3wS0xwcaaKCBBhpooIEGGmigfRPQHh9ooIEGGmiggQYaaKCB9k1Ae3yggQYaaKCBLoN+DGigM5iBBhpooH0T0B7fNwHt8YEGGmiggQYaaKB905GgS6iBvhP0fq/2i6HuCmgBLf0b0FArhRloAS2dDBpqpTADrRxoqJXCDLRyoKFWCjPQyoGGWinMUCuHGWjlQEOtFGaolcMMtXKYoVYOM9TKYYZaOcxQK4cZauUwg60cZKiVxAy2cpDBVhIy2EpChlu7bR4dYOAF7Iv9AKMcfmOIha4cAAAAAElFTkSuQmCC';
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i=0; i<binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new Response(bytes, {headers:{'content-type':'image/png','cache-control':'public,max-age=604800'}});
  }

  if (url.pathname === '/manifest.json') {
        const manifest = {
          name: 'Family Hub',
          short_name: 'Family Hub',
          description: 'Your private family app',
          start_url: '/',
          display: 'standalone',
          orientation: 'portrait',
          background_color: '#0f172a',
          theme_color: '#6366f1',
          icons: [
            {src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable'},
            {src: '/icon.svg', sizes: '192x192', type: 'image/svg+xml'},
            {src: '/icon.svg', sizes: '512x512', type: 'image/svg+xml'}
          ]
        };
        return new Response(JSON.stringify(manifest), {
          headers: {'content-type': 'application/manifest+json', 'cache-control': 'public,max-age=86400'}
        });
      }
      // PWA icon
      if (url.pathname === '/icon.svg') {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="114" fill="#6366f1"/>
  <text x="256" y="340" font-size="260" text-anchor="middle" font-family="-apple-system,sans-serif">🏠</text>
</svg>`;
        return new Response(svg, {
          headers: {'content-type': 'image/svg+xml', 'cache-control': 'public,max-age=86400'}
        });
      }
            return new Response(getSPA(), {headers:{'content-type':'text/html;charset=utf-8','x-robots-tag':'noindex'}});
    }

    // Auth routes (no session needed)
    const authRoutes = ['/api/auth/invite','/api/auth/register','/api/auth/login'];
    if (authRoutes.includes(path)) {
      const r = await handleAuth(path, request, env);
      if (r) return r;
    }

    // Photo proxy (requires session)
    if (path.startsWith('/api/photos/')) {
      const user = await getSession(request, env);
      if (!user) return err('Unauth', 401);
      const r = await handlePhotos(path, request, env, user);
      if (r) return r;
    }

    // All other API routes need auth
    const user = await getSession(request, env);
    if (!user) return err('Unauthorized', 401);

    // Auth profile routes
    const r0 = await handleAuth(path, request, env);
    if (r0) return r0;

    // Posts
    if (path.startsWith('/api/posts')) {
      const r = await handlePosts(path, request, env, user);
      if (r) return r;
    }

    // Users list
    if (path === '/api/users') {
      const r = await handleChats(path, request, env, user);
      if (r) return r;
    }

    // Chats
    if (path.startsWith('/api/chats')) {
      const r = await handleChats(path, request, env, user);
      if (r) return r;
    }

    // Stories
    if (path.startsWith('/api/stories')) {
      const r = await handleStories(path, request, env, user);
      if (r) return r;
    }

    // Events
    if (path.startsWith('/api/events')) {
      const r = await handleEvents(path, request, env, user);
      if (r) return r;
    }

    // Transfers
    if (path.startsWith('/api/transfers')) {
      const r = await handleTransfers(path, request, env, user);
      if (r) return r;
    }

    // Notifications
    if (path.startsWith('/api/notification-prefs')) {
      const r = await handleNotifPrefs(path, request, env, user);
      if (r) return r;
    }

    if (path.startsWith('/api/notifications')) {
      const r = await handleNotifications(path, request, env, user);
      if (r) return r;
    }

    // Documents
    if (path.startsWith('/api/documents')) {
      const r = await handleDocuments(path, request, env, user);
      if (r) return r;
    }

    // Birthdays
    if (path.startsWith('/api/birthdays')) {
      const r = await handleBirthdays(path, request, env, user);
      if (r) return r;
    }

    // Gifts
    if (path.startsWith('/api/gifts')) {
      const r = await handleGifts(path, request, env, user);
      if (r) return r;
    }

    // KK Draw
    if (path.startsWith('/api/kk')) {
      const r = await handleKK(path, request, env, user);
      if (r) return r;
    }

    // Expenses
    if (path.startsWith('/api/expenses')) {
      const r = await handleExpenses(path, request, env, user);
      if (r) return r;
    }


    // ── FAMILIES ──────────────────────────────────────────────────────────────
    if (path === '/api/families' && method === 'GET') {
      const rows = await env.DB.prepare(
        'SELECT f.*, fm.role FROM families f JOIN family_members fm ON fm.family_id=f.id WHERE fm.user_id=?'
      ).bind(user.id).all();
      if (!rows.results.length) return json([]);
      return json(rows.results);
    }
    if (path === '/api/families' && method === 'POST') {
      const {name} = await request.json();
      const id = crypto.randomUUID();
      const invite_code = Math.random().toString(36).slice(2,8).toUpperCase();
      await env.DB.prepare('INSERT INTO families (id,name,invite_code,created_by) VALUES (?,?,?,?)').bind(id,name||'My Family',invite_code,user.id).run();
      await env.DB.prepare('INSERT INTO family_members (family_id,user_id,role) VALUES (?,?,?)').bind(id,user.id,'admin').run();
      const fam = await env.DB.prepare('SELECT * FROM families WHERE id=?').bind(id).first();
      return json(fam, 201);
    }
    if (path === '/api/families/join' && method === 'POST') {
      const {code} = await request.json();
      const fam = await env.DB.prepare('SELECT * FROM families WHERE invite_code=?').bind((code||'').toUpperCase()).first();
      if (!fam) return err('Invalid invite code', 404);
      await env.DB.prepare('INSERT OR IGNORE INTO family_members (family_id,user_id,role) VALUES (?,?,?)').bind(fam.id,user.id,'member').run();
      return json(fam);
    }
    const famMatch = path.match(/^\/api\/families\/([^/]+)$/);
    if (famMatch && method === 'PATCH') {
      const fid = famMatch[1];
      const {name, description} = await request.json();
      await env.DB.prepare('UPDATE families SET name=COALESCE(?,name), description=COALESCE(?,description) WHERE id=?').bind(name||null,description||null,fid).run();
      return json({ok:true});
    }
    const famLogoMatch = path.match(/^\/api\/families\/([^/]+)\/logo$/);
    if (famLogoMatch && method === 'POST') {
      const fid = famLogoMatch[1];
      const fd = await request.formData();
      const file = fd.get('file');
      if (!file) return err('No file');
      const key = 'family-logos/' + fid;
      await env.PHOTOS.put(key, file.stream(), {httpMetadata:{contentType:file.type}});
      await env.DB.prepare('UPDATE families SET logo_key=? WHERE id=?').bind(key,fid).run();
      return json({ok:true,key});
    }
    const famMembersMatch = path.match(/^\/api\/families\/([^/]+)\/members$/);
    if (famMembersMatch && method === 'GET') {
      const fid = famMembersMatch[1];
      const rows = await env.DB.prepare(
        'SELECT u.id,u.name,u.avatar_color,u.avatar_url,fm.role,(CASE WHEN u.password_hash IS NOT NULL THEN 1 ELSE 0 END) as registered FROM users u JOIN family_members fm ON fm.user_id=u.id WHERE fm.family_id=? ORDER BY registered DESC,u.name'
      ).bind(fid).all();
      return json(rows.results);
    }
    const famSettingsMatch = path.match(/^\/api\/families\/([^/]+)\/settings$/);
    if (famSettingsMatch && method === 'GET') {
      const fid = famSettingsMatch[1];
      const rows = await env.DB.prepare('SELECT feature,enabled FROM family_settings WHERE family_id=?').bind(fid).all();
      const out = {};
      rows.results.forEach(r => out[r.feature] = r.enabled);
      return json(out);
    }
    if (famSettingsMatch && (method === 'PATCH' || method === 'POST')) {
      const fid = famSettingsMatch[1];
      const {feature, enabled} = await request.json();
      await env.DB.prepare('INSERT OR REPLACE INTO family_settings (family_id,feature,enabled) VALUES (?,?,?)').bind(fid,feature,enabled?1:0).run();
      return json({ok:true});
    }
    const famRulesMatch = path.match(/^\/api\/families\/([^/]+)\/rules$/);
    if (famRulesMatch && method === 'GET') {
      const fid = famRulesMatch[1];
      const rows = await env.DB.prepare('SELECT * FROM family_rules WHERE family_id=? ORDER BY created_at').bind(fid).all();
      return json(rows.results);
    }
    if (famRulesMatch && method === 'POST') {
      const fid = famRulesMatch[1];
      const {rule} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO family_rules (id,family_id,rule,created_by) VALUES (?,?,?,?)').bind(id,fid,rule,user.id).run();
      return json({id,ok:true},201);
    }
    const famRuleDelMatch = path.match(/^\/api\/families\/([^/]+)\/rules\/([^/]+)$/);
    if (famRuleDelMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM family_rules WHERE id=? AND family_id=?').bind(famRuleDelMatch[2],famRuleDelMatch[1]).run();
      return json({ok:true});
    }

    // ── CHAT RENAME ────────────────────────────────────────────────────────────
    const chatPatchMatch = path.match(/^\/api\/chats\/([^/]+)$/);
    if (chatPatchMatch && method === 'PATCH') {
      const {name} = await request.json();
      await env.DB.prepare('UPDATE chats SET name=? WHERE id=?').bind(name||null, chatPatchMatch[1]).run();
      return json({ok:true});
    }

    // ── AVATAR ────────────────────────────────────────────────────────────────
    if (path === '/api/avatar' && method === 'POST') {
      const fd = await request.formData();
      const file = fd.get('file');
      if (!file) return err('No file');
      const key = 'avatars/' + user.id;
      await env.PHOTOS.put(key, file.stream(), {httpMetadata:{contentType:file.type}});
      const url = '/api/photos/' + key;
      await env.DB.prepare('UPDATE users SET avatar_url=? WHERE id=?').bind(url, user.id).run();
      return json({ok:true, avatar_url:url});
    }

    // ── SHOPPING ──────────────────────────────────────────────────────────────
    if (path === '/api/shopping' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT s.*,u.name as added_by_name FROM shopping_items s LEFT JOIN users u ON u.id=s.added_by ORDER BY s.done ASC, s.created_at DESC').all();
      return json(rows.results);
    }
    if (path === '/api/shopping' && method === 'POST') {
      const {title,category} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO shopping_items (id,title,category,added_by) VALUES (?,?,?,?)').bind(id,title,category||null,user.id).run();
      return json({id,ok:true},201);
    }
    const shopItemMatch = path.match(/^\/api\/shopping\/([^/]+)$/);
    if (shopItemMatch && method === 'PATCH') {
      const {done} = await request.json();
      await env.DB.prepare('UPDATE shopping_items SET done=?,done_by=? WHERE id=?').bind(done?1:0,done?user.id:null,shopItemMatch[1]).run();
      return json({ok:true});
    }
    if (shopItemMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM shopping_items WHERE id=?').bind(shopItemMatch[1]).run();
      return json({ok:true});
    }

    // ── CHORES ────────────────────────────────────────────────────────────────
    if (path === '/api/chores' && method === 'GET') {
      const rows = await env.DB.prepare(`
        SELECT c.*, (SELECT COUNT(*) FROM chore_completions cc WHERE cc.chore_id=c.id AND date(cc.completed_at)=date('now')) as done_today
        FROM chores c ORDER BY c.created_at DESC`).all();
      return json(rows.results);
    }
    if (path === '/api/chores' && method === 'POST') {
      const {title,assigned_to,points,frequency} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO chores (id,title,assigned_to,points,frequency,created_by) VALUES (?,?,?,?,?,?)').bind(id,title,assigned_to||null,points||1,frequency||'daily',user.id).run();
      return json({id,ok:true},201);
    }
    const choreMatch = path.match(/^\/api\/chores\/([^/]+)$/);
    if (choreMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM chores WHERE id=?').bind(choreMatch[1]).run();
      return json({ok:true});
    }
    const choreDelMatch = path.match(/^\/api\/chores\/([^/]+)$/);
    if (choreDelMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM chores WHERE id=?').bind(choreDelMatch[1]).run();
      return json({ok:true});
    }
    const choreCompleteMatch = path.match(/^\/api\/chores\/([^/]+)\/complete$/);
    if (choreCompleteMatch && method === 'POST') {
      await env.DB.prepare('INSERT INTO chore_completions (id,chore_id,user_id) VALUES (?,?,?)').bind(crypto.randomUUID(),choreCompleteMatch[1],user.id).run();
      return json({ok:true});
    }

    // ── PARTY PLANNER (EVENT ITEMS) ────────────────────────────────────────────
    const eventItemsMatch = path.match(/^\/api\/events\/([^/]+)\/items$/);
    if (eventItemsMatch && method === 'GET') {
      const eid = eventItemsMatch[1];
      const rows = await env.DB.prepare('SELECT ei.*,u.name as claimer_name FROM event_items ei LEFT JOIN users u ON u.id=ei.claimed_by WHERE ei.event_id=? ORDER BY ei.created_at').bind(eid).all();
      return json(rows.results);
    }
    if (eventItemsMatch && method === 'POST') {
      const eid = eventItemsMatch[1];
      const {title} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO event_items (id,event_id,title,added_by) VALUES (?,?,?,?)').bind(id,eid,title,user.id).run();
      return json({id,ok:true},201);
    }
    const eventItemClaimMatch = path.match(/^\/api\/events\/([^/]+)\/items\/([^/]+)\/claim$/);
    if (eventItemClaimMatch && method === 'POST') {
      const item = await env.DB.prepare('SELECT * FROM event_items WHERE id=?').bind(eventItemClaimMatch[2]).first();
      if (!item) return err('Not found',404);
      const newClaimed = item.claimed_by === user.id ? null : user.id;
      await env.DB.prepare('UPDATE event_items SET claimed_by=? WHERE id=?').bind(newClaimed,item.id).run();
      return json({ok:true,claimed_by:newClaimed});
    }
    const eventItemDelMatch = path.match(/^\/api\/events\/([^/]+)\/items\/([^/]+)$/);
    if (eventItemDelMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM event_items WHERE id=?').bind(eventItemDelMatch[2]).run();
      return json({ok:true});
    }

    // ── MILESTONES ────────────────────────────────────────────────────────────
    if (path === '/api/milestones' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT m.*,u.name as creator_name FROM milestones m LEFT JOIN users u ON u.id=m.created_by ORDER BY m.date DESC, m.created_at DESC').all();
      return json(rows.results);
    }
    if (path === '/api/milestones' && method === 'POST') {
      const {title,description,date} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO milestones (id,title,description,date,created_by) VALUES (?,?,?,?,?)').bind(id,title,description||null,date||null,user.id).run();
      return json({id,ok:true},201);
    }
    const milestoneDelMatch = path.match(/^\/api\/milestones\/([^/]+)$/);
    if (milestoneDelMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM milestones WHERE id=?').bind(milestoneDelMatch[1]).run();
      return json({ok:true});
    }

    // ── RECIPES ───────────────────────────────────────────────────────────────
    if (path === '/api/recipes' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT r.*,u.name as creator_name FROM recipes r LEFT JOIN users u ON u.id=r.created_by ORDER BY r.created_at DESC').all();
      return json(rows.results);
    }
    if (path === '/api/recipes' && method === 'POST') {
      const {title,description,ingredients,steps} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO recipes (id,title,description,ingredients,steps,created_by) VALUES (?,?,?,?,?,?)').bind(id,title,description||null,ingredients||null,steps||null,user.id).run();
      return json({id,ok:true},201);
    }
    const recipeMatch = path.match(/^\/api\/recipes\/([^/]+)$/);
    if (recipeMatch && method === 'GET') {
      const r = await env.DB.prepare('SELECT * FROM recipes WHERE id=?').bind(recipeMatch[1]).first();
      if (!r) return err('Not found',404);
      return json(r);
    }
    if (recipeMatch && method === 'DELETE') {
      await env.DB.prepare('DELETE FROM recipes WHERE id=?').bind(recipeMatch[1]).run();
      return json({ok:true});
    }

    // ── KINDNESS ──────────────────────────────────────────────────────────────
    if (path === '/api/kindness' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT k.*,u.name as done_by_name FROM kindness k LEFT JOIN users u ON u.id=k.done_by ORDER BY k.done ASC, k.created_at DESC').all();
      return json(rows.results);
    }
    if (path === '/api/kindness' && method === 'POST') {
      const {title,description} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO kindness (id,title,description,created_by) VALUES (?,?,?,?)').bind(id,title,description||null,user.id).run();
      return json({id,ok:true},201);
    }
    const kindnessMatch = path.match(/^\/api\/kindness\/([^/]+)\/done$/);
    if (kindnessMatch && method === 'PATCH') {
      await env.DB.prepare('UPDATE kindness SET done=1,done_by=? WHERE id=?').bind(user.id,kindnessMatch[1]).run();
      return json({ok:true});
    }

    // ── EMERGENCY CONTACTS ────────────────────────────────────────────────────
    // Photo Album
    if (path.startsWith('/api/album')) {
      const r = await handleAlbum(path, request, env, user);
      if (r) return r;
    }

    if (path === '/api/emergency' && method === 'GET') {
      const r = await env.DB.prepare('SELECT * FROM emergency_contacts WHERE user_id=?').bind(user.id).first();
      return json(r||null);
    }
    if (path === '/api/emergency' && method === 'POST') {
      const {name,relationship,phone,blood_type,allergies,medications,notes} = await request.json();
      const id = crypto.randomUUID();
      await env.DB.prepare(`INSERT OR REPLACE INTO emergency_contacts (id,user_id,name,relationship,phone,blood_type,allergies,medications,notes)
        VALUES (COALESCE((SELECT id FROM emergency_contacts WHERE user_id=?),?),?,?,?,?,?,?,?,?)`)
        .bind(user.id,id,user.id,name||null,relationship||null,phone||null,blood_type||null,allergies||null,medications||null,notes||null).run();
      return json({ok:true});
    }

    // ── MEAL ROTA ─────────────────────────────────────────────────────────────
    // ── ADMIN: invites
    if (path === '/api/admin/invites' && method === 'GET') {
      if (!user || user.role !== 'admin') return err('Forbidden', 403);
      const rows = await env.DB.prepare('SELECT id,name,role,token,email FROM invites WHERE used=0 ORDER BY id').all();
      return json(rows.results);
    }
    if (path === '/api/admin/invites' && method === 'POST') {
      if (!user || user.role !== 'admin') return err('Forbidden', 403);
      const {name, email, role} = await request.json();
      if (!name) return err('Name required');
      const token = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b=>b.toString(16).padStart(2,'0')).join('');
      const invId = await env.DB.prepare('INSERT INTO invites (name,role,token,email) VALUES (?,?,?,?) RETURNING id').bind(name, role||'member', token, email||null).first();
      // Send email if provided
      if (email && env.RESEND_API_KEY) {
        const link = `https://hub.luckdragon.io/?invite=${token}`;
        await fetch('https://api.resend.com/emails', {
          method:'POST', headers:{'Authorization':`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},
          body:JSON.stringify({from:'Family Hub <paddy@luckdragon.io>',to:[email],subject:`${user.name} invited you to Family Hub 🏠`,html:`<p>Hi ${name}! ${user.name} has invited you to join the Gallivan Family Hub.</p><p><a href="${link}" style="background:#6366f1;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block">Join Family Hub →</a></p><p>Or copy this link: ${link}</p>`})
        });
      }
      return json({ok:true, id:invId?.id, token});
    }
    if (/^\/api\/admin\/invites\/\d+\/email$/.test(path) && method === 'POST') {
      if (!user || user.role !== 'admin') return err('Forbidden', 403);
      const inviteId = parseInt(path.split('/')[4]);
      const {email} = await request.json();
      if (!email) return err('Email required');
      const invite = await env.DB.prepare('SELECT * FROM invites WHERE id=?').bind(inviteId).first();
      if (!invite) return err('Invite not found', 404);
      // Store email on invite
      await env.DB.prepare('UPDATE invites SET email=? WHERE id=?').bind(email, inviteId).run();
      // Send via Resend
      if (!env.RESEND_API_KEY) return err('Email not configured');
      const link = `https://hub.luckdragon.io/?invite=${invite.token}`;
      const resp = await fetch('https://api.resend.com/emails', {
        method:'POST', headers:{'Authorization':`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},
        body:JSON.stringify({from:'Family Hub <paddy@luckdragon.io>',to:[email],subject:`${user.name} invited you to Family Hub 🏠`,html:`<p>Hi ${invite.name}! ${user.name} has invited you to join the Gallivan Family Hub.</p><p><a href="${link}" style="background:#6366f1;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block">Join Family Hub →</a></p><p>Or copy this link: ${link}</p><p style="color:#888;font-size:12px">Reply to this email if you have questions.</p>`})
      });
      const resendData = await resp.json();
      if (resp.ok) return json({ok:true});
      return err('Email send failed: ' + JSON.stringify(resendData), 500);
    }
    if (path === '/api/meals' && method === 'GET') {
      // Get monday of target week (offset in weeks)
      const offsetParam = parseInt(url.searchParams.get('offset')||'0');
      const now = new Date();
      const day = now.getDay();
      const monday = new Date(now);
      monday.setDate(now.getDate() - (day===0?6:day-1) + (offsetParam*7));
      const weekDate = monday.toISOString().slice(0,10);
      const rows = await env.DB.prepare('SELECT mr.*,u.name as cook_name FROM meal_rota mr LEFT JOIN users u ON u.id=mr.cook_id WHERE mr.week_date=? ORDER BY mr.day_of_week').bind(weekDate).all();
      return json({week_date:weekDate, meals:rows.results});
    }
    if (path === '/api/meals' && method === 'POST') {
      const {day_of_week,meal,cook_id,week_offset} = await request.json();
      const now = new Date();
      const day = now.getDay();
      const monday = new Date(now);
      monday.setDate(now.getDate() - (day===0?6:day-1) + ((week_offset||0)*7));
      const weekDate = monday.toISOString().slice(0,10);
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT OR REPLACE INTO meal_rota (id,week_date,day_of_week,meal,cook_id) VALUES (COALESCE((SELECT id FROM meal_rota WHERE week_date=? AND day_of_week=?),?),?,?,?,?)').bind(weekDate,day_of_week,id,weekDate,day_of_week,meal,cook_id||null).run();
      return json({ok:true});
    }

    return err('Not found', 404);
  }
};
