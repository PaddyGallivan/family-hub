# Family Hub — RESUME-HERE
Last updated: 2026-05-01

## Status: v2 LIVE ✅ — registration working, awaiting family onboarding

**Live URL:** https://family-hub.pgallivan.workers.dev  
**Repo:** https://github.com/PaddyGallivan/family-hub  
**Asgard row:** id 53, progress 85%

---

## What's built & deployed (v2)

| Feature | Status |
|---------|--------|
| Auth — invite token → register → session | ✅ |
| Feed — posts, photo uploads, reactions, comments | ✅ |
| Stories — 24h expiry, text + image, story strip | ✅ |
| Chats — encrypted (AES-256-GCM), group + 1:1, file sends, reactions, poll | ✅ |
| Events / Calendar — create, RSVP (going/maybe/no) | ✅ |
| Birthdays — add, view upcoming | ✅ |
| Gifts / Wish Lists — add, claim, unclaim | ✅ |
| KK Draw — join, do the draw, see assignment | ✅ |
| Expenses — add, split, settle | ✅ |
| Transfers — request money, confirm/reject | ✅ |
| Document Vault — encrypted upload/download, shared flag | ✅ |
| Notifications — feed, badge, mark-all-read | ✅ |
| Photo proxy — R2-backed, served via worker | ✅ |

---

## Infrastructure

- **Worker:** `family-hub` on Cloudflare (account: Luck Dragon Main, `a6f47c17811ee2f8b6caeb8f38768c20`)
- **D1:** `family-hub` — UUID `abcbe15d-9a98-4e01-82eb-c82a0acd1443`
- **R2:** `family-hub-photos` (photos + encrypted docs)
- **Secrets on worker:** `ENCRYPTION_KEY`, `APP_SECRET`
- **Worker size:** ~117 KB, single-file SPA

## Schema notes (post-migration 2026-05-01)
All user_id columns are now TEXT (UUID-compatible). Tables recreated cleanly:
- `users.id TEXT PRIMARY KEY` (was INTEGER — fixed)
- `sessions.token TEXT PRIMARY KEY` (was `id` — renamed)
- All dependent tables (messages, posts, events, etc.) use `TEXT` user_id

## Deploy command (Python urllib multipart)
```python
metadata = {
  "main_module": "worker.js",
  "bindings": [
    {"type":"d1","name":"DB","id":"abcbe15d-9a98-4e01-82eb-c82a0acd1443"},
    {"type":"r2_bucket","name":"PHOTOS","bucket_name":"family-hub-photos"}
  ],
  "keep_bindings": ["secret_text","plain_text","kv_namespace","d1","service","r2_bucket"],
  "compatibility_date": "2024-01-01"
}
# PUT https://api.cloudflare.com/client/v4/accounts/a6f47c17811ee2f8b6caeb8f38768c20/workers/scripts/family-hub
# Auth: Bearer [stored in asgard-vault: CF_API_TOKEN_FULLOPS — PIN from Mona]
```

---

## Family members + invite links

All 14 members seeded. Invite links are in:  
`H:\My Drive\Luck Dragon 2.0\Family Hub - Invite Links.md`

| Name | Role | Token |
|------|------|-------|
| Mona | you | f1c4b46491466b382f5e5a6411289188 (USED — registered) |
| Jacky | Partner | 55d8228c1863df7e557316e1b73da21c |
| Kelly | Sister | a9f4ecb68b4b1e45ee7f3c77685b7c51 |
| Mary | Sister | 5d23619f644ef821dd0ea4bf562b6102 |
| Monica | Sister | 56a493acc0943272ab91846e1d8ccb6a |
| John | Brother | 767d0f33a29c26a5ad1c97cdc831c597 |
| Aeneas | Brother | 66fd28150c6faa84401c49e8e60c7ffc |
| Joe | Dad | c6dde09463470dee6ed5c8704425b9be |
| Marie | Mum | 1ad07680cdfd23120ffd5ba36fe18f7c |
| Michelle | Kelly's partner | 182b488a26d1cc0564b6f2d0c0e6f152 |
| Ryan | Mary's partner | 01b1c085450115d0012895d8a1740b16 |
| Mery | Monica's partner | 1a654d8d867bef12654faaf17c952eed |
| Tess | John's partner | 22f5032050b02b6bb6a36997600b43b2 |
| Georgia | Aeneas's partner | 0797e014698a242686c1e2ef2d3e0c4c |

---

## Next actions

1. **Send invite links to family** — WhatsApp each person their link from the invite doc
2. **After everyone registers:** run the group chat SQL fix:
   ```sql
   INSERT OR IGNORE INTO chat_members (chat_id,user_id) 
   SELECT 1, id FROM users WHERE password_hash IS NOT NULL AND id NOT IN 
   (SELECT user_id FROM chat_members WHERE chat_id=1)
   ```
3. **Nice-to-haves (not built yet):**
   - Push notifications (Web Push API)
   - Avatar photo upload
   - Pin important messages
   - Video calls (would need third-party)

---

## Verified working (2026-05-01)
- ✅ Registration via invi