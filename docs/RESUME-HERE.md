# Family Hub — RESUME-HERE
Last updated: 2026-05-02

## Status: v3 LIVE ✅ — 39/39 tests passing — awaiting family onboarding

**Live URL:** https://hub.luckdragon.io  
**Alt URL:** https://family-hub.pgallivan.workers.dev  
**Repo:** https://github.com/PaddyGallivan/family-hub  
**Asgard row:** id 53, progress 92%

---

## What's built & deployed (v3)

### v2 features (all working)
| Feature | Status |
|---------|--------|
| Auth — invite token → register → session | ✅ |
| Feed — posts, photo uploads, reactions, comments | ✅ |
| Stories — 24h expiry, text + image, story strip | ✅ |
| Chats — encrypted (AES-256-GCM), group + 1:1, file sends, reactions | ✅ |
| Events / Calendar — create, RSVP (going/maybe/no) | ✅ |
| Birthdays — add, view upcoming | ✅ |
| Gifts / Wish Lists — add, claim, unclaim | ✅ |
| KK Draw — join, do the draw, see assignment | ✅ |
| Expenses — add, split, settle | ✅ |
| Transfers — request money, confirm/reject | ✅ |
| Document Vault — encrypted upload/download, shared flag | ✅ |
| Notifications — feed, badge, mark-all-read | ✅ |
| Photo proxy — R2-backed, served via worker | ✅ |

### v3 features (new — 2026-05-02)
| Feature | Status |
|---------|--------|
| 🛒 Shopping list — shared, tick-off, categories | ✅ |
| ✅ Chore chart — assign, points, frequency, mark done | ✅ |
| 🍽️ Meal rota — weekly dinner planner, assign cook | ✅ |
| 🏆 Milestones — family timeline with dates | ✅ |
| 📖 Recipe book — ingredients + steps, expandable cards | ✅ |
| 💛 Kindness board — random acts, mark done | ✅ |
| 🏠 Multi-family — create family, join by invite code, switch | ✅ |
| ⚡ Feature toggles — admin can turn any section on/off | ✅ |
| 📋 Family rules — pinned guidelines per family | ✅ |
| 🚨 Emergency contacts — blood type, allergies, medications | ✅ |
| 🎉 Party planner — who's bringing what per event | ✅ |
| ✏️ Chat rename — tap name to rename | ✅ |
| 📷 Avatar upload — personal profile photo | ✅ |

---

## Infrastructure

- **Worker:** `family-hub` on Cloudflare (account: Luck Dragon Main, `a6f47c17811ee2f8b6caeb8f38768c20`)
- **D1:** `family-hub` — UUID `abcbe15d-9a98-4e01-82eb-c82a0acd1443`
- **R2:** `family-hub-photos` (photos + encrypted docs + family logos + avatars)
- **Secrets on worker:** `ENCRYPTION_KEY`, `APP_SECRET`
- **Worker size:** ~145 KB, single-file SPA

## Deploy command
```python
# POST https://asgard-tools.pgallivan.workers.dev/admin/deploy
# X-Pin: [PIN from Mona]
# Body: {"worker_name":"family-hub","code_b64":"<base64>","main_module":"worker.js"}
# User-Agent header required (CF bot protection)
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

## Your login
- **URL:** https://hub.luckdragon.io
- **Name:** Paddy  **Password:** family123
- *(change it in Profile if you like)*

## Ho Family
- **Admin:** Susie Ho (susie.ho@monash.edu)
- **Susie's invite:** https://hub.luckdragon.io/register?token=d14765
