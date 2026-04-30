# Family Hub — RESUME-HERE

## What it is
Private family social network — WhatsApp/Instagram replacement for the family.
Built 2026-05-01. Live at https://family-hub.pgallivan.workers.dev

## Status
- **Live**: Yes
- **Progress**: 35% (v1 deployed, family seeded, ready to test)
- **Next**: Get family signed up, add custom domain, photo uploads via R2

## Architecture
- Single CF Worker: `family-hub` on Cloudflare (serves SPA + REST API)
- D1: `family-hub` (UUID: `abcbe15d-9a98-4e01-82eb-c82a0acd1443`)
- R2: `family-hub-photos`
- Repo: https://github.com/PaddyGallivan/family-hub
- Asgard D1 row: id 53 in asgard-brain.products

## Family test group (14 members)
Mona, Jacky, Kelly, Mary, Monica, John, Aeneas, Joe, Marie, Michelle, Ryan, Mery, Tess, Georgia
Invite links in: `H:\My Drive\Luck Dragon 2.0\Family Hub - Invite Links.md`

## Features shipped in v1
- Family feed (posts, likes, comments)
- Group + 1:1 chats (The Family group pre-created)
- Birthdays tracker + wish lists with gift claiming
- Christmas KK draw (Secret Santa)
- Shared expense tracker (presents, insurance, holidays)
- Invite-code auth + session management

## Next session priorities
1. Custom domain (familyhub.luckdragon.io or similar)
2. R2 photo uploads (base64 → R2 presigned URL)
3. Real-time chat (polling or Durable Objects)
4. Push notifications (Web Push)
5. Profile editing UI
6. Birthday reminders via email (Resend)

