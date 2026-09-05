---
name: skool
description: >
  Read and update Skool classroom courses and lessons via the unofficial
  api2.skool.com API and classroom page data. Use when listing courses,
  reading or editing lesson bodies, attaching images to lessons, or checking
  whether Skool session cookies are configured (env paste, optional same-machine
  Chrome, or cookie file). Writes default to dry_run.
---

# Skool classroom (unofficial)

Use this plugin’s MCP tools for Skool **classroom** courses and lessons. This is an **unofficial** client of `https://api2.skool.com` plus, when needed, `__NEXT_DATA__` on `https://www.skool.com/{slug}/classroom`. Skool can change either without notice. There is no OAuth.

## When to use

- List courses for a community slug (`skool_courses`)
- Get a course summary (`skool_course_get`)
- List lessons in a course (`skool_lessons`)
- Read a lesson body (`skool_lesson_get`) — markdown or raw `[v2]` TipTap
- Propose or apply a lesson body (`skool_lesson_set`)
- Append an uploaded image to a lesson (`skool_lesson_attach_image`)
- Check session source / expiry (`skool_auth_status`) — booleans and timestamps only

## Auth

Call `skool_auth_status` first. It reports `source`: `env` | `chrome` | `cookie_file` | `missing`, which of the three cookies are present (booleans), and expiry if known. **Never print or invent cookie values.**

Resolution: all three env vars → else `SKOOL_COOKIE_FILE` → else Chrome DB if `SKOOL_AUTH_MODE=chrome` / `SKOOL_USE_CHROME=1`.

**Portable (default, share-safe):** the **user** copies `auth_token`, `client_id`, `aws-waf-token` from DevTools → Application → Cookies and pastes them under **Plugins → Configure**. Session expired → they paste again. Recipients on another machine always use this.

**Same-machine Chrome (optional):** only when the MCP host is the same OS user as a signed-in Chrome profile. Linux v10 decrypt only; macOS Keychain / Windows DPAPI are unsupported — tell the user to paste or set `SKOOL_COOKIE_FILE`. Do not crawl the filesystem for cookie DBs. This is not a way to share credentials.

If tools fail with 401/403 or WAF errors, the **user** refreshes cookies (paste, or refresh Chrome session then re-run with chrome mode). Empty bookmarklet values mean HttpOnly — they must copy from the Application panel.

## Never invent lesson text

`skool_lesson_get` returns stored `metadata.desc` only. If a lesson is empty, say so. Do not fabricate classroom copy, then PUT it.

## Writes are dry-run by default

`skool_lesson_set` and `skool_lesson_attach_image` **must** keep `dry_run=true` unless the user explicitly asks to apply. Only call with `dry_run=false` after showing the preview and getting confirmation.

## Read-then-write rules (easy to get wrong)

Lesson/module `desc` is a string: literal `[v2]` plus a TipTap **JSON array** (not a `{type: doc}` wrapper unless you unwrap `content`).

1. **Never PUT the course root to edit a lesson.** Course and module share `/courses/{hex}` but they are different unit types. Editing a lesson is `GET` the **module** id, then `PUT` that module. Putting the parent course can reset **privacy** (including making a paid course Open) or flip **Draft → Active** if `state` is omitted.
2. **Module PUT body is `{title, desc}` only.** Extra keys → HTTP 400. Always echo the current **title** on set; omitting title blanks it.
3. **If you ever PUT a course root**, the body **must** preserve `state` and `privacy` (and typically `min_tier`). This plugin does not expose a course-write tool; do not improvise one.
4. **Images:** `POST /files` then presigned PUT, then append an image node to the module TipTap array and PUT `{title, desc}` on the module. Do not PUT the course for an inline lesson image.

## Data shapes

- Course: `id` (hex), `name` (numeric web id), `title`, `state` (`1` Draft, `2` Active), `privacy`, optional `min_tier`, `children[]`
- Lesson/module: `id` (hex), `name`, `title`, `unit_type` (`module` page, `set` folder), `parent_id?`, `desc?`
