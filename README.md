# Skool classroom plugin

Smallest-viable **Agent Plugin** for Skool classroom courses and lessons. It talks to the unofficial `https://api2.skool.com` API and, when a courses list is not available there, reads `__NEXT_DATA__` from `https://www.skool.com/{slug}/classroom`.

This is **not** an official Skool API. Endpoints and page shapes can change. Do not publish this package to a marketplace or cursor.directory from this repo.

Recipients supply **their own** session cookies. Nothing in this tree is a credential. There is **no OAuth**.

## What you get

MCP tools (stdio, Python 3 stdlib only — no `requirements.txt`):

| Tool | Role |
| --- | --- |
| `skool_auth_status` | Auth **source** (`env` / `chrome` / `cookie_file` / `missing`); which cookies are present (booleans); expiry if known — never token values |
| `skool_courses` | List courses for a community slug |
| `skool_course_get` | One course summary (`id`, numeric `name`, `title`, `state`, `privacy`, `min_tier`, `children`) |
| `skool_lessons` | List lessons/modules for a course (optional id/name/title substring) |
| `skool_lesson_get` | Lesson body as markdown-ish text or raw `[v2]` TipTap |
| `skool_lesson_set` | Set body from markdown or `[v2]` text — **dry-run by default** |
| `skool_lesson_attach_image` | Upload via `POST /files` + presigned PUT, append image — **dry-run by default** |

Writes never run unless you pass `dry_run=false`.

## Auth

Secrets live only as plugin variables (or a local file you point at). Never commit cookie values.

Resolution order: **all three env cookies** → else **`SKOOL_COOKIE_FILE`** → else **Chrome DB** if `SKOOL_AUTH_MODE=chrome` (or `SKOOL_USE_CHROME=1`) → else missing.

### A. Portable (default, share-safe)

1. Sign in at [skool.com](https://www.skool.com).
2. DevTools → **Application** → **Cookies** → `https://www.skool.com`.
3. Copy the values of `auth_token`, `client_id`, and `aws-waf-token`.
4. Cursor **Plugins → Configure** → paste into `SKOOL_AUTH_TOKEN`, `SKOOL_CLIENT_ID`, `SKOOL_AWS_WAF_TOKEN`.

Session expires (`aws-waf-token` often first) → paste again. Recipients on another machine always use this path.

Optional: `SKOOL_COMMUNITY_SLUG` so tools can omit `community_slug`. Use **your** community’s URL slug (pattern `my-community-1234`). There is no default classroom.

### B. Same-machine Chrome (optional)

If Cursor / the MCP host runs as the **same OS user** as a Chrome profile already signed into skool.com, set `SKOOL_AUTH_MODE=chrome` (or `SKOOL_USE_CHROME=1`) and leave the three env cookies unset.

The server reads Chrome’s **Cookies** SQLite DB at a short list of well-known paths only (no filesystem crawl):

- Linux: `~/.config/google-chrome/{Default,Profile 1}/Cookies` and `.../Network/Cookies` (same for `chromium`, `google-chrome-beta`)
- macOS: `~/Library/Application Support/Google/Chrome/{Default,Profile 1}/Cookies` (and Chromium)

`skool_auth_status` reports `source=chrome` and present/expiry **without printing values**.

Limits:

- **Linux:** decrypts Chrome **v10** cookies (stdlib AES-128-CBC + the well-known `peanuts` key). v11 / libsecret / v20 are not supported — use A or a cookie file.
- **macOS / Windows:** Keychain and DPAPI are not implemented. Use **A** or export a Netscape cookie file to `SKOOL_COOKIE_FILE`.
- Paths are OS/profile-fragile. This is **not** a way to share credentials. Recipients on another machine use **A**.

Optional: `SKOOL_CHROME_PROFILE` (`Default` or `Profile 1`) or an exact `SKOOL_CHROME_COOKIES_DB` path.

### Cookie file (escape hatch)

`SKOOL_COOKIE_FILE` may point at:

- a **Netscape** `cookies.txt` (exported from the browser / an extension), or
- a file whose body is a `Cookie:` header (or `auth_token=…; client_id=…; aws-waf-token=…`)

Used when the three env cookies are not all set. Do not commit that file.

### Optional bookmarklet (clipboard only)

This does **not** inject into Cursor. Run it **on skool.com**. It copies placeholder-ready lines for Plugins → Configure.

**HttpOnly:** `document.cookie` cannot read HttpOnly cookies. If DevTools → Application shows **HttpOnly** on `auth_token` (typical for session JWTs), the bookmarklet **will not see it** — copy from the Application panel (A). If a copied line is empty, that cookie is HttpOnly.

```javascript
javascript:(()=>{const names=['auth_token','client_id','aws-waf-token'];const env={auth_token:'SKOOL_AUTH_TOKEN',client_id:'SKOOL_CLIENT_ID','aws-waf-token':'SKOOL_AWS_WAF_TOKEN'};const map={};for(const p of document.cookie.split(';')){const i=p.indexOf('=');if(i<0)continue;const k=p.slice(0,i).trim();if(names.includes(k))map[k]=p.slice(i+1).trim();}const missing=names.filter(n=>!map[n]);const text=names.map(n=>env[n]+'='+(map[n]||'')).join('\n');const done=()=>alert(missing.length?'Empty value(s) '+missing.join(', ')+' — likely HttpOnly. Copy those from DevTools → Application → Cookies. Clipboard has the other lines.':'Copied three SKOOL_* lines. Paste into Plugins → Configure. Never commit them.');navigator.clipboard.writeText(text).then(done).catch(()=>{prompt('Copy:',text);done();});})();
```

### Local stdio

```bash
# A — portable
export SKOOL_AUTH_TOKEN='…'
export SKOOL_CLIENT_ID='…'
export SKOOL_AWS_WAF_TOKEN='…'

# B — same-machine Chrome (Linux v10)
# export SKOOL_AUTH_MODE=chrome

# or: Netscape / Cookie-header file
# export SKOOL_COOKIE_FILE=./cookies.txt   # gitignored; never commit

python3 ./server.py
```

The server never prints cookie values. `skool_auth_status` is safe to run in logs.

## Share / Grok Bot install

Public clone: `https://github.com/jonhilt/skool-classroom-plugin`

Grok Bot does **not** load `~/.cursor/plugins/local`. Bot templates cannot pack custom MCP servers. This **git clone + Add MCP server** path is the supported friend share until/unless the plugin is listed on cursor.directory later (this repo is **not** submitted to Marketplace or cursor.directory).

### Friend on Grok Bot (custom MCP)

1. Clone this repo onto the **Grok Bot computer** (or copy the folder).
2. Add an MCP server (stdio). Cookies must be **theirs**, copied from their own skool.com DevTools — never someone else’s session.
3. Prefer paste auth (section A). Chrome mode only if **that** Grok Bot machine’s Chrome is signed into Skool as the same OS user.
4. Call `skool_auth_status` first. Writes stay `dry_run` unless they explicitly apply (`dry_run=false`).
5. Unofficial API / bring-your-own session. You are responsible for Skool’s terms; this client is not affiliated with Skool.

Replace the args path with the absolute path on the Grok Bot computer:

```json
{
  "mcpServers": {
    "skool": {
      "type": "stdio",
      "command": "python3",
      "args": ["/absolute/path/to/skool-classroom-plugin/server.py"],
      "env": {
        "SKOOL_AUTH_TOKEN": "<their auth_token cookie>",
        "SKOOL_CLIENT_ID": "<their client_id cookie>",
        "SKOOL_AWS_WAF_TOKEN": "<their aws-waf-token cookie>",
        "SKOOL_COMMUNITY_SLUG": "<their-community-slug>"
      }
    }
  }
}
```

`SKOOL_COMMUNITY_SLUG` is optional if every tool call passes `community_slug`.

## Dry-run writes

`skool_lesson_set` and `skool_lesson_attach_image` default to `dry_run=true`. You get a preview (title + markdown). Nothing is uploaded or PUT until `dry_run=false`.

Lesson edits `PUT /courses/{moduleHex}` with **`{title, desc}` only**. Extra keys return 400. Title is always echoed from the current lesson unless you pass a new one — omitting title blanks it.

**Never PUT the course root to edit a lesson.** A partial course PUT that omits `state` or `privacy` can reset privacy (including opening a gated course) or flip Draft → Active. This plugin refuses course-root ids on lesson write tools.

## Data shapes

```text
Course  = { id (hex), name (numeric web id), title, state (1=Draft | 2=Active), privacy, min_tier?, children[] }
Lesson  = { id (hex), name, title, unit_type, parent_id?, desc? }
```

`desc` is the string `[v2]` plus a TipTap JSON **array**.

## Prove / validate (no live Skool required)

```bash
python3 ./scripts/prove.py
```

This checks:

1. `plugin.json` and `mcp.json` against Agent Plugins 1.0.0 schemas
2. `python3 -m py_compile` on `server.py` and `auth.py`
3. MCP smoke: `initialize` + `tools/list`
4. Unit tests (markdown, dry-run, auth_status with **fake** env / files — no real secrets)

**Live API calls are skipped** unless `SKOOL_AUTH_TOKEN`, `SKOOL_CLIENT_ID`, and `SKOOL_AWS_WAF_TOKEN` are already in the environment. Prove still passes if they are missing. If they are present, prove calls `skool_auth_status` only (still no cookie values in output). A courses list is attempted only when `SKOOL_COMMUNITY_SLUG` is also set.

## Layout

```text
plugin.json                 Agent Plugins 1.0.0 manifest
.cursor-plugin/plugin.json  Cursor variable schema (cookies + optional chrome/file)
mcp.json                    stdio MCP: python3 ./server.py, cwd ${PLUGIN_ROOT}
server.py                   JSON-RPC MCP + urllib (stdlib)
auth.py                     env / cookie file / optional Chrome v10 (never prints values)
skills/skool/SKILL.md       when to use, unofficial API, write rules
scripts/prove.py            schema + compile + smoke
```
