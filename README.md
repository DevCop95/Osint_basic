# ⬡ OSINT Terminal v2 — README

**Quick description**
OSINT Terminal v2 is a lightweight JavaScript tray/terminal that you inject into a webpage (console/bookmarklet) to perform fast browser-based reconnaissance and analysis. It intercepts `fetch` and `XMLHttpRequest`, inspects DOM/meta/scripts, hunts for tokens (JWTs, API keys), persists findings to `IndexedDB`, and allows exporting results. Intended for authorized testing and internal audits only.

> **IMPORTANT — legal & security**
> Use this tool **only** on sites you own or where you have explicit permission to audit. Intercepting traffic or extracting credentials on third‑party sites without authorization can be illegal and dangerous. Do not publish found credentials.

---

## How to use (quick install)

Paste the entire script you were given directly into the browser console (DevTools → Console) and press Enter. Alternatively, build a bookmarklet with the IIFE to inject in one click.

### Inject via console

1. Open DevTools (F12 / Ctrl+Shift+I).
2. Go to *Console*.
3. Paste the complete script and press Enter.
4. The terminal UI will appear at the bottom-right: `⬡ OSINT Terminal v2`.

### Bookmarklet (one-click)

Create a bookmark with the following as the URL:

```text
javascript:(() => { /* paste the whole IIFE body here */ })();
```

Clicking the bookmark injects the terminal into the current page.

---

## Requirements / Compatibility

* Modern browser (Chrome, Edge, Firefox).
* `fetch` / `XMLHttpRequest` and IndexedDB support.
* In pages with very restrictive CSP or cross-origin iframes, deep scan and some overrides may fail.
* No external dependencies required.

---

## Main commands (quick list)

Type these commands inside the terminal's input (the UI created by the script):

```
help         # Show commands list
info         # Page basic info
meta         # Meta tags and SEO
links        # External links
imgs         # Images with dimensions
scripts      # Loaded scripts
headings     # Headings structure
forms        # Forms and fields
emails       # Visible email addresses
tech         # Detected technologies
a11y         # Accessibility analysis
scan         # Full scan (runs all scans)
export       # Export page info (osint_<host>.json)
cookies      # Show accessible cookies
show-deep    # Token hunter: DOM/localStorage/sessionStorage
net-on       # Enable network interceptor (fetch + XHR)
net-off      # Disable network interceptor
deep         # Deep script scan (token hunter)
traffic      # View captured traffic (recent)
inspect <i>  # Inspect request/response by index
replay       # Replay last request (cloned)
history      # Command history
correlate    # Correlation engine (flags: AUTH, TOKEN, HEADER_AUTH)
findings     # Summary of findings (tokens, endpoints, headers, JWTs)
export-all   # Export traffic + findings → osint_pro.json
clear        # Clear terminal
exit         # Close UI
```

---

## Example test case — paste and run (step-by-step)

Follow this typical test flow. You may paste lines one-by-one into the terminal input or run them sequentially.

1. Enable the network interceptor and perform actions on the page:

```
net-on
```

**Expected logs** (examples):

```
🔥 NET INTERCEPTOR + ANALYSIS ACTIVATED
── FETCH → GET ─────────────────────────────────────
  URL: https://example.com/api/...
  accept: application/json
  ⚠ possible sensitive data in response
  [JWT] (4) eyJhbGci...  // if a JWT is detected
```

2. Run a full page scan:

```
scan
```

**Expected partial output**:

```
── INFO ─────────────────────────────────────────────
  URL: https://example.com/path
  Title: Example Site
  Scripts: 12
  Links: 34
── META TAGS ───────────────────────────────────────
  description: Example...
  og:title: Example Site
...
```

3. Hunt tokens in DOM/storage:

```
show-deep
```

**Output**:

```
TOKEN HUNTER
  eyJ... (if a JWT is found)
  Nothing found (if none)
```

4. View and correlate captured traffic:

```
traffic
correlate
```

**Example**:

```
[0] POST https://example.com/api/login
  headers: {"authorization":"Bearer eyJ..."}
  ⚠ AUTH | TOKEN
```

5. Export everything locally:

```
export-all
```

Generates `osint_pro.json` containing tokens, endpoints, headers, decoded JWTs, and a recent slice of traffic.

---

## Detection technical notes

* **JWT detection**: Regex `eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+` — payload is base64-decoded and stored under `findings.jwt`.
* **Rules**: Look for common patterns (AWS keys `AKIA...`, `api_key`, `Bearer <token>`, etc.). Also flag high-entropy strings (>=20 characters and entropy > 4.2).
* **Persistence**: Uses `IndexedDB` store `osintDB_v2` with `traffic` and `findings` object stores.
* **Interception**: Overrides `window.fetch` and `XMLHttpRequest` to record URL, headers, body, and responses (responses are cloned before reading).

---

## Security, privacy and limitations

* **Sensitive data**: The script logs credentials and tokens into the UI and IndexedDB. Remove or redact sensitive data before sharing results.
* **CORS / same-origin**: Cannot read cross-origin responses unless the server allows CORS.
* **Risk**: Executing on third-party sites can cause data leakage — again: **only** use in authorized environments.
* **No exfiltration by default**: The script does not transmit findings to external services; `export`/`export-all` produce local downloadable files. Review code if you need to change behavior.

---

## Troubleshooting (common issues)

* **UI not visible**: Check for script blockers, CSP rules, or that the IIFE was actually executed.
* **`net-on` not capturing**: Pages using ServiceWorkers or WebSockets may bypass `fetch`/XHR overrides.
* **IndexedDB open errors**: Try clearing site storage or testing in a new tab; some sandboxed contexts interfere with IndexedDB.
* **Restore original `fetch`/XHR**: Run `net-off` or `exit`; if the page behaves strangely, reload it.

---

## Development & contribution notes

* Recommended improvements: add more detection rules (OAuth codes, SAML assertions), integrate a headless/export-only mode for controlled pentests, or add richer correlation rules.
* Keep the main script modular for testing and version control.

---

## License & credits

* Add a license (MIT/Apache) if you plan to publish publicly.
* Author: add your name or alias and any credits.

---

## Changelog (suggested)

* **v2** — Unified interceptor (fetch + XHR), high-entropy detection, persistent IndexedDB, export-all.

*End of README — English version.*
