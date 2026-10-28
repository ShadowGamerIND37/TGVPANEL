# HKVM Panel

A self-hosted **QEMU/KVM virtual machine control panel** built with Express, EJS and SQLite.
Manage machines, users, OS templates, VNC consoles and SSH sessions from one dashboard.

This fork ships the **Aurora** UI layer — a premium design system and UX engine layered on top of the
classic panel so every page feels modern without changing how the backend works.

---

## Highlights

| Area | What you get |
| --- | --- |
| **Design system** | Dark/light themes, five accent palettes, comfortable/compact density, animated ambient background, glass surfaces, refined typography |
| **Command palette** | Press <kbd>⌘</kbd>/<kbd>Ctrl</kbd> + <kbd>K</kbd> anywhere to search VMs, users, pages and actions — including *start* / *stop* on any machine without leaving the keyboard |
| **Dashboards** | Live KPI cards with sparkline history, host CPU/RAM/disk telemetry, activity feed, membership snapshot |
| **VM management** | Start/stop with styled confirmations, live cards, per-VM SSH command copy, console links |
| **Feedback** | Toast notifications, inline alerts, top progress bar, skeleton loaders, empty states |
| **Accessibility** | Focus-visible rings, keyboard navigation, reduced-motion support, semantic landmarks |
| **Responsive** | Collapsible icon rail on desktop, off-canvas drawer on mobile, fluid grids |

---

## Quick start

```bash
npm install
npm start          # http://localhost:8080
```

Environment variables (optional):

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `PANEL_NAME` | `HKVM` | Default site name |
| `PANEL_VERSION` | `V2.0` | Version label in the UI |
| `HKVM_DATA_DIR` | `~/.hkvm` | SQLite database directory |
| `DEFAULT_LOGO_URL` | `/images/logo.png` | Fallback logo |

The first boot creates an `admin` account (password `admin`) — **change it immediately** from
*Profile → Password*.

---

## Keyboard shortcuts

| Keys | Action |
| --- | --- |
| <kbd>⌘</kbd>/<kbd>Ctrl</kbd> + <kbd>K</kbd> | Open the command palette |
| <kbd>/</kbd> | Focus the navigation filter |
| <kbd>T</kbd> | Toggle dark / light theme |
| <kbd>?</kbd> | Shortcut cheat-sheet |
| <kbd>G</kbd> then <kbd>D</kbd> / <kbd>V</kbd> / <kbd>U</kbd> / <kbd>S</kbd> | Go to dashboard / VMs / users / settings |
| <kbd>N</kbd> | Create a new VM (administrators) |
| <kbd>Esc</kbd> | Close palette, popovers and dialogs |

---

## Appearance studio

Click the palette icon in the header (or run **Appearance studio** from the command palette) to change:

- **Theme** — dark (default) or light
- **Accent** — indigo, violet, cyan, emerald, rose
- **Density** — comfortable or compact
- **Motion** — disable animations for calmer sessions

Preferences are stored in `localStorage` (`pm.theme`, `pm.accent`, `pm.density`, `pm.motion`)
so they follow the user across every page and survive reloads.

---

## Architecture

```
app.js                     Express app, SQLite schema, REST API, WebSocket console/SSH
views/                     EJS pages and shared partials
  partials/admin/          Sidebar, header, footer for the admin area
  partials/users/          Sidebar for the end-user area
public/css/admin.css       Legacy component library (still used by every page)
public/css/premium.css     Aurora design layer (loaded after admin.css)
public/js/premium.js       UX engine: palette, toasts, themes, charts, shortcuts
public/images/logo.png     Default brand mark
```

`premium.css` maps the legacy CSS variables onto the new token set, so older pages inherit the new
look automatically while page-specific layouts keep working.

### Added API endpoints

| Endpoint | Auth | Description |
| --- | --- | --- |
| `GET /api/system/metrics` | any session | CPU load, memory, disk, uptime, host info, VM counts |
| `GET /api/system/status` | any session | Compact CPU/memory/uptime summary |
| `GET /api/activity?limit=` | any session | Recent `vm_logs` entries scoped to the caller's machines |
| `GET /api/admin/activity?limit=` | admin | Panel-wide activity feed |
| `GET /api/search?q=` | any session | Unified VM + user search used by the command palette |

---

## Notes

- The UI layer is dependency-free — no build step, no bundler, no external JS libraries.
- Google Fonts (Inter) is used when available and degrades to the system font stack offline.
- All new client-side features are progressive enhancements: every page still works if JavaScript
  is unavailable for those extras.
- Font Awesome glyphs used by a few legacy pages are re-rendered as inline SVG when the CDN cannot be
  reached, so icons never disappear on an offline panel.
- Protected `/api/*` routes answer `401` / `403` with JSON instead of an HTML redirect, so the SPA-style
  scripts can show a proper error toast instead of failing silently.

## License

MIT — see `package.json`.
