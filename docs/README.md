# Cybersecurity Skills Browser

A static, single-page browser for the 754 skills in this repository. Filter by
subdomain, tag, or framework mapping; search across names, descriptions, tags,
and MITRE ATT&CK technique IDs; preview each skill's "When to use" section
without leaving the page.

## Run locally

From the repository root:

```bash
python3 tools/build-browser-data.py   # writes docs/data.json
python3 -m http.server --directory docs 8000
```

Then open <http://localhost:8000>.

The browser is plain HTML/CSS/JS — no build step, no `node_modules`. All
filtering happens client-side over an in-memory copy of `data.json`.

## Deploy to GitHub Pages

1. In the repository on github.com, open **Settings → Pages**.
2. Under **Build and deployment → Source**, choose **Deploy from a branch**.
3. Set branch to `main` and folder to `/docs`. Save.

The site will be served at `https://<owner>.github.io/<repo>/` within a minute
or two. No additional CI configuration is required — Pages picks up the
`/docs` folder directly.

`docs/data.json` is regenerated automatically by `.github/workflows/update-index.yml`
on every push to `main` that touches `skills/**`,
`mappings/attack-navigator-layer.json`, or `tools/build-browser-data.py`. The
generated file is committed back to the repo, so the deployed site stays in
sync with the catalogue.

## Shareable filtered views

The current filter state is serialized into the URL hash, so any filtered view
can be linked. Example:

```
https://<owner>.github.io/<repo>/#sub=cloud-security&tag=kerberos&fw=attack
```

Parameters:

| Key   | Meaning                                  | Example value                       |
|-------|------------------------------------------|-------------------------------------|
| `sub` | Subdomain(s), comma-separated            | `cloud-security,threat-hunting`     |
| `tag` | Tag(s), comma-separated                  | `kerberos,lateral-movement`         |
| `fw`  | Framework presence: `attack`, `nist_csf`, `owasp` | `attack,nist_csf`             |
| `q`   | Free-text search                         | `T1558` or `kerberoasting`          |

Within a category the filter is OR; across categories it is AND.

## Keyboard shortcuts

| Key       | Action                                     |
|-----------|--------------------------------------------|
| `↑` / `↓` | Move selection through visible results     |
| `Enter`   | Open the first result (when none active)   |
| `/`       | (Browser default) focus the search bar     |

## File layout

```
docs/
├── index.html      Layout shell
├── app.css         Styles (dark theme)
├── app.js          Filtering, rendering, URL/keyboard state
├── data.json       Generated catalogue (CI-managed; do not hand-edit)
└── README.md       This file
```
