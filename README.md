<div align="center">

# reconmind

**Passive recon coverage index for bug bounty — what you already tested, and where**

![Language](https://img.shields.io/badge/Python-3.12+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-0.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

```text
┌──────────────────────────────────────────────────┐
│  reconmind — coverage index for bug bounty        │
│  passive · zero-command · by theoffsecgirl        │
└──────────────────────────────────────────────────┘
```

---

## What does it do?

On a large target you end up with a pile of recon output from your own tools —
[pathraider](https://github.com/theoffsecgirl/pathraider) *(now folded into this repo, see
below)*, [webxray](https://github.com/theoffsecgirl/webxray),
[takeovflow](https://github.com/theoffsecgirl/takeovflow),
[findings-hub](https://github.com/theoffsecgirl/findings-hub) — plus whatever a
deterministic recon pipeline produced, and it's easy to lose track of which endpoint or
parameter was already tested for which vulnerability class. There's no equivalent of
"code coverage" for bug bounty. `reconmind` reads the JSON those tools already emit with
`--json-output` and writes a Markdown matrix, `notes/coverage.md`, straight into the
target's own folder.

`reconmind` **does not scan, does not send a single request, does not decide anything for
you.** It only reads JSON that already exists on disk and summarizes it. It's a view, not
a tool you run.

> Note: `notes/coverage.md` itself is generated in Spanish — it's a personal tool wired
> into a Spanish-language hunting workflow. The code, this README and the tests are in
> English/bilingual, but the output matches the rest of the notes it lives next to.

---

## Zero friction: not a command you have to remember

`reconmind` is not used by hand. It hooks into the end of an existing `hunt-start`
shell function and runs silently every time a session starts — the same way
`program-init` or `scope-program` already do. It never blocks the session: if anything
fails, it warns on stderr and moves on.

### Installation

**From source**
```bash
git clone https://github.com/theoffsecgirl/reconmind.git
cd reconmind
chmod +x reconmind.py
ln -s "$(pwd)/reconmind.py" ~/.local/bin/reconmind
```

**Requirements**
- Python 3.12+
- No runtime dependencies (standard library only)

### Hooking into `hunt-start`

Inside your `hunt-start` function, between the step that loads test-account credentials
into the environment and the step that opens your editor/agent (the final `cd "$tdir"`),
add:

```zsh
  # reconmind — silently refreshes notes/coverage.md, never blocks the session
  if command -v reconmind >/dev/null 2>&1; then
    reconmind "$tdir" || print -u2 "[i] reconmind could not update coverage.md (non-blocking)"
  fi
```

Nothing else to wire up — `$tdir` already exists as the target's directory in a typical
`hunt-start`.

---

## Output format: `notes/coverage.md`

Open it like any other notes file — it's not something you "run". It only lists
endpoints that already have a signal from some tool (with thousands of URLs per target, a
table with a row for every untouched endpoint would be unreadable); everything else is
summarized in one line, the way a real code-coverage report doesn't print every untested
line either.

Example (synthetic domains):

```markdown
# Coverage — testtarget
> Generado por reconmind el 2026-08-20 20:56 UTC. No editar a mano — se sobreescribe en cada `hunt-start`.

JSON de herramientas encontrados: takeovflow(1) · webxray(1)

Leyenda: ⬜ no probado · 🟢 probado-limpio · 🟡 probado-sospechoso · 🔴 confirmado (reservado — este script nunca lo marca, ver abajo)

| Endpoint | Auth | Access Control | IDOR | API Security | Business Logic | Client-Side/XSS | Misconfig | SSRF | Otro |
|---|---|---|---|---|---|---|---|---|---|
| https://example.com/search | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🟡 webxray: xss en param `q` | ⬜ | ⬜ | ⬜ |
| https://staging.example.com/ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🟡 webxray: cabecera ausente `Content-Security-Policy` | ⬜ | ⬜ |
| old-shop.example.com | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🟡 takeovflow: posible takeover (subjack, severidad HIGH) | ⬜ | ⬜ |
| www.example.com | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🟢 takeovflow: resuelto, sin huella de takeover | ⬜ | ⬜ |

## Resumen
- 3 endpoints conocidos (http/*.txt) · 4 con alguna señal de herramienta · 0 sin tocar (⬜)
- 🟡 sospechoso: 3 · 🟢 limpio: 1 · 🔴 confirmado: 0
```

Columns are your 8 priority vulnerability classes (Auth, Access Control, IDOR, API
Security, Business Logic, Client-Side/XSS, Misconfig, SSRF) plus a ninth, "Otro"
("Other"), for things the tools do test but that don't belong in those 8 (e.g. SQLi,
LFI/path traversal).

### Why there's no auto-confirmed state

`reconmind` never writes a 🔴 confirmed cell on its own. None of these tools validate
impact — they're heuristics (`webxray`: reflected payload, unverified; `pathraider`:
candidate traversal pattern; `takeovflow`: it literally calls its own finding
`potential_takeovers`). Auto-marking something confirmed would break the basic bug-bounty
discipline of never calling something a vulnerability without validated impact. The state
stays reserved in the legend for a future phase that correlates with what you confirm by
hand in your target notes — not implemented in this MVP.

### Privacy

`reconmind` never walks into `loot/`, `.creds/`, `.git/`, `.venv`/`venv/`,
`node_modules/` or `.claude/` inside a target folder, even if they contain `.json`. It
only looks at the rest.

---

## What JSON it can read

`reconmind` doesn't trust filenames — it identifies the tool by the *shape* of the JSON
(the keys each one already emits with `--json-output`), so you can save those files
wherever you like inside the target folder (e.g. `notes/` or `meta/`).

| Tool | How to produce the JSON | Shape it recognizes | What it contributes |
|---|---|---|---|
| [`pathraider`](https://github.com/theoffsecgirl/pathraider) | `pathraider ... --json-output notes/pathraider.json` | `{"tool": "pathraider", "targets": {url: [findings]}}` | "Otro" column — 🟢 if that URL's findings list is empty, 🟡 otherwise |
| [`webxray`](https://github.com/theoffsecgirl/webxray) | `webxray ... --json-output notes/webxray.json` | flat list of dicts with `type` + `url` | XSS → Client-Side/XSS · SQLi → Otro · missing header → Misconfig. **Never produces 🟢**: its JSON only records findings, not "scanned, nothing to report" |
| [`takeovflow`](https://github.com/theoffsecgirl/takeovflow) | `takeovflow ... --json-output notes/takeovflow.json` | `{"tool": "takeovflow", "domains": {...}}` | Misconfig column — 🟡 for each entry in `potential_takeovers`, 🟢 for the rest of the resolved subdomains |
| [`findings-hub`](https://github.com/theoffsecgirl/findings-hub) | `findings-hub analyze ... --json > notes/findings-hub.json` (note: it does **not** write a file on its own, you need to redirect stdout yourself) | `{"modo": "analyze", "hallazgos": [...]}` | Column inferred from each finding's `tags`/`description` (falls back to "Otro"); endpoint extracted from any URL inside `line`, or `source_file (line N)` otherwise |

Any other `.json` sitting in the target folder (npm packages, configs, Caido exports...)
is silently ignored — that's not an error, it just doesn't match a known shape. If an
expected `.json` is corrupt or unreadable, `reconmind` warns on stderr and keeps going
without breaking `hunt-start`.

The deterministic recon pipeline (subdomain/URL/param discovery scripts) doesn't produce
JSON with a per-endpoint verdict — only plain-text lists (`http/live.txt`,
`http/urls_clean.txt`, `fuzz/params.txt`...). `reconmind` does use those to count total
known surface in the summary line (check the `SURFACE_FILES` constant in `reconmind.py`
if that folder layout changes), but they never generate rows on their own — a row only
appears once a tool has actually left a signal.

---

## What it does NOT do (yet)

None of this is in the MVP — future phase, decided after living with this for a while:

- Interactive query commands.
- Manual logging of tests done by hand in Caido/Burp.
- Natural language / LLM correlation.
- Cross-target correlation.

---

## Tests

```bash
cd reconmind
python3 -m pip install pytest   # or: pip install -e ".[dev]"
pytest
```

---

## Ethical use

For bug bounty, labs and authorized engagements only. `reconmind` itself never touches
the network — it only reads local JSON your other tools already produced under
authorization.

---

## License

MIT · [theoffsecgirl](https://github.com/theoffsecgirl)
