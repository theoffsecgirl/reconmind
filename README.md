<div align="center">

# reconmind

**Passive recon coverage index for bug bounty — what you already tested, and where**

![Language](https://img.shields.io/badge/Python-3.12+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-0.2.0-9E4AFF?style=flat-square)
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

On a large target you end up with a pile of recon output from a bunch of different
tools, and it's easy to lose track of which endpoint or parameter was already tested for
which vulnerability class. There's no equivalent of "code coverage" for bug bounty.
`reconmind` reads JSON that tools already emit and writes a Markdown matrix,
`notes/coverage.md`, straight into the target's own folder.

`reconmind` **does not scan, does not send a single request, does not decide anything for
you.** It only reads JSON that already exists on disk and summarizes it. It's a view, not
a tool you run.

It reads two kinds of input:

1. **The generic schema** (see below) — a small public JSON contract any tool, yours or
   someone else's, can emit. This is the main way to plug something into `reconmind`, and
   `reconmind` doesn't need to know the tool in advance to understand it.
2. **A few built-in adapters** for tools of mine that don't speak that schema —
   [webxray](https://github.com/theoffsecgirl/webxray),
   [takeovflow](https://github.com/theoffsecgirl/takeovflow),
   [findings-hub](https://github.com/theoffsecgirl/findings-hub). These are an addition,
   not a requirement — if you don't use any of them, the generic schema is all you need.

> Note: `notes/coverage.md` itself is generated in Spanish — it's a personal tool wired
> into a Spanish-language hunting workflow. The code, this README and the tests are in
> English/bilingual, but the output matches the rest of the notes it lives next to.

---

## Zero friction: not a command you have to remember

`reconmind` is not used by hand. It hooks into the end of an existing `hunt-start`
shell function and runs silently every time a session starts — the same way other
recon steps already do. It never blocks the session: if anything fails, it warns on
stderr and moves on.

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

## The generic schema — how to plug in any tool

This is the contract. Any tool, script, or one-off `jq` pipeline can produce a JSON file
that looks like this, drop it anywhere inside the target folder, and `reconmind` will
pick it up without needing to know the tool by name:

```json
{
  "tool": "your-tool-name",
  "findings": [
    {
      "url": "https://example.com/endpoint",
      "class": "xss",
      "status": "suspicious",
      "detail": "optional free-text note"
    }
  ]
}
```

- **`tool`** — free text, shown in the note for each finding and in the source count at
  the top of `coverage.md`.
- **`class`** — one of: `auth`, `access-control`, `idor`, `api`, `business-logic`, `xss`,
  `misconfig`, `ssrf`, `other`. These map 1:1 to the 8 priority vulnerability classes plus
  a catch-all "Otro" column. An unrecognized value falls back to `other` instead of
  breaking the parse.
- **`status`** — one of: `clean`, `suspicious`, `confirmed`. An unrecognized value falls
  back to `suspicious`.
- **`detail`** — optional free text shown in the cell.

Any field reconmind doesn't recognize is ignored; a finding missing a `url` is skipped.
A malformed JSON file never crashes the run — it's reported on stderr and skipped.

**On `"confirmed"`:** unlike the built-in adapters below (which never assert confirmed —
see "On the confirmed state" further down), the generic schema *does* pass through
`"confirmed"` as given. That's a deliberate difference: here a tool is making an explicit
claim under its own responsibility, not reconmind inferring one from a heuristic. If your
tool only reports unverified candidates, use `"suspicious"` — don't claim `"confirmed"`
unless you've actually validated it.

To keep that distinction visible where it matters, `reconmind` appends a disclaimer to
any 🔴 confirmed cell that came from the generic schema: `— confirmado declarado por
<tool>, no validado por reconmind` ("confirmed as declared by `<tool>`, not validated by
reconmind"). You'll never see that disclaimer on a confirmed cell from one of the
built-in adapters, because they never produce one in the first place — see below.

---

## Output format: `notes/coverage.md`

Open it like any other notes file — it's not something you "run". It only lists
endpoints that already have a signal from some tool (with thousands of URLs per target, a
table with a row for every untouched endpoint would be unreadable); everything else is
summarized in one line, the way a real code-coverage report doesn't print every untested
line either.

Example (synthetic domains, mixing the generic schema and a built-in adapter):

```markdown
# Coverage — testtarget
> Generado por reconmind el 2026-08-21 09:00 UTC. No editar a mano — se sobreescribe en cada `hunt-start`.

JSON de herramientas encontrados: generico(1) · webxray(1)

Leyenda: ⬜ no probado · 🟢 probado-limpio · 🟡 probado-sospechoso · 🔴 confirmado (solo si una herramienta lo declara explicitamente via el esquema generico — ningun adaptador conocido lo marca por su cuenta, ver README)

| Endpoint | Auth | Access Control | IDOR | API Security | Business Logic | Client-Side/XSS | Misconfig | SSRF | Otro |
|---|---|---|---|---|---|---|---|---|---|
| https://example.com/search | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🟡 webxray: xss en param `q` | ⬜ | ⬜ | ⬜ |
| https://internal.example.com/admin | ⬜ | 🔴 mi-escaner-random: acceso sin auth validado a mano — confirmado declarado por mi-escaner-random, no validado por reconmind | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |

## Resumen
- 2 endpoints conocidos (http/*.txt) · 2 con alguna señal de herramienta · 0 sin tocar (⬜)
- 🟡 sospechoso: 1 · 🟢 limpio: 0 · 🔴 confirmado: 1
```

Columns are the 8 priority vulnerability classes (Auth, Access Control, IDOR, API
Security, Business Logic, Client-Side/XSS, Misconfig, SSRF) plus a ninth, "Otro"
("Other"), for anything that doesn't belong in those 8.

### On the confirmed state

The three built-in adapters (`webxray`, `takeovflow`, `findings-hub`) never write a 🔴
confirmed cell on their own. None of them validate impact — they're heuristics
(`webxray`: reflected payload, unverified; `takeovflow`: it literally calls its own
finding `potential_takeovers`; `findings-hub`: pattern match, not exploitation).
Auto-marking something confirmed from a heuristic would break the basic bug-bounty
discipline of never calling something a vulnerability without validated impact.

The generic schema is different: there, `"confirmed"` is something the tool itself
asserts, and `reconmind` just renders what the contract says — see above. But it doesn't
render it identically to how a hypothetical future confirmed-by-reconmind state would
look: every 🔴 cell coming from the generic schema carries the `— confirmado declarado
por <tool>, no validado por reconmind` disclaimer inline, so it reads visually different
from a plain 🔴, and nobody mistakes a third party's claim for something reconmind itself
checked.

### Privacy

`reconmind` never walks into `loot/`, `.creds/`, `.git/`, `.venv`/`venv/`,
`node_modules/` or `.claude/` inside a target folder, even if they contain `.json`. It
only looks at the rest.

---

## Built-in adapters

These ship with `reconmind` for tools of mine that predate the generic schema and don't
speak it. They're additional, not the primary path — if none of these are your tools,
just emit the generic schema from whatever you use instead.

| Tool | How to produce the JSON | Shape it recognizes | What it contributes |
|---|---|---|---|
| [`webxray`](https://github.com/theoffsecgirl/webxray) | `webxray ... --json-output notes/webxray.json` | flat list of dicts with `type` + `url` | XSS → Client-Side/XSS · SQLi → Otro · missing header → Misconfig. **Never produces 🟢**: its JSON only records findings, not "scanned, nothing to report" |
| [`takeovflow`](https://github.com/theoffsecgirl/takeovflow) | `takeovflow ... --json-output notes/takeovflow.json` | `{"tool": "takeovflow", "domains": {...}}` | Misconfig column — 🟡 for each entry in `potential_takeovers`, 🟢 for the rest of the resolved subdomains |
| [`findings-hub`](https://github.com/theoffsecgirl/findings-hub) | `findings-hub analyze ... --json > notes/findings-hub.json` (note: it does **not** write a file on its own, you need to redirect stdout yourself) | `{"modo": "analyze", "hallazgos": [...]}` | Column inferred from each finding's `tags`/`description` (falls back to "Otro"); endpoint extracted from any URL inside `line`, or `source_file (line N)` otherwise |

Any other `.json` sitting in the target folder that matches neither the generic schema
nor one of these three shapes is silently ignored — that's not an error, it just doesn't
match anything reconmind understands. If an expected `.json` is corrupt or unreadable,
`reconmind` warns on stderr and keeps going without breaking `hunt-start`.

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
