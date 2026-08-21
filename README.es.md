<div align="center">

# reconmind

**Índice pasivo de cobertura de recon para bug bounty — qué ya probaste, y dónde**

![Language](https://img.shields.io/badge/Python-3.12+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-0.1.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)
![Dependencies](https://img.shields.io/badge/dependencias-ninguna-brightgreen?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

```text
┌──────────────────────────────────────────────────┐
│  reconmind — indice de cobertura para bug bounty  │
│  pasivo · sin comandos nuevos · by theoffsecgirl  │
└──────────────────────────────────────────────────┘
```

---

## Qué problema resuelve

En un target grande se acumulan muchos outputs de recon de tus propias herramientas —
[pathraider](https://github.com/theoffsecgirl/pathraider) *(ahora fusionado en este
mismo repo, ver abajo)*, [webxray](https://github.com/theoffsecgirl/webxray),
[takeovflow](https://github.com/theoffsecgirl/takeovflow),
[findings-hub](https://github.com/theoffsecgirl/findings-hub) — más lo que genera tu
pipeline determinista de recon, y es fácil perder de vista qué endpoint/parámetro ya se
probó para qué clase de vulnerabilidad. No existe un "code coverage" equivalente para bug
bounty. `reconmind` lee el JSON que esas herramientas ya generan con `--json-output` y
escribe una matriz Markdown, `notes/coverage.md`, dentro de la propia carpeta del target.

`reconmind` **no escanea nada, no hace ni una petición, no decide nada por ti**. Solo lee
JSON que ya existe en disco y lo resume. Es una vista, no una herramienta que se ejecuta.

---

## Cero fricción: no es un comando que tengas que recordar

`reconmind` no se usa a mano. Se engancha al final de tu función `hunt-start` existente y
corre en silencio cada vez que arrancas una sesión — igual que ya haces con
`program-init` o `scope-program`. Nunca bloquea la sesión: si algo falla, avisa por
stderr y sigue.

### Instalación

**Desde el código fuente**
```bash
git clone https://github.com/theoffsecgirl/reconmind.git
cd reconmind
chmod +x reconmind.py
ln -s "$(pwd)/reconmind.py" ~/.local/bin/reconmind
```

**Requisitos**
- Python 3.12+
- Sin dependencias en runtime (solo librería estándar)

### Enganche en `hunt-start`

Dentro de tu función `hunt-start`, entre el paso que carga las credenciales de las
cuentas de test al entorno y el paso que abre tu editor/agente (el `cd "$tdir"` final),
añade:

```zsh
  # reconmind — actualiza notes/coverage.md en silencio, nunca bloquea la sesión
  if command -v reconmind >/dev/null 2>&1; then
    reconmind "$tdir" || print -u2 "[i] reconmind no pudo actualizar coverage.md (no bloquea la sesión)"
  fi
```

No hace falta tocar nada más — `$tdir` ya existe como la carpeta del target en un
`hunt-start` típico.

---

## Formato de salida: `notes/coverage.md`

Se abre como cualquier otro fichero de notas — no se "ejecuta". Solo lista endpoints que
ya tienen alguna señal de herramienta (con miles de URLs por target, una tabla con una
fila por endpoint sin tocar sería ilegible); el resto se resume en una línea, igual que
un reporte de code coverage real tampoco imprime cada línea sin cubrir.

Ejemplo (con dominios ficticios):

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

Las columnas son tus 8 categorías priorizadas (Auth, Access Control, IDOR, API Security,
Business Logic, Client-Side/XSS, Misconfig, SSRF) más una novena, "Otro", para lo que las
herramientas sí prueban pero no encaja ahí (p. ej. SQLi, LFI/path traversal).

### Por qué no hay auto-confirmado

`reconmind` nunca escribe 🔴 **confirmado** por su cuenta. Ninguna de estas herramientas
valida impacto — son heurísticas (`webxray`: payload reflejado, no verificado;
`pathraider`: patrón de traversal candidato; `takeovflow`: literalmente lo llama
`potential_takeovers`). Marcarlo confirmado automáticamente rompería la disciplina básica
de bug bounty de no llamar vulnerabilidad a algo sin impacto validado. El estado queda
reservado en la leyenda para una fase futura que correlacione con lo que confirmes a mano
en tus notas del target — no está implementado en este MVP.

### Privacidad

`reconmind` nunca recorre `loot/`, `.creds/`, `.git/`, `.venv`/`venv/`, `node_modules/`
ni `.claude/` dentro de la carpeta del target, aunque contengan `.json`. Solo mira el
resto.

---

## Qué JSON sabe leer

`reconmind` no confía en el nombre del fichero — identifica la herramienta por la forma
del JSON (las claves que cada una ya emite con `--json-output`), así que puedes guardar
los ficheros donde quieras dentro de la carpeta del target (p. ej. `notes/` o `meta/`).

| Herramienta | Cómo se invoca para generar el JSON | Forma que reconoce | Qué aporta |
|---|---|---|---|
| [`pathraider`](https://github.com/theoffsecgirl/pathraider) | `pathraider ... --json-output notes/pathraider.json` | `{"tool": "pathraider", "targets": {url: [hallazgos]}}` | Columna "Otro" — 🟢 si la lista de hallazgos de esa URL está vacía, 🟡 si no |
| [`webxray`](https://github.com/theoffsecgirl/webxray) | `webxray ... --json-output notes/webxray.json` | lista plana de dicts con `type` + `url` | XSS → Client-Side/XSS · SQLi → Otro · cabecera ausente → Misconfig. **Nunca produce 🟢**: su JSON solo registra hallazgos, no "escaneado sin nada que reportar" |
| [`takeovflow`](https://github.com/theoffsecgirl/takeovflow) | `takeovflow ... --json-output notes/takeovflow.json` | `{"tool": "takeovflow", "domains": {...}}` | Columna Misconfig — 🟡 por cada entrada en `potential_takeovers`, 🟢 para el resto de subdominios resueltos |
| [`findings-hub`](https://github.com/theoffsecgirl/findings-hub) | `findings-hub analyze ... --json > notes/findings-hub.json` (ojo: **no** escribe fichero por su cuenta, hay que redirigir tú el stdout) | `{"modo": "analyze", "hallazgos": [...]}` | Columna inferida de `tags`/`description` de cada hallazgo (o "Otro" si no matchea ninguna); endpoint extraído de la URL dentro de `line` si la hay, si no `source_file (línea N)` |

Cualquier otro `.json` que haya en la carpeta del target (paquetes npm, configs, exports
de Caido, etc.) se ignora en silencio — no es un error, solo no matchea ninguna forma
conocida. Si un `.json` esperado está corrupto o no se puede leer, se avisa por stderr y
`reconmind` sigue con el resto sin romper `hunt-start`.

El pipeline determinista de recon (scripts de descubrimiento de subdominios/URLs/params)
no genera JSON con veredicto por endpoint — solo listas de texto plano (`http/live.txt`,
`http/urls_clean.txt`, `fuzz/params.txt`...). `reconmind` sí las usa para contar la
superficie conocida total en el resumen (revisa la constante `SURFACE_FILES` dentro de
`reconmind.py` si esa estructura de carpetas cambia), pero no genera filas por sí solas:
una fila en la matriz solo aparece cuando una herramienta dejó una señal real.

---

## Qué NO hace (todavía)

Nada de esto está en el MVP — es fase futura, a decidir tras usar esto un tiempo:

- Comandos de consulta interactivos.
- Registro manual de pruebas hechas a mano en Caido/Burp.
- Lenguaje natural / correlación con LLM.
- Correlación cross-target.

---

## Tests

```bash
cd reconmind
python3 -m pip install pytest   # o: pip install -e ".[dev]"
pytest
```

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas. `reconmind` en sí mismo
nunca toca la red — solo lee JSON local que tus otras herramientas ya generaron bajo
autorización.

---

## Licencia

MIT · [theoffsecgirl](https://github.com/theoffsecgirl)
