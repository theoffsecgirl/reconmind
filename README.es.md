<div align="center">

# reconmind

**Índice pasivo de cobertura de recon para bug bounty — qué ya probaste, y dónde**

![Language](https://img.shields.io/badge/Python-3.12+-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-0.2.0-9E4AFF?style=flat-square)
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

En un target grande se acumula output de recon de un montón de herramientas distintas, y
es fácil perder de vista qué endpoint/parámetro ya se probó para qué clase de
vulnerabilidad. No existe un "code coverage" equivalente para bug bounty. `reconmind` lee
el JSON que esas herramientas ya generan y escribe una matriz Markdown,
`notes/coverage.md`, dentro de la propia carpeta del target.

`reconmind` **no escanea nada, no hace ni una petición, no decide nada por ti**. Solo lee
JSON que ya existe en disco y lo resume. Es una vista, no una herramienta que se ejecuta.

Lee dos tipos de entrada:

1. **El esquema genérico** (ver abajo) — un pequeño contrato público en JSON que
   cualquier herramienta, tuya o de un tercero, puede emitir. Esta es la forma principal
   de conectar algo a `reconmind`, y `reconmind` no necesita conocer la herramienta de
   antemano para entenderlo.
2. **Unos pocos adaptadores conocidos** para herramientas mías que no hablan ese esquema
   — [webxray](https://github.com/theoffsecgirl/webxray),
   [takeovflow](https://github.com/theoffsecgirl/takeovflow),
   [findings-hub](https://github.com/theoffsecgirl/findings-hub). Son un añadido, no un
   requisito — si no usas ninguna de estas, el esquema genérico es lo único que
   necesitas.

> Nota: `notes/coverage.md` en sí se genera en español — es una herramienta personal
> integrada en un flujo de trabajo de hunting en español. El código, este README y los
> tests están en inglés/bilingüe, pero el output coincide con el resto de las notas
> donde vive.

---

## Cero fricción: no es un comando que tengas que recordar

`reconmind` no se usa a mano. Se engancha al final de tu función `hunt-start` existente y
corre en silencio cada vez que arrancas una sesión — igual que ya hacen otros pasos de
recon. Nunca bloquea la sesión: si algo falla, avisa por stderr y sigue.

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

## El esquema genérico — cómo conectar cualquier herramienta

Este es el contrato. Cualquier herramienta, script o pipeline de `jq` de andar por casa
puede producir un JSON con esta forma, dejarlo en cualquier sitio dentro de la carpeta
del target, y `reconmind` lo recogerá sin necesidad de conocer la herramienta por su
nombre:

```json
{
  "tool": "nombre-de-tu-herramienta",
  "findings": [
    {
      "url": "https://ejemplo.com/endpoint",
      "class": "xss",
      "status": "suspicious",
      "detail": "texto libre opcional"
    }
  ]
}
```

- **`tool`** — texto libre, se muestra en la nota de cada hallazgo y en el conteo de
  fuentes al principio de `coverage.md`.
- **`class`** — uno de: `auth`, `access-control`, `idor`, `api`, `business-logic`, `xss`,
  `misconfig`, `ssrf`, `other`. Mapean 1:1 a las 8 categorías priorizadas más una columna
  comodín "Otro". Un valor no reconocido cae en `other` en vez de romper el parseo.
- **`status`** — uno de: `clean`, `suspicious`, `confirmed`. Un valor no reconocido cae
  en `suspicious`.
- **`detail`** — texto libre opcional que se muestra en la celda.

Cualquier campo que reconmind no reconozca se ignora; un hallazgo sin `url` se descarta.
Un JSON mal formado nunca rompe la ejecución — se avisa por stderr y se salta.

**Sobre `"confirmed"`:** a diferencia de los adaptadores conocidos de abajo (que nunca
afirman confirmado — ver "Sobre el estado confirmado" más abajo), el esquema genérico
**sí** respeta `"confirmed"` tal cual se declare. Es una diferencia deliberada: aquí una
herramienta está haciendo una afirmación explícita bajo su propia responsabilidad, no
reconmind infiriendo algo de una heurística. Si tu herramienta solo reporta candidatos
sin verificar, usa `"suspicious"` — no declares `"confirmed"` salvo que lo hayas
validado de verdad.

Para que esa distinción quede visible donde importa, `reconmind` añade un aviso a
cualquier celda 🔴 confirmado que venga del esquema genérico: `— confirmado declarado
por <herramienta>, no validado por reconmind`. Nunca verás ese aviso en una celda
confirmada que venga de uno de los adaptadores conocidos, porque esos jamás producen
una — ver abajo.

---

## Formato de salida: `notes/coverage.md`

Se abre como cualquier otro fichero de notas — no se "ejecuta". Solo lista endpoints que
ya tienen alguna señal de herramienta (con miles de URLs por target, una tabla con una
fila por endpoint sin tocar sería ilegible); el resto se resume en una línea, igual que
un reporte de code coverage real tampoco imprime cada línea sin cubrir.

Ejemplo (dominios ficticios, mezclando el esquema genérico con un adaptador conocido):

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

Las columnas son las 8 categorías priorizadas (Auth, Access Control, IDOR, API Security,
Business Logic, Client-Side/XSS, Misconfig, SSRF) más una novena, "Otro", para lo que no
encaja en esas 8.

### Sobre el estado confirmado

Los tres adaptadores conocidos (`webxray`, `takeovflow`, `findings-hub`) nunca escriben
una celda 🔴 confirmado por su cuenta. Ninguno valida impacto — son heurísticas
(`webxray`: payload reflejado, no verificado; `takeovflow`: literalmente lo llama
`potential_takeovers`; `findings-hub`: coincidencia de patrón, no explotación). Marcar
confirmado automáticamente desde una heurística rompería la disciplina básica de bug
bounty de no llamar vulnerabilidad a algo sin impacto validado.

El esquema genérico es distinto: ahí `"confirmed"` es algo que la propia herramienta
afirma, y `reconmind` solo renderiza lo que dice el contrato — ver arriba. Pero no lo
renderiza igual que se vería un hipotético estado "confirmado por reconmind" a futuro:
toda celda 🔴 que venga del esquema genérico lleva el aviso `— confirmado declarado por
<herramienta>, no validado por reconmind` justo ahí en la celda, así que se lee
visualmente distinta de un 🔴 a secas y nadie confunde la afirmación de un tercero con
algo que reconmind mismo verificó.

### Privacidad

`reconmind` nunca recorre `loot/`, `.creds/`, `.git/`, `.venv`/`venv/`, `node_modules/`
ni `.claude/` dentro de la carpeta del target, aunque contengan `.json`. Solo mira el
resto.

---

## Adaptadores conocidos

Vienen incluidos con `reconmind` para herramientas mías que son anteriores al esquema
genérico y no lo hablan. Son un añadido, no el camino principal — si ninguna de estas es
tuya, simplemente emite el esquema genérico desde lo que uses.

| Herramienta | Cómo se invoca para generar el JSON | Forma que reconoce | Qué aporta |
|---|---|---|---|
| [`webxray`](https://github.com/theoffsecgirl/webxray) | `webxray ... --json-output notes/webxray.json` | lista plana de dicts con `type` + `url` | XSS → Client-Side/XSS · SQLi → Otro · cabecera ausente → Misconfig. **Nunca produce 🟢**: su JSON solo registra hallazgos, no "escaneado sin nada que reportar" |
| [`takeovflow`](https://github.com/theoffsecgirl/takeovflow) | `takeovflow ... --json-output notes/takeovflow.json` | `{"tool": "takeovflow", "domains": {...}}` | Columna Misconfig — 🟡 por cada entrada en `potential_takeovers`, 🟢 para el resto de subdominios resueltos |
| [`findings-hub`](https://github.com/theoffsecgirl/findings-hub) | `findings-hub analyze ... --json > notes/findings-hub.json` (ojo: **no** escribe fichero por su cuenta, hay que redirigir tú el stdout) | `{"modo": "analyze", "hallazgos": [...]}` | Columna inferida de `tags`/`description` de cada hallazgo (o "Otro" si no matchea ninguna); endpoint extraído de la URL dentro de `line` si la hay, si no `source_file (línea N)` |

Cualquier otro `.json` que haya en la carpeta del target y no encaje ni con el esquema
genérico ni con estas tres formas se ignora en silencio — no es un error, simplemente no
matchea nada que reconmind entienda. Si un `.json` esperado está corrupto o no se puede
leer, se avisa por stderr y `reconmind` sigue con el resto sin romper `hunt-start`.

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
