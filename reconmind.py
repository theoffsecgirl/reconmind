#!/usr/bin/env python3
"""reconmind — actualiza notes/coverage.md a partir del JSON que ya generan tus herramientas.

Se invoca en silencio desde `hunt-start` al final de cada arranque de sesion. Nunca debe
bloquear esa sesion: cualquier fichero inesperado o ausente se avisa por stderr y se ignora.

Uso:
    reconmind <carpeta-del-target>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

COLUMNAS = [
    "Auth",
    "Access Control",
    "IDOR",
    "API Security",
    "Business Logic",
    "Client-Side/XSS",
    "Misconfig",
    "SSRF",
    "Otro",
]

# Carpetas que reconmind nunca recorre: privacidad (loot/.creds) y ruido (venvs, vcs).
EXCLUDE_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".claude", "loot", ".creds"}

# Ficheros de superficie conocida del pipeline determinista (solo para contar, nunca para
# generar filas por si solos — una fila solo aparece si una herramienta dejo una señal).
SURFACE_FILES = [
    "http/live.txt",
    "http/urls_clean.txt",
    "http/urls.txt",
    "http/api_candidates.txt",
    "http/graphql.txt",
]

ICONOS = {"limpio": "🟢", "sospechoso": "🟡", "confirmado": "🔴", "no_probado": "⬜"}


@dataclass
class Signal:
    """Una señal normalizada extraida del JSON de una herramienta.

    `estado` es siempre "limpio" o "sospechoso": reconmind nunca marca "confirmado" por su
    cuenta (ninguna de estas herramientas valida impacto, solo dan heuristicas/candidatos) —
    ver README, seccion "Por que no hay auto-confirmado".
    """

    endpoint: str
    columna: str
    estado: str
    nota: str
    fuente: str


# ─── Descubrimiento de ficheros JSON ────────────────────────────────────────


def encontrar_json(target_dir: Path) -> list[Path]:
    encontrados = []
    for path in target_dir.rglob("*.json"):
        relativo = path.relative_to(target_dir)
        if any(parte in EXCLUDE_DIRS for parte in relativo.parts):
            continue
        encontrados.append(path)
    return sorted(encontrados)


def _cargar(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        print(f"[reconmind] aviso: no se pudo leer {path}: {exc}", file=sys.stderr)
        return None


# ─── Parsers por herramienta ─────────────────────────────────────────────────
# Cada parser recibe el JSON ya cargado y devuelve una lista de Signal normalizadas.
# Ningun parser lanza excepcion por datos faltantes: usa .get() con defaults en todo.


def parse_pathraider(data: dict, fuente: str) -> list[Signal]:
    """pathraider --json-output: {"tool": "pathraider", "targets": {url: [hallazgos]}}."""
    señales = []
    for target_url, hallazgos in data.get("targets", {}).items():
        if not hallazgos:
            señales.append(
                Signal(target_url, "Otro", "limpio", "pathraider: sin hallazgos (LFI/traversal)", fuente)
            )
            continue
        rutas = ", ".join(sorted({h.get("path", "?") for h in hallazgos})[:2])
        señales.append(
            Signal(target_url, "Otro", "sospechoso", f"pathraider: posible traversal ({rutas})", fuente)
        )
    return señales


_WEBXRAY_XSS = {"xss", "waf_xss", "waf_xss_form"}
_WEBXRAY_SQLI = {"sqli_get", "sqli_post"}


def parse_webxray(data: list, fuente: str) -> list[Signal]:
    """webxray --json-output: lista plana de hallazgos, sin envoltorio.

    Importante: esta lista solo contiene hallazgos, nunca "objetivo escaneado sin nada que
    reportar" — por eso webxray jamas produce señales "limpio" (ver README).
    """
    señales = []
    for h in data:
        tipo = h.get("type")
        url = h.get("url", "?")
        if tipo in _WEBXRAY_XSS:
            param = h.get("parameter", "?")
            señales.append(
                Signal(url, "Client-Side/XSS", "sospechoso", f"webxray: {tipo} en param `{param}`", fuente)
            )
        elif tipo in _WEBXRAY_SQLI:
            param = h.get("parameter", "?")
            señales.append(Signal(url, "Otro", "sospechoso", f"webxray: {tipo} en param `{param}`", fuente))
        elif tipo == "missing_header":
            header = h.get("header", "?")
            señales.append(
                Signal(url, "Misconfig", "sospechoso", f"webxray: cabecera ausente `{header}`", fuente)
            )
    return señales


def parse_takeovflow(data: dict, fuente: str) -> list[Signal]:
    """takeovflow --json-output: {"tool": "takeovflow", "domains": {dominio: {...}}}."""
    señales = []
    for _dominio, info in data.get("domains", {}).items():
        potenciales = info.get("potential_takeovers", [])
        marcados: set[str] = set()
        for hallazgo in potenciales:
            raw = hallazgo.get("raw", "")
            sub = raw.split()[0] if raw.split() else _dominio
            marcados.add(sub)
            origen = hallazgo.get("source", "?")
            severidad = hallazgo.get("severity", "?")
            señales.append(
                Signal(
                    sub,
                    "Misconfig",
                    "sospechoso",
                    f"takeovflow: posible takeover ({origen}, severidad {severidad})",
                    fuente,
                )
            )
        for sub in info.get("resolved", []):
            if sub not in marcados:
                señales.append(
                    Signal(sub, "Misconfig", "limpio", "takeovflow: resuelto, sin huella de takeover", fuente)
                )
    return señales


_URL_RE = re.compile(r"https?://\S+")

# Orden importa: primer match gana. Claves en minuscula, buscadas por substring.
_TAG_A_COLUMNA = [
    ("idor", "IDOR"),
    ("access control", "Access Control"),
    ("acceso", "Access Control"),
    ("auth", "Auth"),
    ("ssrf", "SSRF"),
    ("cross-site", "Client-Side/XSS"),
    ("xss", "Client-Side/XSS"),
    ("business", "Business Logic"),
    ("logica de negocio", "Business Logic"),
    ("api", "API Security"),
]


def _columna_para_hallazgo(h: dict) -> str:
    texto = " ".join([h.get("description", ""), *h.get("tags", [])]).lower()
    for clave, columna in _TAG_A_COLUMNA:
        if clave in texto:
            return columna
    return "Misconfig" if h.get("tool") in {"nmap", "http_generic"} else "Otro"


def parse_findings_hub(data: dict, fuente: str) -> list[Signal]:
    """findings-hub `analyze --json`: {"modo", ..., "hallazgos": [Finding, ...]}.

    findings-hub no escribe fichero por su cuenta (imprime a stdout) — hay que
    redirigirlo tu a un .json dentro del target para que reconmind lo vea. Ver README.
    """
    señales = []
    for h in data.get("hallazgos", []):
        linea = h.get("line", "")
        m = _URL_RE.search(linea)
        if m:
            endpoint = m.group(0)
        else:
            origen = h.get("source_file") or h.get("tool") or "desconocido"
            endpoint = f"{origen} (linea {h.get('line_number', '?')})"
        columna = _columna_para_hallazgo(h)
        nota = f"findings-hub: {h.get('rule_id', '?')} ({h.get('severity', '?')}/{h.get('confidence', '?')})"
        señales.append(Signal(endpoint, columna, "sospechoso", nota, fuente))
    return señales


def _sniff(data: object) -> str | None:
    """Identifica que herramienta produjo este JSON por su forma, no por el nombre del fichero."""
    if isinstance(data, dict) and data.get("tool") == "pathraider" and "targets" in data:
        return "pathraider"
    if isinstance(data, dict) and data.get("tool") == "takeovflow" and "domains" in data:
        return "takeovflow"
    if isinstance(data, dict) and "hallazgos" in data and "modo" in data:
        return "findings-hub"
    if isinstance(data, list) and data and all(isinstance(x, dict) and "type" in x and "url" in x for x in data):
        return "webxray"
    return None


PARSERS = {
    "pathraider": parse_pathraider,
    "webxray": parse_webxray,
    "takeovflow": parse_takeovflow,
    "findings-hub": parse_findings_hub,
}


def recolectar_señales(target_dir: Path) -> tuple[list[Signal], dict[str, int], int]:
    señales: list[Signal] = []
    conteo_por_herramienta: dict[str, int] = {}
    ignorados = 0
    for path in encontrar_json(target_dir):
        data = _cargar(path)
        if data is None:
            continue
        herramienta = _sniff(data)
        if herramienta is None:
            ignorados += 1
            continue
        fuente = str(path.relative_to(target_dir))
        señales.extend(PARSERS[herramienta](data, fuente))
        conteo_por_herramienta[herramienta] = conteo_por_herramienta.get(herramienta, 0) + 1
    return señales, conteo_por_herramienta, ignorados


# ─── Superficie conocida (solo cuenta, no genera filas) ─────────────────────


def contar_superficie_conocida(target_dir: Path) -> int:
    vistos: set[str] = set()
    for rel in SURFACE_FILES:
        f = target_dir / rel
        if f.is_file():
            try:
                for linea in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                    linea = linea.strip()
                    if linea:
                        vistos.add(linea)
            except OSError:
                continue
    return len(vistos)


# ─── Construccion y render de la matriz ──────────────────────────────────────


def construir_matriz(señales: list[Signal]) -> dict[str, dict[str, list[Signal]]]:
    matriz: dict[str, dict[str, list[Signal]]] = {}
    for s in señales:
        matriz.setdefault(s.endpoint, {}).setdefault(s.columna, []).append(s)
    return matriz


def _celda(señales_celda: list[Signal] | None) -> str:
    if not señales_celda:
        return ICONOS["no_probado"]
    sospechosas = [s.nota for s in señales_celda if s.estado == "sospechoso"]
    if sospechosas:
        return f"{ICONOS['sospechoso']} " + "; ".join(sospechosas)
    limpias = [s.nota for s in señales_celda if s.estado == "limpio"]
    return f"{ICONOS['limpio']} " + "; ".join(limpias)


def render_markdown(
    target_name: str,
    target_dir: Path,
    señales: list[Signal],
    conteo_por_herramienta: dict[str, int],
    json_ignorados: int,
) -> str:
    ahora = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    matriz = construir_matriz(señales)
    superficie_conocida = contar_superficie_conocida(target_dir)

    lineas = [
        f"# Coverage — {target_name}",
        f"> Generado por reconmind el {ahora}. No editar a mano — se sobreescribe en cada `hunt-start`.",
        "",
    ]

    if conteo_por_herramienta:
        fuentes = " · ".join(f"{k}({v})" for k, v in sorted(conteo_por_herramienta.items()))
        lineas.append(f"JSON de herramientas encontrados: {fuentes}")
    else:
        lineas.append("JSON de herramientas encontrados: ninguno todavia.")
    if json_ignorados:
        lineas.append(f"({json_ignorados} fichero(s) .json en la carpeta con formato no reconocido, ignorados)")
    lineas.append("")
    lineas.append(
        "Leyenda: ⬜ no probado · 🟢 probado-limpio · 🟡 probado-sospechoso · "
        "🔴 confirmado (reservado — este script nunca lo marca, ver README)"
    )
    lineas.append("")

    if not matriz:
        lineas.append("Ningun endpoint con señal de herramienta todavia.")
    else:
        lineas.append("| Endpoint | " + " | ".join(COLUMNAS) + " |")
        lineas.append("|---|" + "|".join(["---"] * len(COLUMNAS)) + "|")
        for endpoint in sorted(matriz):
            fila = [endpoint] + [_celda(matriz[endpoint].get(col)) for col in COLUMNAS]
            lineas.append("| " + " | ".join(fila) + " |")

    tocados = len(matriz)
    total_sospechoso = sum(1 for s in señales if s.estado == "sospechoso")
    total_limpio = sum(1 for s in señales if s.estado == "limpio")
    lineas.append("")
    lineas.append("## Resumen")
    if superficie_conocida:
        sin_tocar = max(superficie_conocida - tocados, 0)
        lineas.append(
            f"- {superficie_conocida} endpoints conocidos (http/*.txt) · {tocados} con alguna señal de herramienta"
            f" · {sin_tocar} sin tocar (⬜)"
        )
    else:
        lineas.append(
            f"- {tocados} endpoints con alguna señal de herramienta "
            "(no se encontro http/live.txt ni http/urls_clean.txt para contar la superficie total)"
        )
    lineas.append(f"- 🟡 sospechoso: {total_sospechoso} · 🟢 limpio: {total_limpio} · 🔴 confirmado: 0")

    return "\n".join(lineas) + "\n"


# ─── CLI ──────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Actualiza notes/coverage.md a partir del JSON de tus herramientas de recon."
    )
    parser.add_argument("target_dir", help="Carpeta del target, p.ej. $HUNTING_HOME/targets/<programa>")
    args = parser.parse_args(argv)

    target_dir = Path(args.target_dir).expanduser().resolve()
    if not target_dir.is_dir():
        print(f"[reconmind] '{target_dir}' no es una carpeta. Nada que hacer.", file=sys.stderr)
        return 1

    señales, conteo, ignorados = recolectar_señales(target_dir)
    salida = render_markdown(target_dir.name, target_dir, señales, conteo, ignorados)

    notes_dir = target_dir / "notes"
    try:
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "coverage.md").write_text(salida, encoding="utf-8")
    except OSError as exc:
        print(f"[reconmind] no se pudo escribir notes/coverage.md: {exc}", file=sys.stderr)
        return 1

    reconocidos = sum(conteo.values())
    print(f"[reconmind] coverage.md actualizado — {len(señales)} señales de {reconocidos} fichero(s) JSON reconocidos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
