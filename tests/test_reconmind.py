"""Tests de reconmind. Todos los datos son sinteticos (example.com / testtarget.io)."""
import json

import reconmind as rm

# ─── Sniffing ────────────────────────────────────────────────────────────────


def test_sniff_generico():
    data = {"tool": "cualquier-cosa", "findings": [{"url": "https://example.com/x", "class": "ssrf"}]}
    assert rm._sniff(data) == "generico"


def test_sniff_generico_gana_sobre_adaptadores_conocidos_si_ambos_encajaran():
    # findings-hub exige "hallazgos"+"modo"; si un JSON tuviera "tool"+"findings" ademas de
    # eso, el esquema generico gana por ir primero en _sniff.
    data = {"tool": "x", "findings": [], "hallazgos": [], "modo": "analyze"}
    assert rm._sniff(data) == "generico"


def test_sniff_takeovflow():
    data = {"tool": "takeovflow", "version": "1.5.0", "domains": {"example.com": {}}}
    assert rm._sniff(data) == "takeovflow"


def test_sniff_findings_hub():
    data = {"modo": "analyze", "hallazgos": []}
    assert rm._sniff(data) == "findings-hub"


def test_sniff_webxray():
    data = [{"type": "xss", "url": "https://example.com/search", "parameter": "q"}]
    assert rm._sniff(data) == "webxray"


def test_sniff_lista_vacia_no_reconocida():
    assert rm._sniff([]) is None


def test_sniff_json_desconocido():
    assert rm._sniff({"foo": "bar"}) is None
    assert rm._sniff(["algo", "que", "no", "es", "una", "herramienta"]) is None


# ─── Parsers ─────────────────────────────────────────────────────────────────


def test_parse_generico_mapea_clase_y_estado():
    data = {
        "tool": "mi-escaner-random",
        "findings": [
            {"url": "https://example.com/admin", "class": "access-control", "status": "suspicious", "detail": "endpoint sin auth"},
            {"url": "https://example.com/safe", "class": "misconfig", "status": "clean"},
            {"url": "https://example.com/confirmed", "class": "ssrf", "status": "confirmed", "detail": "SSRF validado a mano"},
        ],
    }
    señales = rm.parse_generico(data, "notes/tercero.json")
    por_endpoint = {s.endpoint: s for s in señales}
    assert por_endpoint["https://example.com/admin"].columna == "Access Control"
    assert por_endpoint["https://example.com/admin"].estado == "sospechoso"
    assert por_endpoint["https://example.com/safe"].estado == "limpio"
    # A diferencia de los adaptadores conocidos, el esquema generico SI respeta "confirmed".
    assert por_endpoint["https://example.com/confirmed"].estado == "confirmado"
    assert "mi-escaner-random" in por_endpoint["https://example.com/confirmed"].nota
    # ...pero la celda deja explicito que es una afirmacion de terceros, no una validacion propia.
    assert "no validado por reconmind" in por_endpoint["https://example.com/confirmed"].nota
    # Los estados "sospechoso"/"limpio" del esquema generico NO llevan ese disclaimer.
    assert "no validado por reconmind" not in por_endpoint["https://example.com/admin"].nota
    assert "no validado por reconmind" not in por_endpoint["https://example.com/safe"].nota


def test_parse_generico_clase_desconocida_cae_en_otro():
    data = {"tool": "x", "findings": [{"url": "https://example.com/y", "class": "algo-que-no-existe", "status": "suspicious"}]}
    señales = rm.parse_generico(data, "f")
    assert señales[0].columna == "Otro"


def test_parse_generico_status_desconocido_cae_en_sospechoso():
    data = {"tool": "x", "findings": [{"url": "https://example.com/y", "class": "xss", "status": "algo-raro"}]}
    señales = rm.parse_generico(data, "f")
    assert señales[0].estado == "sospechoso"


def test_parse_generico_ignora_findings_sin_url():
    data = {"tool": "x", "findings": [{"class": "xss", "status": "clean"}, {"url": "", "class": "xss"}, "no-es-un-dict"]}
    assert rm.parse_generico(data, "f") == []


def test_parse_webxray_tipos():
    data = [
        {"type": "xss", "url": "https://example.com/search", "parameter": "q", "payload": "<script>", "status": 200},
        {"type": "sqli_get", "url": "https://example.com/item", "parameter": "id", "payload": "' OR 1=1", "status": 200},
        {"type": "missing_header", "url": "https://example.com/", "header": "Content-Security-Policy"},
    ]
    señales = rm.parse_webxray(data, "notes/webxray.json")
    columnas = {s.endpoint: s.columna for s in señales}
    assert columnas["https://example.com/search"] == "Client-Side/XSS"
    assert columnas["https://example.com/item"] == "Otro"
    assert columnas["https://example.com/"] == "Misconfig"
    assert all(s.estado == "sospechoso" for s in señales)


def test_parse_webxray_nunca_produce_limpio():
    # webxray no registra "escaneado sin hallazgos" en su JSON -> lista vacia no da señales.
    assert rm.parse_webxray([], "notes/webxray.json") == []


def test_parse_takeovflow_confirmado_vs_limpio():
    data = {
        "tool": "takeovflow",
        "domains": {
            "example.com": {
                "resolved": ["old-shop.example.com", "www.example.com"],
                "potential_takeovers": [
                    {"source": "subjack", "severity": "HIGH", "raw": "old-shop.example.com [potentially vulnerable] [github] [HTTPS]"}
                ],
            }
        },
    }
    señales = rm.parse_takeovflow(data, "notes/takeovflow.json")
    por_endpoint = {s.endpoint: s for s in señales}
    assert por_endpoint["old-shop.example.com"].estado == "sospechoso"
    assert por_endpoint["www.example.com"].estado == "limpio"
    # Nunca "confirmado", ni con severidad HIGH de subjack.
    assert all(s.estado != "confirmado" for s in señales)


def test_parse_findings_hub_extrae_url_de_la_linea():
    data = {
        "modo": "analyze",
        "hallazgos": [
            {
                "rule_id": "http-missing-auth-header",
                "line_number": 12,
                "line": "GET https://example.com/api/internal/users 200",
                "severity": "alta",
                "confidence": "media",
                "description": "posible falta de control de acceso en endpoint interno",
                "tags": ["access-control"],
                "tool": "http_generic",
            },
            {
                "rule_id": "nmap-open-mgmt-port",
                "line_number": 3,
                "line": "9200/tcp open  elasticsearch",
                "severity": "media",
                "confidence": "baja",
                "description": "puerto de gestion expuesto",
                "tags": [],
                "tool": "nmap",
                "source_file": "recon/nmap-example.txt",
            },
        ],
    }
    señales = rm.parse_findings_hub(data, "notes/findings-hub.json")
    assert señales[0].endpoint == "https://example.com/api/internal/users"
    assert señales[0].columna == "Access Control"
    assert señales[1].endpoint == "recon/nmap-example.txt (linea 3)"
    assert señales[1].columna == "Misconfig"


# ─── Matriz y render ──────────────────────────────────────────────────────────


def test_construir_matriz_agrupa_por_endpoint_y_columna():
    señales = [
        rm.Signal("https://example.com/a", "Client-Side/XSS", "sospechoso", "nota1", "f1"),
        rm.Signal("https://example.com/a", "Misconfig", "limpio", "nota2", "f2"),
        rm.Signal("https://example.com/b", "Otro", "sospechoso", "nota3", "f3"),
    ]
    matriz = rm.construir_matriz(señales)
    assert set(matriz) == {"https://example.com/a", "https://example.com/b"}
    assert "Client-Side/XSS" in matriz["https://example.com/a"]
    assert "Misconfig" in matriz["https://example.com/a"]


def test_celda_sospechoso_gana_sobre_limpio():
    celda = [
        rm.Signal("e", "Otro", "limpio", "limpio-nota", "f"),
        rm.Signal("e", "Otro", "sospechoso", "sospechoso-nota", "f"),
    ]
    resultado = rm._celda(celda)
    assert resultado.startswith(rm.ICONOS["sospechoso"])
    assert "sospechoso-nota" in resultado


def test_celda_confirmado_gana_sobre_todo():
    celda = [
        rm.Signal("e", "Otro", "limpio", "limpio-nota", "f"),
        rm.Signal("e", "Otro", "sospechoso", "sospechoso-nota", "f"),
        rm.Signal("e", "Otro", "confirmado", "confirmado-nota", "f"),
    ]
    resultado = rm._celda(celda)
    assert resultado.startswith(rm.ICONOS["confirmado"])
    assert "confirmado-nota" in resultado


def test_celda_vacia_es_no_probado():
    assert rm._celda(None) == rm.ICONOS["no_probado"]
    assert rm._celda([]) == rm.ICONOS["no_probado"]


def test_render_markdown_sin_señal_confirmada_no_la_inventa(tmp_path):
    señales = [
        rm.Signal("https://example.com/x", "Otro", "sospechoso", "algo raro", "notes/webxray.json"),
    ]
    salida = rm.render_markdown("testtarget", tmp_path, señales, {"webxray": 1}, 0)
    cuerpo = salida.split("## Resumen")[0]
    # El emoji de confirmado solo debe aparecer en la linea de leyenda, nunca en una fila de datos,
    # si ninguna señal recibida es "confirmado".
    assert cuerpo.count(rm.ICONOS["confirmado"]) == 1  # la mencion en la leyenda
    assert "| " + rm.ICONOS["confirmado"] not in cuerpo


def test_render_markdown_respeta_confirmado_declarado_por_esquema_generico(tmp_path):
    señales = [
        rm.Signal("https://example.com/x", "SSRF", "confirmado", "ssrf validado a mano", "notes/tercero.json"),
    ]
    salida = rm.render_markdown("testtarget", tmp_path, señales, {"generico": 1}, 0)
    cuerpo = salida.split("## Resumen")[0]
    assert "| " + rm.ICONOS["confirmado"] in cuerpo
    assert "🔴 confirmado: 1" in salida


def test_end_to_end_confirmado_del_esquema_generico_lleva_disclaimer_en_la_celda(tmp_path):
    # pipeline completo: parse_generico -> construir_matriz -> render_markdown
    data = {
        "tool": "mi-escaner-random",
        "findings": [
            {"url": "https://example.com/admin", "class": "access-control", "status": "confirmed", "detail": "acceso sin auth validado a mano"},
        ],
    }
    señales = rm.parse_generico(data, "notes/tercero.json")
    salida = rm.render_markdown("testtarget", tmp_path, señales, {"generico": 1}, 0)
    cuerpo = salida.split("## Resumen")[0]
    fila = next(linea for linea in cuerpo.splitlines() if linea.startswith("| https://example.com/admin"))
    assert rm.ICONOS["confirmado"] in fila
    assert "confirmado declarado por mi-escaner-random, no validado por reconmind" in fila


def test_render_markdown_sin_señales_no_rompe(tmp_path):
    salida = rm.render_markdown("testtarget", tmp_path, [], {}, 0)
    assert "Ningun endpoint con señal de herramienta todavia." in salida


# ─── Descubrimiento de JSON e integracion completa ────────────────────────────


def test_encontrar_json_excluye_loot_y_creds(tmp_path):
    (tmp_path / "notes").mkdir()
    (tmp_path / "loot").mkdir()
    (tmp_path / ".creds").mkdir()
    (tmp_path / "notes" / "webxray.json").write_text("[]")
    (tmp_path / "loot" / "secreto.json").write_text("[]")
    (tmp_path / ".creds" / "testtarget.json").write_text("{}")

    encontrados = rm.encontrar_json(tmp_path)
    relativos = {p.relative_to(tmp_path).as_posix() for p in encontrados}
    assert relativos == {"notes/webxray.json"}


def test_json_invalido_no_rompe_la_recoleccion(tmp_path, capsys):
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "roto.json").write_text("{esto no es json valido")

    señales, conteo, ignorados = rm.recolectar_señales(tmp_path)
    assert señales == []
    assert conteo == {}
    err = capsys.readouterr().err
    assert "no se pudo leer" in err


def test_json_de_formato_desconocido_se_ignora_en_silencio(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "algo", "version": "1.0.0"}))

    señales, conteo, ignorados = rm.recolectar_señales(tmp_path)
    assert señales == []
    assert ignorados == 1


def test_main_end_to_end_genera_coverage_md(tmp_path):
    target_dir = tmp_path / "testtarget"
    (target_dir / "notes").mkdir(parents=True)
    (target_dir / "http").mkdir()
    (target_dir / "http" / "live.txt").write_text("https://example.com/\nhttps://api.example.com/\n")

    webxray_json = [
        {"type": "xss", "url": "https://example.com/search", "parameter": "q", "payload": "<script>", "status": 200}
    ]
    (target_dir / "notes" / "webxray.json").write_text(json.dumps(webxray_json))

    codigo = rm.main([str(target_dir)])
    assert codigo == 0

    coverage = (target_dir / "notes" / "coverage.md").read_text(encoding="utf-8")
    assert "# Coverage — testtarget" in coverage
    assert "https://example.com/search" in coverage
    assert "webxray(1)" in coverage
    assert "2 endpoints conocidos" in coverage


def test_main_carpeta_inexistente_devuelve_error(tmp_path, capsys):
    codigo = rm.main([str(tmp_path / "no-existe")])
    assert codigo == 1
    assert "no es una carpeta" in capsys.readouterr().err
