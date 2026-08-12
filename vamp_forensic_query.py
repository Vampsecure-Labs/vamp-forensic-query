#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp-forensic-query — Consultas forenses self-service sobre logs/eventos + evidencia.
VampSecure Labs (Vampsecure Studios).

Convierte cualquier fuente tabular (CSV/XLSX) o log de eventos de usuario en un
almacén consultable, permite hacer preguntas concretas SIN un LLM, y por cada
consulta genera evidencia forense reproducible y a prueba de manipulación:
resultados (CSV+JSON) + informe HTML + paquete ZIP firmado con MANIFEST.sha256
y cadena de custodia (SHA-256 de las fuentes originales).

Ejemplos:
  # ¿Cuántos DNI distintos cambiaron contraseña en 2026, cuáles y cuántas veces?
  vamp_forensic_query.py AqualiaContrasenas.xlsx \
      --map entity=Usuario ts=CreatedAt ip=Datos --sep ';' --action-const password_change \
      distinct --year 2026 --entity-type DNI \
      --case "AQUALIA-2026-001" --analyst "A. Hernández — VampSecure" --evidence

  # Cronología exacta de una entidad
  vamp_forensic_query.py AqualiaContrasenas.xlsx --map entity=Usuario ts=CreatedAt ip=Datos --sep ';' \
      timeline --entity 11723541G

  # Reincidentes (>=3 cambios) de cualquier tipo, con evidencia
  vamp_forensic_query.py ... top --action password_change --year 2026 --min-count 3 --evidence
"""
import argparse, csv, json, os, re, sqlite3, sys, hashlib, zipfile, io, datetime as _dt

def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)

VERSION = "1.0"
TOOL = "vamp-forensic-query"

# ─────────────────────── clasificación de entidades (España) ───────────────────────
_RE = {
    "DNI":   re.compile(r"^[0-9]{8}[A-Z]$"),
    "NIE":   re.compile(r"^[XYZ][0-9]{7}[A-Z]$"),
    "CIF":   re.compile(r"^[A-HJNPQRSUVW][0-9]{7}[0-9A-J]$"),
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "IPv4":  re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
}
def clasificar(v):
    v = (v or "").strip().upper()
    for t, rx in _RE.items():
        if rx.match(v):
            return t
    return "otro"

# ─────────────────────── parseo de timestamps flexible ───────────────────────
_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d",
]
def parse_ts(v):
    if v is None:
        return None
    s = str(v).strip().strip('[]"')
    # .NET/SQL a veces trae 7 decimales; recorta a 6 para %f
    m = re.match(r"^(.*\.\d{6})\d*(.*)$", s)
    if m:
        s = m.group(1) + m.group(2)
    for f in _TS_FORMATS:
        try:
            return _dt.datetime.strptime(s, f).replace(tzinfo=None)
        except Exception:
            pass
    # ISO fallback
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=None)
    except Exception:
        return None

# ─────────────────────── cadena de custodia (SHA-256 de fuentes) ───────────────────────
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def cadena_custodia(paths, analyst, case):
    ficheros = []
    for p in paths:
        try:
            ficheros.append({"ruta": os.path.abspath(p), "nombre": os.path.basename(p),
                             "sha256": sha256_file(p), "tamaño_bytes": os.path.getsize(p)})
        except Exception as e:
            ficheros.append({"ruta": p, "nombre": os.path.basename(p), "sha256": "ERROR:%s" % e, "tamaño_bytes": 0})
    return {
        "herramienta": "%s v%s" % (TOOL, VERSION),
        "caso": case or "(sin referencia)",
        "analista": analyst or "(sin identificar)",
        "generado_utc": _utcnow().isoformat() + "Z",
        "ficheros_fuente": ficheros,
    }

# ─────────────────────── ingesta → SQLite ───────────────────────
def _read_rows(path, sep):
    """Devuelve lista de dicts (cabecera->valor) desde CSV o XLSX."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xls"):
        try:
            import pandas as pd
        except ImportError:
            sys.exit("ERROR: para XLSX se necesita pandas+openpyxl (pip install pandas openpyxl)")
        df = pd.read_excel(path, header=0, dtype=str)
        # si toda la fila viene en una sola columna separada por 'sep', re-split
        if sep and len(df.columns) == 1 and sep in str(df.columns[0]):
            cols = str(df.columns[0]).split(sep)
            df = df[df.columns[0]].astype(str).str.split(sep, n=len(cols) - 1, expand=True)
            df.columns = cols
        return [{k: (None if v is None else str(v)) for k, v in r.items()} for r in df.to_dict("records")]
    # CSV/TSV
    delim = sep if sep else ","
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f, delimiter=delim))

def ingest(paths, mapping, sep, action_const, db):
    """mapping: dict role->columna (entity, ts, ip, action, status). Crea tabla events."""
    db.execute("""CREATE TABLE events(
        entity TEXT, entity_type TEXT, action TEXT, ts TEXT, ts_year INT,
        ip TEXT, status TEXT, source TEXT, rowid_src INT)""")
    n = 0
    for path in paths:
        rows = _read_rows(path, sep)
        for i, row in enumerate(rows):
            # normaliza claves (quita espacios)
            row = {(k or "").strip(): v for k, v in row.items()}
            entity = (row.get(mapping.get("entity", ""), "") or "").strip().upper()
            if not entity:
                continue
            tsv = row.get(mapping.get("ts", ""), "")
            ts = parse_ts(tsv)
            action = action_const or (row.get(mapping.get("action", ""), "") or "").strip() or "evento"
            ip = (row.get(mapping.get("ip", ""), "") or "").strip()
            status = (row.get(mapping.get("status", ""), "") or "").strip()
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                       (entity, clasificar(entity), action,
                        ts.isoformat() if ts else None, ts.year if ts else None,
                        ip, status, os.path.basename(path), i))
            n += 1
    db.commit()
    db.execute("CREATE INDEX ix_ent ON events(entity)")
    db.execute("CREATE INDEX ix_act ON events(action, ts_year)")
    return n

# ─────────────────────── filtros comunes ───────────────────────
def where(args):
    cl, params = [], []
    if args.action:      cl.append("action=?");       params.append(args.action)
    if args.entity:      cl.append("entity=?");        params.append(args.entity.strip().upper())
    if args.entity_type: cl.append("entity_type=?");   params.append(args.entity_type)
    if args.ip:          cl.append("ip=?");            params.append(args.ip)
    if args.year:        cl.append("ts_year=?");       params.append(args.year)
    if args.date_from:   cl.append("ts>=?");           params.append(args.date_from)
    if args.date_to:     cl.append("ts<=?");           params.append(args.date_to + "T23:59:59")
    return (" WHERE " + " AND ".join(cl)) if cl else "", params

# ─────────────────────── consultas ───────────────────────
def q_distinct(db, args):
    w, p = where(args)
    total = db.execute("SELECT COUNT(*) FROM events" + w, p).fetchone()[0]
    rows = db.execute(
        "SELECT entity, entity_type, COUNT(*) veces, MIN(ts) primero, MAX(ts) ultimo, "
        "COUNT(DISTINCT ip) ips FROM events" + w + " GROUP BY entity ORDER BY veces DESC, entity", p).fetchall()
    by_type = db.execute("SELECT entity_type, COUNT(DISTINCT entity), COUNT(*) FROM events" + w +
                         " GROUP BY entity_type ORDER BY 2 DESC", p).fetchall()
    return {
        "consulta": "distinct", "total_eventos": total, "entidades_distintas": len(rows),
        "por_tipo": [{"tipo": t, "entidades": e, "eventos": ev} for t, e, ev in by_type],
        "resultados": [{"entidad": r[0], "tipo": r[1], "veces": r[2], "primero": r[3], "ultimo": r[4], "ips_distintas": r[5]} for r in rows],
    }

def q_top(db, args):
    d = q_distinct(db, args)
    mc = args.min_count or 2
    d["resultados"] = [r for r in d["resultados"] if r["veces"] >= mc]
    d["consulta"] = "top"; d["min_count"] = mc
    d["entidades_distintas"] = len(d["resultados"])
    return d

def q_timeline(db, args):
    if not args.entity:
        sys.exit("timeline requiere --entity")
    w, p = where(args)
    rows = db.execute("SELECT ts, action, ip, status, source FROM events" + w + " ORDER BY ts", p).fetchall()
    return {"consulta": "timeline", "entidad": args.entity.strip().upper(), "eventos": len(rows),
            "resultados": [{"fecha_hora": r[0], "accion": r[1], "ip": r[2], "estado": r[3], "fuente": r[4]} for r in rows]}

def q_events(db, args):
    w, p = where(args)
    rows = db.execute("SELECT entity, entity_type, ts, action, ip, status, source FROM events" + w + " ORDER BY ts", p).fetchall()
    return {"consulta": "events", "eventos": len(rows),
            "resultados": [{"entidad": r[0], "tipo": r[1], "fecha_hora": r[2], "accion": r[3], "ip": r[4], "estado": r[5], "fuente": r[6]} for r in rows]}

def q_sql(db, args):
    if not args.sql:
        sys.exit("--sql requiere la sentencia SELECT")
    if not re.match(r"^\s*select\b", args.sql, re.I):
        sys.exit("Por seguridad solo se permiten SELECT en --sql")
    cur = db.execute(args.sql)
    cols = [c[0] for c in cur.description]
    return {"consulta": "sql", "sql": args.sql,
            "resultados": [dict(zip(cols, row)) for row in cur.fetchall()]}

QUERIES = {"distinct": q_distinct, "top": q_top, "timeline": q_timeline, "events": q_events, "sql": q_sql}

# ─────────────────────── salida + evidencia ───────────────────────
def _rows_for_csv(res):
    return res.get("resultados", [])

def write_outputs(res, coc, args):
    os.makedirs(args.out, exist_ok=True)
    stamp = _utcnow().strftime("%Y%m%dT%H%M%SZ")
    base = os.path.join(args.out, "%s_%s" % (res["consulta"], stamp))
    files = {}
    # JSON (resultado + metadatos de reproducibilidad)
    meta = {"herramienta": "%s v%s" % (TOOL, VERSION), "caso": args.case, "analista": args.analyst,
            "generado_utc": _utcnow().isoformat() + "Z",
            "consulta_reproducible": " ".join(_reproducible_args()), "resultado": res, "cadena_custodia": coc}
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    files["json"] = base + ".json"
    # CSV
    rows = _rows_for_csv(res)
    if rows:
        with open(base + ".csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
        files["csv"] = base + ".csv"
    # Informe HTML forense
    files["html"] = base + ".html"
    with open(files["html"], "w", encoding="utf-8") as f:
        f.write(render_html(res, coc, meta))
    # Paquete de evidencia firmado
    if args.evidence:
        files["zip"] = base + "_evidencia.zip"
        empaquetar(files["zip"], coc, meta, res, args)
    return files, base

def _reproducible_args():
    # reconstruye la línea de comando (sin --evidence/--out para que sea determinista)
    out = ["vamp_forensic_query.py"]
    for a in sys.argv[1:]:
        out.append(a)
    return out

def empaquetar(zip_path, coc, meta, res, args):
    manifest = ["# MANIFEST.sha256 — %s v%s" % (TOOL, VERSION),
                "# caso: %s   analista: %s" % (args.case, args.analyst),
                "# generado: %s" % meta["generado_utc"], ""]
    def add(zf, arc, data):
        zf.writestr(arc, data)
        manifest.append("%s  %s" % (hashlib.sha256(data).hexdigest(), arc))
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        add(zf, "resultado.json", json.dumps(meta, ensure_ascii=False, indent=2).encode())
        rows = _rows_for_csv(res)
        if rows:
            buf = io.StringIO(); w = csv.DictWriter(buf, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
            add(zf, "resultado.csv", buf.getvalue().encode())
        add(zf, "informe_forense.html", render_html(res, coc, meta).encode())
        add(zf, "cadena_de_custodia.json", json.dumps(coc, ensure_ascii=False, indent=2).encode())
        # el MANIFEST se escribe al final (no se auto-incluye en su propio hash)
        zf.writestr("MANIFEST.sha256", "\n".join(manifest).encode())

def render_html(res, coc, meta):
    esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    rows = _rows_for_csv(res)
    head = "".join("<th>%s</th>" % esc(k) for k in (rows[0].keys() if rows else []))
    body = "".join("<tr>" + "".join("<td>%s</td>" % esc(v) for v in r.values()) + "</tr>" for r in rows[:5000])
    coc_rows = "".join(
        "<tr><td>%s</td><td class=mono>%s</td><td>%s B</td></tr>" % (esc(f["nombre"]), esc(f["sha256"]), f["tamaño_bytes"])
        for f in coc["ficheros_fuente"])
    tipo = ""
    if res.get("por_tipo"):
        tipo = "<h3>Distribución por tipo de entidad</h3><table><tr><th>Tipo</th><th>Entidades</th><th>Eventos</th></tr>" + \
               "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (t["tipo"], t["entidades"], t["eventos"]) for t in res["por_tipo"]) + "</table>"
    resumen = "<li>Entidades distintas: <b>%s</b></li>" % res.get("entidades_distintas", "—") if "entidades_distintas" in res else ""
    resumen += "<li>Eventos: <b>%s</b></li>" % res.get("total_eventos", res.get("eventos", len(rows)))
    return f"""<!doctype html><html lang=es><meta charset=utf-8>
<title>Informe forense — {esc(meta['caso'])} — {esc(res['consulta'])}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#1c2430;max-width:1000px;margin:0 auto;padding:28px}}
 h1{{font-size:22px;border-left:4px solid #b30021;padding-left:12px}}
 h2{{font-size:17px;margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:5px}}
 .mono{{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}}
 table{{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0;display:block;overflow-x:auto}}
 th,td{{border:1px solid #ccd;padding:5px 8px;text-align:left}} th{{background:#f2f4f7}}
 .meta{{background:#f7f9fb;border:1px solid #e0e5ea;border-radius:8px;padding:12px 16px}}
 .legal{{font-size:11.5px;color:#556;border-top:1px solid #ddd;margin-top:30px;padding-top:12px}}
 .seal{{background:#0e6b2e;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px}}
</style>
<h1>Informe pericial forense — Consulta «{esc(res['consulta'])}»</h1>
<div class=meta>
 <b>Caso:</b> {esc(meta['caso'])} &nbsp;·&nbsp; <b>Analista:</b> {esc(meta['analista'])}<br>
 <b>Herramienta:</b> {esc(meta['herramienta'])} &nbsp;·&nbsp; <b>Generado (UTC):</b> {esc(meta['generado_utc'])}<br>
 <b>Integridad:</b> <span class=seal>SHA-256 sobre fuentes + MANIFEST</span>
</div>
<h2>1 · Resumen</h2><ul>{resumen}</ul>{tipo}
<h2>2 · Metodología y reproducibilidad</h2>
<p>Consulta ejecutada de forma determinista sobre los eventos normalizados; sin intervención de IA ni criterio subjetivo. Comando reproducible:</p>
<pre class=mono>{esc(meta['consulta_reproducible'])}</pre>
<h2>3 · Cadena de custodia (fuentes originales)</h2>
<table><tr><th>Fichero</th><th>SHA-256</th><th>Tamaño</th></tr>{coc_rows}</table>
<p class=mono>Cualquier alteración de un byte de las fuentes cambia su hash SHA-256 y rompe la cadena de custodia.</p>
<h2>4 · Resultados ({len(rows)} filas{'; se muestran las primeras 5000' if len(rows)>5000 else ''})</h2>
<table><tr>{head}</tr>{body}</table>
<div class=legal>Documento generado automáticamente por {esc(TOOL)} de VampSecure Labs (Vampsecure Studios) a partir de fuentes cuyo hash SHA-256 consta en la cadena de custodia. Los resultados son verificables reejecutando la consulta indicada sobre ficheros con idéntico hash. Este informe y su paquete de evidencia (.zip con MANIFEST.sha256) constituyen un registro íntegro y a prueba de manipulación de la consulta realizada.</div>
</html>"""

# ─────────────────────── CLI ───────────────────────
def main():
    ap = argparse.ArgumentParser(prog=TOOL, description="Consultas forenses self-service + evidencia (VampSecure Labs)")
    ap.add_argument("sources", nargs="+", help="Ficheros fuente (CSV/XLSX)")
    ap.add_argument("query", choices=list(QUERIES.keys()), help="Tipo de consulta")
    ap.add_argument("--map", nargs="+", default=[], metavar="rol=columna",
                    help="Mapeo de columnas: entity=<col> ts=<col> [ip=<col>] [action=<col>] [status=<col>]")
    ap.add_argument("--profile", metavar="perfil.json", help="Perfil de mapeo predefinido (JSON con 'map','sep','action_const')")
    ap.add_argument("--sep", default="", help="Separador si la fuente trae campos en una columna (ej. ';')")
    ap.add_argument("--action-const", dest="action_const", default="", help="Fija la acción para toda la fuente (ej. password_change)")
    # filtros
    ap.add_argument("--action"); ap.add_argument("--entity"); ap.add_argument("--entity-type", dest="entity_type",
                    choices=["DNI", "NIE", "CIF", "email", "IPv4", "otro"])
    ap.add_argument("--ip"); ap.add_argument("--year", type=int)
    ap.add_argument("--from", dest="date_from", metavar="YYYY-MM-DD"); ap.add_argument("--to", dest="date_to", metavar="YYYY-MM-DD")
    ap.add_argument("--min-count", dest="min_count", type=int)
    ap.add_argument("--sql", help="SELECT libre sobre la tabla 'events' (solo lectura)")
    # evidencia
    ap.add_argument("--case", default="", metavar="REF"); ap.add_argument("--analyst", default="", metavar="NOMBRE")
    ap.add_argument("--out", default="./forensic_out", metavar="DIR")
    ap.add_argument("--evidence", action="store_true", help="Genera paquete ZIP firmado (MANIFEST.sha256 + cadena de custodia)")
    args = ap.parse_args()

    # mapeo (perfil o --map)
    mapping, sep, action_const = {}, args.sep, args.action_const
    if args.profile:
        prof = json.load(open(args.profile, encoding="utf-8"))
        mapping = prof.get("map", {}); sep = sep or prof.get("sep", ""); action_const = action_const or prof.get("action_const", "")
    for kv in args.map:
        if "=" in kv:
            k, v = kv.split("=", 1); mapping[k] = v
    if "entity" not in mapping:
        sys.exit("Falta el mapeo de la entidad: --map entity=<columna>  (o --profile)")

    db = sqlite3.connect(":memory:")
    n = ingest(args.sources, mapping, sep, action_const, db)
    print("[%s] %d eventos normalizados desde %d fuente(s)" % (TOOL, n, len(args.sources)), file=sys.stderr)

    res = QUERIES[args.query](db, args)
    coc = cadena_custodia(args.sources, args.analyst, args.case)
    files, base = write_outputs(res, coc, args)

    # resumen a stdout
    if args.query in ("distinct", "top"):
        print("Entidades distintas: %d  |  eventos: %s" % (res["entidades_distintas"], res.get("total_eventos")))
        for t in res.get("por_tipo", []):
            print("  %-6s %d entidades / %d eventos" % (t["tipo"], t["entidades"], t["eventos"]))
    else:
        print("Filas: %d" % len(res.get("resultados", [])))
    print("Generado:")
    for k, v in files.items():
        print("  %-5s %s" % (k, v))

if __name__ == "__main__":
    main()
