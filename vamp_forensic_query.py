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
  vamp_forensic_query.py usuarios.xlsx \
      --map entity=Usuario ts=CreatedAt ip=Datos --sep ';' --action-const password_change \
      distinct --year 2026 --entity-type DNI \
      --case "CASO-2026-001" --analyst "A. Hernández — VampSecure" --evidence

  # Cronología exacta de una entidad
  vamp_forensic_query.py eventos.xlsx --map entity=Usuario ts=CreatedAt ip=Datos --sep ';' \
      timeline --entity 00000001R

  # Reincidentes (>=3 cambios) de cualquier tipo, con evidencia
  vamp_forensic_query.py ... top --action password_change --year 2026 --min-count 3 --evidence
"""
import argparse
import csv
import datetime as _dt
import hashlib
import io
import json
import os
import re
import sqlite3
import struct
import sys
import zipfile


def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)

VERSION = "1.3"
TOOL = "vamp-forensic-query"

BANNER = (
    "\n"
    "__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ \n"
    "\\ \\ / /_\\ |  \\/  | _ \\/ __| __/ __| | | | _ \\ __| |    /_\\ | _ ) __|\n"
    " \\ V / _ \\| |\\/| |  _/\\__ \\ _| (__| |_| |   / _|| |__ / _ \\| _ \\__ \\\n"
    "  \\_/_/ \\_\\_|  |_|_|  |___/___\\___|\\___/|_|_\\___|____/_/ \\_\\___/___/\n"
    '  by Antonio Hernandez "Belky" — VampSecure Studios\n'
    "  vamp-forensic-query v1.2 · Forensic Query Engine + Binary Analysis\n"
    "  ────────────────────────────────────────────────────────────────────────\n"
    "  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal\n"
)

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
            ficheros.append({"ruta": p, "nombre": os.path.basename(p), "sha256": f"ERROR:{e}", "tamaño_bytes": 0})
    return {
        "herramienta": f"{TOOL} v{VERSION}",
        "caso": case or "(sin referencia)",
        "analista": analyst or "(sin identificar)",
        "generado_utc": _utcnow().isoformat() + "Z",
        "ficheros_fuente": ficheros,
    }

# ─────────────────────── ingesta → SQLite ───────────────────────
def _read_rows(path, sep):
    """Itera dicts (cabecera->valor) desde CSV o XLSX sin materializar en RAM."""
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xls"):
        try:
            import pandas as pd
        except ImportError:
            sys.exit("ERROR: para XLSX se necesita pandas+openpyxl (pip install pandas openpyxl)")
        df = pd.read_excel(path, header=0, dtype=str)
        if sep and len(df.columns) == 1 and sep in str(df.columns[0]):
            cols = str(df.columns[0]).split(sep)
            df = df[df.columns[0]].astype(str).str.split(sep, n=len(cols) - 1, expand=True)
            df.columns = cols
        yield from ({k: (None if v is None else str(v)) for k, v in r.items()}
                    for r in df.to_dict("records"))
        return
    # CSV/TSV — streaming: no materializa en RAM, compatible con ficheros >500 MB
    delim = sep if sep else ","
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        yield from csv.DictReader(f, delimiter=delim)

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
    if not re.match(r"^\s*select\b", args.sql, re.IGNORECASE):
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
    base = os.path.join(args.out, "{}_{}".format(res["consulta"], stamp))
    files = {}
    # JSON (resultado + metadatos de reproducibilidad)
    meta = {"herramienta": f"{TOOL} v{VERSION}", "caso": args.case, "analista": args.analyst,
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
    manifest = [f"# MANIFEST.sha256 — {TOOL} v{VERSION}",
                f"# caso: {args.case}   analista: {args.analyst}",
                "# generado: {}".format(meta["generado_utc"]), ""]
    def add(zf, arc, data):
        zf.writestr(arc, data)
        manifest.append(f"{hashlib.sha256(data).hexdigest()}  {arc}")
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
    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    rows = _rows_for_csv(res)
    head = "".join(f"<th>{esc(k)}</th>" for k in (rows[0].keys() if rows else []))
    body = "".join("<tr>" + "".join(f"<td>{esc(v)}</td>" for v in r.values()) + "</tr>" for r in rows[:5000])
    coc_rows = "".join(
        "<tr><td>{}</td><td class=mono>{}</td><td>{} B</td></tr>".format(esc(f["nombre"]), esc(f["sha256"]), f["tamaño_bytes"])
        for f in coc["ficheros_fuente"])
    tipo = ""
    if res.get("por_tipo"):
        tipo = "<h3>Distribución por tipo de entidad</h3><table><tr><th>Tipo</th><th>Entidades</th><th>Eventos</th></tr>" + \
               "".join("<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(t["tipo"], t["entidades"], t["eventos"]) for t in res["por_tipo"]) + "</table>"
    resumen = "<li>Entidades distintas: <b>{}</b></li>".format(res.get("entidades_distintas", "—")) if "entidades_distintas" in res else ""
    resumen += "<li>Eventos: <b>{}</b></li>".format(res.get("total_eventos", res.get("eventos", len(rows))))
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

# ─────────────────────── análisis de ficheros binarios ───────────────────────

# Tipos reconocidos por magic bytes (primeros bytes del fichero)
_MAGIC_SIGNATURES = [
    (b"\x7fELF",                     "ELF"),
    (b"MZ",                          "PE (Windows Executable)"),
    (b"\xca\xfe\xba\xbe",            "Mach-O (fat binary)"),
    (b"\xfe\xed\xfa\xce",            "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf",            "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe",            "Mach-O 32-bit (little-endian)"),
    (b"\xcf\xfa\xed\xfe",            "Mach-O 64-bit (little-endian)"),
    (b"%PDF",                        "PDF"),
    (b"PK\x03\x04",                  "ZIP"),
    (b"\x1f\x8b",                    "GZIP"),
    (b"BZh",                         "BZIP2"),
    (b"\xfd7zXZ\x00",               "XZ"),
    (b"Rar!\x1a\x07",               "RAR"),
    (b"7z\xbc\xaf\x27\x1c",        "7-ZIP"),
    (b"\x89PNG\r\n\x1a\n",          "PNG"),
    (b"\xff\xd8\xff",               "JPEG"),
    (b"GIF87a",                      "GIF"),
    (b"GIF89a",                      "GIF"),
]

# Strings PE sospechosos: indicadores de inyección de procesos
_PE_SUSPICIOUS_IMPORTS = [
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "OpenProcess", "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory", "RtlCreateUserThread", "SetWindowsHookEx",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
]

# Strings en ELF/PE considerados sospechosos por su contenido
_SUSPICIOUS_STRING_PATTERNS = [
    re.compile(r"https?://[^\x00-\x1f\x7f-\xff]{8,}", re.ASCII),       # URLs embebidas
    re.compile(r"/etc/passwd|/etc/shadow|/bin/sh|/bin/bash", re.ASCII), # rutas sensibles Unix
    re.compile(r"cmd\.exe|powershell|wscript|cscript", re.IGNORECASE),  # ejecución Windows
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}", re.ASCII),                 # base64 largo
    re.compile(r"(?:[0-9a-fA-F]{2}){16,}", re.ASCII),                  # shellcode hex
]

# Nombres de máquina ELF (e_machine)
_ELF_MACHINE = {
    0x00: "EM_NONE", 0x02: "EM_SPARC", 0x03: "EM_386", 0x08: "EM_MIPS",
    0x14: "EM_PPC",  0x15: "EM_PPC64", 0x16: "EM_S390", 0x28: "EM_ARM",
    0x3E: "EM_X86_64", 0xB7: "EM_AARCH64", 0xF3: "EM_RISCV",
}

# Tipos ELF (e_type)
_ELF_TYPE = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}

# Nombres de máquina PE (COFF machine)
_PE_MACHINE = {
    0x014c: "IMAGE_FILE_MACHINE_I386",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xaa64: "IMAGE_FILE_MACHINE_ARM64",
    0x01c4: "IMAGE_FILE_MACHINE_ARMNT",
}


def _extract_strings(data: bytes, min_len: int = 6) -> list:
    """
    Extrae cadenas de caracteres ASCII imprimibles de longitud >= min_len.
    Equivale a la herramienta 'strings' de Unix.
    """
    results = []
    current = []
    for byte in data:
        ch = chr(byte)
        if 0x20 <= byte < 0x7F:  # ASCII imprimible
            current.append(ch)
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def _analyze_binary(filepath: str, findings: list) -> dict:
    """
    Analiza un fichero binario buscando indicadores forenses relevantes.

    Solo usa stdlib (struct, os, re). Sin dependencias externas.

    Parámetros
    ----------
    filepath : str   — Ruta absoluta al fichero a analizar
    findings : list  — Lista donde se añaden los hallazgos (dicts)

    Retorna
    -------
    dict — Resumen del análisis: tipo, arquitectura, indicadores detectados
    """
    resultado = {
        "fichero": filepath,
        "tipo": "desconocido",
        "tamaño_bytes": 0,
        "sha256": "",
        "hallazgos": findings,
        "indicadores": [],
    }

    # ── Lectura inicial ───────────────────────────────────────────────────────
    try:
        stat = os.stat(filepath)
    except OSError as e:
        findings.append({
            "severidad": "ERROR",
            "tipo": "acceso",
            "descripcion": f"No se puede leer el fichero: {e}",
        })
        return resultado

    resultado["tamaño_bytes"] = stat.st_size

    # Calcular SHA-256 del fichero completo
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        resultado["sha256"] = h.hexdigest()
    except OSError:
        pass

    # Leer cabecera (512 bytes para magic bytes + headers de ELF/PE)
    try:
        with open(filepath, "rb") as f:
            header = f.read(512)
    except OSError as e:
        findings.append({
            "severidad": "ERROR",
            "tipo": "lectura",
            "descripcion": f"Error leyendo cabecera: {e}",
        })
        return resultado

    if not header:
        findings.append({
            "severidad": "INFO",
            "tipo": "fichero_vacio",
            "descripcion": "El fichero está vacío.",
        })
        return resultado

    # ── Detección de tipo por magic bytes ─────────────────────────────────────
    file_type = "desconocido"
    for magic, label in _MAGIC_SIGNATURES:
        if header.startswith(magic):
            file_type = label
            break
    resultado["tipo"] = file_type

    findings.append({
        "severidad": "INFO",
        "tipo": "tipo_detectado",
        "descripcion": f"Tipo de fichero: {file_type}",
        "sha256": resultado["sha256"],
    })

    # ── Comprobación SUID bit ─────────────────────────────────────────────────
    if stat.st_mode & 0o4000:
        hallazgo = {
            "severidad": "HIGH",
            "tipo": "suid_bit",
            "descripcion": f"Fichero {file_type} con SUID bit activo — puede elevar privilegios",
            "modo": oct(stat.st_mode),
        }
        findings.append(hallazgo)
        resultado["indicadores"].append("SUID_BIT")

    # ── Análisis ELF ──────────────────────────────────────────────────────────
    if file_type == "ELF" and len(header) >= 64:
        _analyze_elf(filepath, header, findings, resultado)

    # ── Análisis PE (Windows Executable) ─────────────────────────────────────
    elif file_type == "PE (Windows Executable)" and len(header) >= 64:
        _analyze_pe(filepath, header, findings, resultado)

    return resultado


def _analyze_elf(filepath: str, header: bytes, findings: list, resultado: dict) -> None:
    """
    Parsea la cabecera ELF y busca indicadores en los strings del ejecutable.

    Extrae:
      - e_type (ET_EXEC, ET_DYN, ET_CORE)
      - e_machine (arquitectura)
      - e_entry (punto de entrada)

    Para ET_EXEC y ET_DYN extrae strings y busca patrones sospechosos.
    """
    # ELF identification (EI_CLASS, EI_DATA)
    ei_class = header[4]   # 1=32bit, 2=64bit
    ei_data  = header[5]   # 1=little-endian, 2=big-endian
    endian   = "<" if ei_data == 1 else ">"

    try:
        if ei_class == 1:  # ELF32
            e_type, e_machine = struct.unpack_from(f"{endian}HH", header, 16)
            e_entry = struct.unpack_from(f"{endian}I", header, 24)[0]
        elif ei_class == 2:  # ELF64
            e_type, e_machine = struct.unpack_from(f"{endian}HH", header, 16)
            e_entry = struct.unpack_from(f"{endian}Q", header, 24)[0]
        else:
            findings.append({
                "severidad": "INFO",
                "tipo": "elf_clase_desconocida",
                "descripcion": f"ELF EI_CLASS desconocido: {ei_class}",
            })
            return
    except struct.error as e:
        findings.append({
            "severidad": "WARN",
            "tipo": "elf_parse_error",
            "descripcion": f"Error parseando cabecera ELF: {e}",
        })
        return

    arch_str  = _ELF_MACHINE.get(e_machine, f"0x{e_machine:04x}")
    type_str  = _ELF_TYPE.get(e_type, f"0x{e_type:04x}")
    bits_str  = "64-bit" if ei_class == 2 else "32-bit"
    entry_str = f"0x{e_entry:016x}" if ei_class == 2 else f"0x{e_entry:08x}"

    findings.append({
        "severidad": "INFO",
        "tipo": "elf_info",
        "descripcion": (
            f"ELF {bits_str} · tipo={type_str} · arch={arch_str} "
            f"· entry_point={entry_str}"
        ),
        "e_type": type_str,
        "e_machine": arch_str,
        "e_entry": entry_str,
    })
    resultado["indicadores"].append(f"ELF_{type_str}")

    # Solo analizar strings en ejecutables o librerías dinámicas
    if e_type not in (2, 3):  # ET_EXEC=2, ET_DYN=3
        return

    # Leer el fichero completo para extracción de strings
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return

    strings = _extract_strings(data, min_len=6)

    # Buscar strings sospechosos
    for s in strings:
        for pat in _SUSPICIOUS_STRING_PATTERNS:
            if pat.search(s):
                hallazgo = {
                    "severidad": "MEDIUM",
                    "tipo": "elf_string_sospechoso",
                    "descripcion": f"String sospechoso en ELF: {s[:120]}",
                    "valor": s[:200],
                }
                # Evitar duplicados exactos
                if hallazgo not in findings:
                    findings.append(hallazgo)
                    resultado["indicadores"].append("STRING_SOSPECHOSO")
                break


def _analyze_pe(filepath: str, header: bytes, findings: list, resultado: dict) -> None:
    """
    Parsea la cabecera PE/COFF y busca imports de funciones sospechosas.

    Parsea:
      - DOS header (offset al PE signature)
      - PE signature (0x50450000 = "PE\\0\\0")
      - COFF header (Machine type)

    Luego extrae strings del binario completo y busca nombres de funciones
    asociadas a inyección de procesos / shellcode loaders.
    """
    # DOS header: e_lfanew está en offset 0x3C (little-endian DWORD)
    if len(header) < 0x40:
        return

    try:
        e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
    except struct.error:
        return

    # Leer el fichero completo para acceder al PE header completo
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return

    # Verificar PE signature
    if e_lfanew + 6 > len(data):
        findings.append({
            "severidad": "WARN",
            "tipo": "pe_truncado",
            "descripcion": f"PE header fuera del rango del fichero (e_lfanew=0x{e_lfanew:x})",
        })
        return

    pe_sig = data[e_lfanew: e_lfanew + 4]
    if pe_sig != b"PE\x00\x00":
        findings.append({
            "severidad": "WARN",
            "tipo": "pe_firma_invalida",
            "descripcion": f"Firma PE inválida: {pe_sig.hex()} (esperado 50450000)",
        })
        return

    # COFF header: Machine (2 bytes) en e_lfanew+4
    try:
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    except struct.error:
        machine = 0

    machine_str = _PE_MACHINE.get(machine, f"0x{machine:04x}")
    findings.append({
        "severidad": "INFO",
        "tipo": "pe_info",
        "descripcion": f"PE · arquitectura={machine_str}",
        "machine": machine_str,
        "e_lfanew": hex(e_lfanew),
    })
    resultado["indicadores"].append(f"PE_{machine_str}")

    # Extraer strings y buscar imports sospechosos
    strings = _extract_strings(data, min_len=6)

    for imp in _PE_SUSPICIOUS_IMPORTS:
        # Buscar el nombre del import en la lista de strings extraídos
        for s in strings:
            if imp.lower() in s.lower():
                hallazgo = {
                    "severidad": "HIGH",
                    "tipo": "pe_import_sospechoso",
                    "descripcion": (
                        f"Import sospechoso detectado: '{imp}' — "
                        "indicador de inyección de procesos o shellcode loader"
                    ),
                    "import": imp,
                    "contexto": s[:200],
                }
                if hallazgo["descripcion"] not in [h.get("descripcion", "") for h in findings]:
                    findings.append(hallazgo)
                    resultado["indicadores"].append(f"PE_IMPORT_{imp.upper()}")
                break

    # Buscar otros strings sospechosos
    for s in strings:
        for pat in _SUSPICIOUS_STRING_PATTERNS:
            if pat.search(s):
                hallazgo = {
                    "severidad": "MEDIUM",
                    "tipo": "pe_string_sospechoso",
                    "descripcion": f"String sospechoso en PE: {s[:120]}",
                    "valor": s[:200],
                }
                if hallazgo not in findings:
                    findings.append(hallazgo)
                    resultado["indicadores"].append("STRING_SOSPECHOSO")
                break


# ─────────────────────── CLI ───────────────────────
def main():
    ap = argparse.ArgumentParser(prog=TOOL, description="Consultas forenses self-service + evidencia + análisis binario (VampSecure Labs)")
    # Modo análisis binario — excluye los argumentos de consulta SQL
    ap.add_argument("--binary", metavar="FICHERO",
                    help=(
                        "Analizar un fichero binario (ELF/PE/Mach-O/PDF/ZIP…). "
                        "Detecta tipo por magic bytes, parsea cabeceras ELF/PE, "
                        "extrae strings sospechosos y comprueba SUID bit. "
                        "Cuando se usa este argumento, 'sources' y 'query' son opcionales."
                    ))
    ap.add_argument("sources", nargs="*", help="Ficheros fuente (CSV/XLSX) — no requerido con --binary")
    ap.add_argument("query", nargs="?", choices=list(QUERIES.keys()), help="Tipo de consulta")
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
    ap.add_argument("--stream", action="store_true",
                    help="Fuerza modo streaming (SQLite en disco temporal): recomendado para "
                         "fuentes >500 MB; se activa automáticamente si alguna fuente supera "
                         "ese umbral (v1.3)")
    args = ap.parse_args()

    # ── Modo análisis de fichero binario ──────────────────────────────────────
    if args.binary:
        print(BANNER, file=sys.stderr)
        binary_path = os.path.abspath(args.binary)
        if not os.path.isfile(binary_path):
            sys.exit(f"ERROR: fichero no encontrado: {binary_path}")
        print(f"[{TOOL}] Analizando fichero binario: {binary_path}", file=sys.stderr)

        findings_bin = []
        resultado = _analyze_binary(binary_path, findings_bin)

        # Ordenar hallazgos por severidad
        sev_order = {"ERROR": 0, "HIGH": 1, "MEDIUM": 2, "WARN": 3, "INFO": 4}
        findings_bin.sort(key=lambda h: sev_order.get(h.get("severidad", "INFO"), 99))

        # Mostrar resumen en stderr
        print(f"  Tipo:       {resultado['tipo']}", file=sys.stderr)
        print(f"  Tamaño:     {resultado['tamaño_bytes']} bytes", file=sys.stderr)
        print(f"  SHA-256:    {resultado['sha256']}", file=sys.stderr)
        print(f"  Indicadores: {', '.join(resultado['indicadores']) or '(ninguno)'}", file=sys.stderr)
        print(f"  Hallazgos:  {len(findings_bin)}", file=sys.stderr)

        # Salida JSON a stdout
        out = {
            "herramienta": f"{TOOL} v{VERSION}",
            "generado_utc": _utcnow().isoformat() + "Z",
            "fichero": binary_path,
            "tipo": resultado["tipo"],
            "tamaño_bytes": resultado["tamaño_bytes"],
            "sha256": resultado["sha256"],
            "indicadores": resultado["indicadores"],
            "hallazgos": findings_bin,
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))

        # Código de salida: 0 si solo INFO, 1 si hay MEDIUM/WARN, 2 si hay HIGH/ERROR
        max_sev = max((sev_order.get(h.get("severidad","INFO"), 99) for h in findings_bin), default=99)
        if max_sev <= 1:    # HIGH o ERROR
            sys.exit(2)
        elif max_sev <= 3:  # MEDIUM o WARN
            sys.exit(1)
        sys.exit(0)

    # ── Validar argumentos de consulta SQL (modo normal) ─────────────────────
    if not args.sources:
        ap.error("se requiere al menos un fichero fuente (o usa --binary para análisis binario)")
    if not args.query:
        ap.error(f"se requiere el tipo de consulta: {list(QUERIES.keys())}")

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

    # Modo streaming: SQLite en disco si cualquier fuente supera 500 MB
    # o si el usuario pide --stream explícitamente
    _STREAM_UMBRAL = 500 * 1024 * 1024  # 500 MB
    usar_disco = getattr(args, "stream", False) or any(
        os.path.isfile(p) and os.path.getsize(p) >= _STREAM_UMBRAL
        for p in args.sources
    )
    if usar_disco:
        import tempfile
        _db_tmp = tempfile.NamedTemporaryFile(
            suffix=".sqlite", prefix="vfq_", delete=False
        )
        _db_path = _db_tmp.name
        _db_tmp.close()
        print(
            f"[{TOOL}] Modo streaming activado — SQLite en disco: {_db_path}",
            file=sys.stderr,
        )
        db = sqlite3.connect(_db_path)
    else:
        _db_path = None
        db = sqlite3.connect(":memory:")

    try:
        n = ingest(args.sources, mapping, sep, action_const, db)
    except Exception:
        if _db_path:
            try:
                os.unlink(_db_path)
            except OSError:
                pass
        raise
    print("[%s] %d eventos normalizados desde %d fuente(s)" % (TOOL, n, len(args.sources)), file=sys.stderr)

    res = QUERIES[args.query](db, args)
    coc = cadena_custodia(args.sources, args.analyst, args.case)
    files, _base = write_outputs(res, coc, args)

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

    # Limpiar SQLite temporal si se usó modo streaming
    db.close()
    if _db_path:
        try:
            os.unlink(_db_path)
        except OSError:
            pass

if __name__ == "__main__":
    main()
