# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-forensic-query.

Crea CSV reales de prueba, los ingesta en SQLite, ejecuta las consultas
forenses y verifica resultados y paquetes de evidencia ZIP.
Mínimo 5 tests de integración.
"""

import csv
import hashlib
import sqlite3
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_forensic_query import (
    cadena_custodia,
    empaquetar,
    ingest,
    q_distinct,
    q_timeline,
    q_top,
)

# ── Helpers de fixtures locales ───────────────────────────────────────────────

def _crear_csv(ruta, filas, sep=","):
    """Escribe un CSV en la ruta dada con las filas proporcionadas."""
    if not filas:
        return
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(filas[0].keys()),
                                delimiter=sep)
        writer.writeheader()
        writer.writerows(filas)


class Args:
    """Namespace mínimo de argparse para las consultas."""
    action = "password_change"
    entity = None
    entity_type = None
    ip = None
    year = None
    date_from = None
    date_to = None
    min_count = None
    sql = None
    out = None
    case = "TEST-001"
    analyst = "TestAnalyst"
    evidence = False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Integración: consulta distinct sobre 20 filas reales
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_distinct_conteos_exactos(tmp_path):
    """
    Ingestar 20 filas con DNIs conocidos y verificar que distinct
    devuelve exactamente el número correcto de entidades únicas.
    """
    # 5 DNIs únicos: A aparece 4 veces, el resto 1 vez cada uno
    filas = [{"Usuario": "12345678A", "Fecha": f"2026-01-{i:02d}", "IP": "10.0.0.1"}
             for i in range(1, 5)]
    filas += [{"Usuario": f"1111111{i}B", "Fecha": f"2026-02-{i:02d}", "IP": "10.0.0.2"}
              for i in range(1, 5)]
    # Total: 8 filas, 5 entidades únicas (1 con 4 ocurrencias, 4 con 1)
    ruta = tmp_path / "test.csv"
    _crear_csv(ruta, filas)

    conn = sqlite3.connect(":memory:")
    mapping = {"entity": "Usuario", "ts": "Fecha", "ip": "IP"}
    total_ing = ingest([str(ruta)], mapping, ",", "login", conn)
    assert total_ing == 8

    args = Args()
    args.action = "login"
    resultado = q_distinct(conn, args)

    assert resultado["total_eventos"] == 8
    assert resultado["entidades_distintas"] == 5

    # 12345678A debe tener 4 eventos
    reincidente = next(r for r in resultado["resultados"] if r["entidad"] == "12345678A")
    assert reincidente["veces"] == 4


# ─────────────────────────────────────────────────────────────────────────────
# 2. Integración: consulta top filtra reincidentes correctamente
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_top_min_count(tmp_path):
    """
    q_top con min_count=3 devuelve solo la entidad que aparece 4 veces.
    """
    filas = [{"U": "A1234567B", "T": f"2026-01-{i:02d}", "I": ""} for i in range(1, 5)]
    filas += [{"U": "B9876543C", "T": "2026-01-05", "I": ""} for _ in range(2)]
    filas += [{"U": "C1122334D", "T": "2026-01-06", "I": ""} for _ in range(1)]

    ruta = tmp_path / "reincidentes.csv"
    _crear_csv(ruta, filas)

    conn = sqlite3.connect(":memory:")
    mapping = {"entity": "U", "ts": "T"}
    ingest([str(ruta)], mapping, ",", "evento", conn)

    args = Args()
    args.action = "evento"
    args.min_count = 3

    resultado = q_top(conn, args)
    # Solo A1234567B (4 veces) supera min_count=3
    assert resultado["entidades_distintas"] == 1
    assert resultado["resultados"][0]["entidad"] == "A1234567B"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Integración: consulta timeline ordenada cronológicamente
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_timeline_orden_cronologico(tmp_path):
    """
    Los eventos de una entidad deben estar ordenados cronológicamente
    en la salida de q_timeline.
    """
    filas = [
        {"ID": "99999999R", "Fecha": "2026-03-15 10:00:00", "IP": "10.0.0.1"},
        {"ID": "99999999R", "Fecha": "2026-01-10 08:00:00", "IP": "10.0.0.2"},
        {"ID": "99999999R", "Fecha": "2026-06-01 12:00:00", "IP": "10.0.0.3"},
        {"ID": "88888888S", "Fecha": "2026-02-01 09:00:00", "IP": "10.0.0.4"},
    ]
    ruta = tmp_path / "timeline_test.csv"
    _crear_csv(ruta, filas)

    conn = sqlite3.connect(":memory:")
    mapping = {"entity": "ID", "ts": "Fecha", "ip": "IP"}
    ingest([str(ruta)], mapping, ",", "acceso", conn)

    args = Args()
    args.entity = "99999999R"
    args.action = "acceso"
    resultado = q_timeline(conn, args)

    assert resultado["eventos"] == 3
    fechas = [r["fecha_hora"] for r in resultado["resultados"]]
    assert fechas == sorted(fechas), "Los eventos no están ordenados cronológicamente"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Integración: CSV con separador configurable (--sep ';')
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_csv_separador_punto_y_coma(tmp_path):
    """
    Un CSV delimitado por ';' debe ingestarse correctamente con sep=';'.
    """
    filas = [
        {"Usuario": "12345678Z", "Fecha": "2026-01-01 10:00:00", "IP": "10.0.0.1"},
        {"Usuario": "87654321X", "Fecha": "2026-01-02 11:00:00", "IP": "10.0.0.2"},
        {"Usuario": "12345678Z", "Fecha": "2026-01-03 12:00:00", "IP": "10.0.0.3"},
    ]
    ruta = tmp_path / "semicolon.csv"
    _crear_csv(ruta, filas, sep=";")

    conn = sqlite3.connect(":memory:")
    mapping = {"entity": "Usuario", "ts": "Fecha", "ip": "IP"}
    n = ingest([str(ruta)], mapping, ";", "cambio", conn)

    assert n == 3
    args = Args()
    args.action = "cambio"
    resultado = q_distinct(conn, args)
    assert resultado["entidades_distintas"] == 2


# ─────────────────────────────────────────────────────────────────────────────
# 5. Integración: paquete ZIP de evidencia con MANIFEST SHA-256
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_paquete_evidencia_manifest(tmp_path):
    """
    empaquetar() debe crear un ZIP con MANIFEST.sha256 cuyos hashes son
    correctos y reproducibles.
    """
    # Preparar datos mínimos para empaquetar
    res = {
        "consulta": "distinct",
        "total_eventos": 5,
        "entidades_distintas": 2,
        "por_tipo": [{"tipo": "DNI", "entidades": 2, "eventos": 5}],
        "resultados": [
            {"entidad": "12345678Z", "tipo": "DNI", "veces": 3,
             "primero": "2026-01-01", "ultimo": "2026-01-03", "ips_distintas": 2},
            {"entidad": "87654321X", "tipo": "DNI", "veces": 2,
             "primero": "2026-01-02", "ultimo": "2026-01-02", "ips_distintas": 1},
        ],
    }

    # Crear fuente ficticia para la cadena de custodia
    fuente = tmp_path / "datos.csv"
    fuente.write_text("col1,col2\nval1,val2\n", encoding="utf-8")

    coc = cadena_custodia([str(fuente)], "TestAnalyst", "CASO-ZIP-001")
    meta = {
        "herramienta": "vamp-forensic-query v1.2",
        "caso": "CASO-ZIP-001",
        "analista": "TestAnalyst",
        "generado_utc": "2026-10-01T10:00:00Z",
        "consulta_reproducible": "vamp_forensic_query.py datos.csv distinct",
        "resultado": res,
        "cadena_custodia": coc,
    }

    args = Args()
    args.case = "CASO-ZIP-001"
    args.analyst = "TestAnalyst"
    args.evidence = True

    zip_ruta = tmp_path / "evidencia.zip"
    empaquetar(str(zip_ruta), coc, meta, res, args)

    # Verificar que el ZIP contiene MANIFEST.sha256
    assert zip_ruta.exists()
    with zipfile.ZipFile(str(zip_ruta), "r") as zf:
        nombres = zf.namelist()
        assert "MANIFEST.sha256" in nombres
        assert "resultado.json" in nombres
        assert "cadena_de_custodia.json" in nombres

        # Verificar que los hashes del MANIFEST son correctos
        manifest = zf.read("MANIFEST.sha256").decode("utf-8")
        resultado_json_bytes = zf.read("resultado.json")
        hash_calculado = hashlib.sha256(resultado_json_bytes).hexdigest()
        assert hash_calculado in manifest


# ─────────────────────────────────────────────────────────────────────────────
# 6. Integración: filtro por año
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_filtro_por_anyo(tmp_path):
    """
    Filtrar por year=2026 devuelve solo los eventos de ese año.
    """
    filas = [
        {"ID": "11111111H", "Fecha": "2025-12-31 23:59:59", "IP": "10.0.0.1"},
        {"ID": "11111111H", "Fecha": "2026-01-01 00:00:01", "IP": "10.0.0.2"},
        {"ID": "22222222J", "Fecha": "2026-06-15 10:00:00", "IP": "10.0.0.3"},
        {"ID": "33333333P", "Fecha": "2027-01-01 00:00:00", "IP": "10.0.0.4"},
    ]
    ruta = tmp_path / "anyo.csv"
    _crear_csv(ruta, filas)

    conn = sqlite3.connect(":memory:")
    mapping = {"entity": "ID", "ts": "Fecha", "ip": "IP"}
    ingest([str(ruta)], mapping, ",", "acceso", conn)

    args = Args()
    args.action = "acceso"
    args.year = 2026
    resultado = q_distinct(conn, args)

    # Solo 2 filas son de 2026 (11111111H y 22222222J)
    assert resultado["total_eventos"] == 2
    entidades_2026 = {r["entidad"] for r in resultado["resultados"]}
    assert "11111111H" in entidades_2026
    assert "22222222J" in entidades_2026
    assert "33333333P" not in entidades_2026
