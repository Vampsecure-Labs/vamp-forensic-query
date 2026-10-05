# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-forensic-query.

Proporciona bases de datos SQLite en memoria, ficheros CSV de prueba y
configuraciones de args para test_unit.py y test_integration.py.
"""

import sys
import sqlite3
import csv
import datetime
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_forensic_query import ingest, clasificar, parse_ts


# ── Datos de prueba (CSV) ────────────────────────────────────────────────────

# 20 filas de muestra con DNIs, emails, IPs y timestamps
FILAS_PRUEBA = [
    # DNIs reales (8 dígitos + letra)
    {"Usuario": "12345678Z", "CreatedAt": "2026-01-15 10:00:00", "Datos": "192.168.1.1"},
    {"Usuario": "87654321X", "CreatedAt": "2026-01-15 10:05:00", "Datos": "192.168.1.2"},
    {"Usuario": "11111111H", "CreatedAt": "2026-02-20 12:00:00", "Datos": "10.0.0.1"},
    {"Usuario": "22222222J", "CreatedAt": "2026-02-21 09:00:00", "Datos": "10.0.0.2"},
    # El mismo DNI repite varias veces (reincidente)
    {"Usuario": "12345678Z", "CreatedAt": "2026-03-01 10:00:00", "Datos": "172.16.0.1"},
    {"Usuario": "12345678Z", "CreatedAt": "2026-03-02 10:00:00", "Datos": "172.16.0.2"},
    {"Usuario": "12345678Z", "CreatedAt": "2026-03-03 10:00:00", "Datos": "172.16.0.3"},
    # Emails
    {"Usuario": "usuario@ejemplo.es", "CreatedAt": "2026-04-01 08:00:00", "Datos": "10.1.1.1"},
    {"Usuario": "otro@dominio.com", "CreatedAt": "2026-04-02 09:00:00", "Datos": "10.1.1.2"},
    # IPs como entidad
    {"Usuario": "10.0.0.50", "CreatedAt": "2026-05-01 10:00:00", "Datos": ""},
    {"Usuario": "10.0.0.51", "CreatedAt": "2026-05-01 11:00:00", "Datos": ""},
    # NIEs
    {"Usuario": "X1234567R", "CreatedAt": "2026-06-01 10:00:00", "Datos": "192.168.2.1"},
    {"Usuario": "Y9876543A", "CreatedAt": "2026-06-02 10:00:00", "Datos": "192.168.2.2"},
    # Más DNIs
    {"Usuario": "33333333P", "CreatedAt": "2026-07-01 10:00:00", "Datos": "10.2.0.1"},
    {"Usuario": "44444444A", "CreatedAt": "2026-07-02 10:00:00", "Datos": "10.2.0.2"},
    {"Usuario": "55555555B", "CreatedAt": "2026-07-03 10:00:00", "Datos": "10.2.0.3"},
    {"Usuario": "66666666C", "CreatedAt": "2026-07-04 10:00:00", "Datos": "10.2.0.4"},
    {"Usuario": "77777777D", "CreatedAt": "2026-07-05 10:00:00", "Datos": "10.2.0.5"},
    # Otro email reincidente
    {"Usuario": "usuario@ejemplo.es", "CreatedAt": "2026-08-01 10:00:00", "Datos": "10.3.0.1"},
    {"Usuario": "usuario@ejemplo.es", "CreatedAt": "2026-09-01 10:00:00", "Datos": "10.3.0.2"},
]


@pytest.fixture
def csv_prueba(tmp_path):
    """Crea un CSV de prueba con 20 filas mixtas y devuelve su ruta."""
    ruta = tmp_path / "datos.csv"
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Usuario", "CreatedAt", "Datos"])
        writer.writeheader()
        writer.writerows(FILAS_PRUEBA)
    return ruta


@pytest.fixture
def db_cargada(csv_prueba, tmp_path):
    """Base de datos SQLite en memoria cargada con las 20 filas de prueba."""
    conn = sqlite3.connect(":memory:")
    mapping = {"entity": "Usuario", "ts": "CreatedAt", "ip": "Datos"}
    ingest([str(csv_prueba)], mapping, ",", "password_change", conn)
    return conn


@pytest.fixture
def args_basicos():
    """Namespace simple de argparse para las consultas."""
    class Args:
        action = "password_change"
        entity = None
        entity_type = None
        ip = None
        year = None
        date_from = None
        date_to = None
        min_count = None
        sql = None
    return Args()
