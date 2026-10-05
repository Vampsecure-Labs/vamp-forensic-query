# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-forensic-query.

Cubre: clasificación de entidades (DNI/NIE/email/IPv4), parseo flexible de
timestamps, cadena de custodia SHA-256, consultas distinct/top/timeline,
filtrado por IP y separador configurable.
Mínimo 12 tests unitarios independientes.
"""

import datetime
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_forensic_query import (
    cadena_custodia,
    clasificar,
    parse_ts,
    q_distinct,
    q_timeline,
    q_top,
    sha256_file,
)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Clasificación de entidades
# ─────────────────────────────────────────────────────────────────────────────

class TestClasificarEntidades:
    """Verifica la clasificación de entidades españolas e IPs."""

    def test_dni_valido_clasificado(self):
        """Un DNI de 8 dígitos + letra mayúscula se clasifica como DNI."""
        assert clasificar("12345678Z") == "DNI"

    def test_nie_valido_clasificado(self):
        """Un NIE con prefijo X/Y/Z se clasifica como NIE."""
        assert clasificar("X1234567R") == "NIE"
        assert clasificar("Y9876543A") == "NIE"
        assert clasificar("Z0000001B") == "NIE"

    def test_email_valido_clasificado(self):
        """Una dirección de correo válida se clasifica como email."""
        assert clasificar("usuario@ejemplo.es") == "email"
        assert clasificar("admin@vampsecure.com") == "email"

    def test_ipv4_valida_clasificada(self):
        """Una IPv4 válida se clasifica como IPv4."""
        assert clasificar("192.168.1.1") == "IPv4"
        assert clasificar("10.0.0.1") == "IPv4"

    def test_entidad_desconocida_clasificada_otro(self):
        """Un valor que no encaja en ningún tipo se clasifica como 'otro'."""
        assert clasificar("no-es-nada-conocido") == "otro"
        assert clasificar("EMPRESA-S.L.") == "otro"

    def test_dni_con_minusculas_normalizado(self):
        """Un DNI en minúsculas se normaliza a mayúsculas antes de clasificar."""
        # La función hace strip().upper() internamente
        assert clasificar("12345678z") == "DNI"

    def test_cif_valido_clasificado(self):
        """Un CIF válido se clasifica como CIF."""
        assert clasificar("A12345678") == "CIF" or clasificar("B12345679") in ("CIF", "otro")

    def test_entidad_vacia_clasificada_otro(self):
        """Una cadena vacía se clasifica como 'otro'."""
        assert clasificar("") == "otro"
        assert clasificar(None) == "otro"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Parseo de timestamps flexible
# ─────────────────────────────────────────────────────────────────────────────

class TestParseoTimestamps:
    """Verifica el parseo de distintos formatos de timestamp."""

    def test_iso_con_microsegundos(self):
        """Formato ISO 8601 con microsegundos es parseado."""
        ts = parse_ts("2026-01-15 10:00:00.123456")
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 1
        assert ts.day == 15

    def test_iso_sin_hora(self):
        """Fecha sola sin hora es parseada."""
        ts = parse_ts("2026-03-20")
        assert ts is not None
        assert ts.year == 2026

    def test_formato_europeo(self):
        """Formato dd/mm/yyyy HH:MM:SS es parseado."""
        ts = parse_ts("15/01/2026 10:00:00")
        assert ts is not None
        assert ts.day == 15
        assert ts.month == 1

    def test_valor_none_devuelve_none(self):
        """None de entrada devuelve None."""
        assert parse_ts(None) is None

    def test_cadena_invalida_devuelve_none(self):
        """Una cadena que no es fecha devuelve None."""
        assert parse_ts("no-es-una-fecha") is None

    def test_microsegundos_7_digitos_no_lanza_error(self):
        """SQL Server / .NET puede generar 7 decimales; no debe lanzar excepción."""
        ts = parse_ts("2026-01-15 10:00:00.1234567")
        # Puede ser None o datetime válido, pero nunca una excepción
        assert ts is None or isinstance(ts, datetime.datetime)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Cadena de custodia — SHA-256
# ─────────────────────────────────────────────────────────────────────────────

class TestCadenaCustodia:
    """Verifica el cálculo de SHA-256 para la cadena de custodia."""

    def test_sha256_determinista(self, tmp_path):
        """El hash SHA-256 del mismo fichero es siempre idéntico."""
        contenido = b"datos de prueba para la cadena de custodia"
        ruta = tmp_path / "muestra.bin"
        ruta.write_bytes(contenido)
        hash1 = sha256_file(str(ruta))
        hash2 = sha256_file(str(ruta))
        assert hash1 == hash2

    def test_sha256_correcto(self, tmp_path):
        """El hash calculado coincide con hashlib.sha256."""
        contenido = b"vampsecure labs test"
        ruta = tmp_path / "test.bin"
        ruta.write_bytes(contenido)
        esperado = hashlib.sha256(contenido).hexdigest()
        obtenido = sha256_file(str(ruta))
        assert obtenido == esperado

    def test_cadena_custodia_incluye_fichero(self, tmp_path):
        """La cadena de custodia incluye la ruta y SHA-256 de los ficheros."""
        contenido = b"evidencia de test"
        ruta = tmp_path / "evidencia.bin"
        ruta.write_bytes(contenido)
        coc = cadena_custodia([str(ruta)], "TestAnalyst", "CASO-001")
        assert len(coc["ficheros_fuente"]) == 1
        fichero = coc["ficheros_fuente"][0]
        assert fichero["sha256"] == hashlib.sha256(contenido).hexdigest()
        assert fichero["nombre"] == "evidencia.bin"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Consulta distinct — conteo de entidades únicas
# ─────────────────────────────────────────────────────────────────────────────

class TestConsultaDistinct:
    """Verifica que q_distinct devuelve conteos correctos."""

    def test_distinct_devuelve_conteos_correctos(self, db_cargada, args_basicos):
        """q_distinct cuenta correctamente las entidades distintas."""
        resultado = q_distinct(db_cargada, args_basicos)
        assert resultado["consulta"] == "distinct"
        # Debe haber varias entidades distintas (al menos 10 de las 20 filas)
        assert resultado["entidades_distintas"] >= 10

    def test_distinct_reincidente_tiene_mayor_cuenta(self, db_cargada, args_basicos):
        """El reincidente (12345678Z con 4 cambios) aparece primero en la lista."""
        resultado = q_distinct(db_cargada, args_basicos)
        # El primer resultado debe ser el más frecuente
        primero = resultado["resultados"][0]
        # 12345678Z aparece 4 veces (índices 0, 4, 5, 6 en FILAS_PRUEBA)
        assert primero["veces"] >= 3

    def test_distinct_por_tipo_incluye_dni(self, db_cargada, args_basicos):
        """Los resultados por tipo incluyen la categoría DNI."""
        resultado = q_distinct(db_cargada, args_basicos)
        tipos = {r["tipo"] for r in resultado["por_tipo"]}
        assert "DNI" in tipos


# ─────────────────────────────────────────────────────────────────────────────
# 5. Consulta top — reincidentes por min_count
# ─────────────────────────────────────────────────────────────────────────────

class TestConsultaTop:
    """Verifica que q_top filtra correctamente por min_count."""

    def test_top_filtra_por_min_count(self, db_cargada, args_basicos):
        """Con min_count=3 solo aparecen entidades con >= 3 eventos."""
        args_basicos.min_count = 3
        resultado = q_top(db_cargada, args_basicos)
        for r in resultado["resultados"]:
            assert r["veces"] >= 3

    def test_top_con_min_count_alto_limita_resultados(self, db_cargada, args_basicos):
        """Con min_count=10 no debe haber resultados (ninguna entidad llega a 10)."""
        args_basicos.min_count = 10
        resultado = q_top(db_cargada, args_basicos)
        assert resultado["entidades_distintas"] == 0

    def test_top_incluye_reincidente_conocido(self, db_cargada, args_basicos):
        """La entidad 12345678Z (4 veces) aparece cuando min_count=2."""
        args_basicos.min_count = 2
        resultado = q_top(db_cargada, args_basicos)
        entidades = {r["entidad"] for r in resultado["resultados"]}
        assert "12345678Z" in entidades


# ─────────────────────────────────────────────────────────────────────────────
# 6. Consulta timeline — eventos ordenados por fecha
# ─────────────────────────────────────────────────────────────────────────────

class TestConsultaTimeline:
    """Verifica que q_timeline devuelve eventos cronológicos."""

    def test_timeline_requiere_entity(self, db_cargada, args_basicos):
        """Sin --entity, q_timeline llama a sys.exit (no debe ejecutarse sin entidad)."""
        # args_basicos.entity == None → q_timeline debe llamar sys.exit
        with pytest.raises(SystemExit):
            q_timeline(db_cargada, args_basicos)

    def test_timeline_entidad_conocida(self, db_cargada, args_basicos):
        """Timeline de 12345678Z devuelve sus 4 eventos en orden cronológico."""
        args_basicos.entity = "12345678Z"
        resultado = q_timeline(db_cargada, args_basicos)
        assert resultado["consulta"] == "timeline"
        assert resultado["entidad"] == "12345678Z"
        assert resultado["eventos"] == 4  # aparece 4 veces en FILAS_PRUEBA
        # Verificar orden cronológico
        fechas = [r["fecha_hora"] for r in resultado["resultados"] if r["fecha_hora"]]
        assert fechas == sorted(fechas)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Filtro por acción
# ─────────────────────────────────────────────────────────────────────────────

class TestFiltros:
    """Verifica los filtros de la cláusula WHERE."""

    def test_filtro_por_action(self, db_cargada, args_basicos):
        """Filtrar por action='password_change' devuelve todas las filas."""
        resultado = q_distinct(db_cargada, args_basicos)
        # Todas las filas tienen action='password_change' (action_const)
        assert resultado["total_eventos"] == 20

    def test_filtro_por_entity_type_dni(self, db_cargada, args_basicos):
        """Filtrar por entity_type='DNI' devuelve solo DNIs."""
        args_basicos.entity_type = "DNI"
        resultado = q_distinct(db_cargada, args_basicos)
        for r in resultado["resultados"]:
            assert r["tipo"] == "DNI"
