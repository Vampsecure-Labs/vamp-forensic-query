<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-forensic-query/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-forensic-query

© VampSecure Studios — VampSecure Labs Security Research Division

Consultas **forenses self-service** sobre logs y eventos de usuario, **sin necesidad de un LLM**,
que generan por sí solas la **evidencia lista para peritaje**: informe firmado, cadena de custodia
(SHA-256 de las fuentes) y paquete ZIP a prueba de manipulación (`MANIFEST.sha256`).

Pensado para responder preguntas concretas de una investigación —"¿cuántos DNI distintos
cambiaron la contraseña en 2026, cuáles y cuántas veces?", "dame la cronología exacta de esta
cuenta"— de forma **determinista y reproducible**.

## Cómo funciona
1. **Ingesta** cualquier fuente tabular (CSV/XLSX) a un modelo normalizado de eventos
   `(entidad, tipo, acción, fecha_hora, IP, estado, fuente)`.
2. **Clasifica** la entidad automáticamente: `DNI` (8 díg.+letra), `NIE`, `CIF`, `email`, `IPv4`.
3. **Consulta** con la CLI (sin IA): `distinct`, `top`, `timeline`, `events`, `sql`.
4. **Genera evidencia**: por cada consulta escribe resultado (CSV+JSON), **informe pericial HTML**
   (con la consulta reproducible, metodología, cadena de custodia y nota legal) y, con `--evidence`,
   un **ZIP firmado** con `MANIFEST.sha256` de cada artefacto + `cadena_de_custodia.json`.

## Consultas
| Consulta | Qué devuelve |
|----------|--------------|
| `distinct` | Entidades distintas + nº de veces, primero/último evento, nº de IPs, y distribución por tipo |
| `top` | Como `distinct` pero solo reincidentes (`--min-count N`) |
| `timeline` | Cronología exacta (fecha-hora + IP + estado) de una entidad (`--entity`) |
| `events` | Todos los eventos que cumplen los filtros |
| `sql` | `SELECT` libre (solo lectura) sobre la tabla `events` |

## Filtros
`--action`, `--entity`, `--entity-type {DNI,NIE,CIF,email,IPv4,otro}`, `--ip`, `--year`,
`--from`/`--to` (YYYY-MM-DD), `--min-count`.

## Mapeo de columnas
Con `--map rol=columna` o un **perfil** reutilizable (`--profile cliente.json`):
```json
{ "sep": ";", "action_const": "password_change",
  "map": { "entity": "Usuario", "ts": "CreatedAt", "ip": "Datos" } }
```
`--action-const` fija la acción para toda la fuente (útil si el fichero es de un solo tipo de evento,
p. ej. un export de cambios de contraseña). `--sep` re-divide fuentes cuyos campos vienen en una sola
columna.

## Ejemplos
```bash
# Cuántos DNI distintos cambiaron contraseña en 2026 (+ evidencia firmada)
vamp_forensic_query.py Contrasenas.xlsx distinct \
  --profile cliente.json --year 2026 --entity-type DNI \
  --case "CASO-2026-001" --analyst "Perito — VampSecure Labs" --evidence

# Cronología exacta de una cuenta
vamp_forensic_query.py Contrasenas.xlsx timeline --profile cliente.json --entity 11723541G

# Reincidentes (>=4 eventos) de todos los tipos, con evidencia
vamp_forensic_query.py Contrasenas.xlsx top --profile cliente.json --action password_change \
  --year 2026 --min-count 4 --evidence

# Consulta libre
vamp_forensic_query.py Acceso.csv sql --map entity=Usuario ts=Fecha ip=IP \
  --sql "SELECT ip, COUNT(DISTINCT entity) n FROM events GROUP BY ip HAVING n>=3 ORDER BY n DESC"
```

## Salida de evidencia
Cada consulta con `--evidence` produce en `--out`:
- `consulta_<UTC>.json` — resultado + metadatos + consulta reproducible + cadena de custodia
- `consulta_<UTC>.csv` — resultado tabulado
- `consulta_<UTC>.html` — informe pericial
- `consulta_<UTC>_evidencia.zip` — paquete sellado (`MANIFEST.sha256` + `cadena_de_custodia.json`)

**Integridad:** cualquier alteración de un byte de las fuentes cambia su SHA-256 y rompe la cadena
de custodia; cualquier alteración de un artefacto rompe su hash en el `MANIFEST`. Los resultados son
verificables reejecutando la consulta indicada sobre ficheros de idéntico hash.

## Instalación

```bash
pip install vamp-forensic-query
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-forensic-query
```

## Requisitos
- Python 3.9+ (stdlib). Para fuentes `.xlsx`: `pip install pandas openpyxl`.

## Prefijo de hallazgos
No aplica (es una herramienta de consulta/evidencia, no de detección). Complementa a
`vamp-log-analyzer` (detección FORA-NNN) aportando la capa de consulta ad-hoc + evidencia.

---

## Sample Output

```
$ vamp_forensic_query.py Contrasenas.xlsx distinct \
    --profile cliente.json --year 2026 --entity-type DNI \
    --case "CASO-2026-001" --analyst "Perito — VampSecure Labs" --evidence

 vamp-forensic-query v1.3 — VampSecure Labs
 Source: Contrasenas.xlsx  (SHA-256: 3a9f...c204)  |  Rows ingested: 18 432
 Profile: cliente.json  |  Entity type filter: DNI  |  Year: 2026
 Case: CASO-2026-001  |  Analyst: Perito — VampSecure Labs

 Query: DISTINCT ─────────────────────────────────────────────────────────────────
 Entity          Type   Events   IPs   First event           Last event
 ─────────────────────────────────────────────────────────────────────────────────
 11723541G       DNI    14       5     2026-01-14 09:22:03   2026-09-30 17:41:10
 28901234A       DNI    9        3     2026-02-03 08:05:52   2026-08-11 16:30:07
 47812345B       DNI    7        1     2026-03-22 11:18:44   2026-09-01 09:55:30
 52934812C       DNI    4        2     2026-04-17 07:40:12   2026-07-29 14:22:03
 63801234D       DNI    3        1     2026-06-08 16:02:55   2026-09-12 10:41:57
 74523018E       DNI    2        1     2026-07-23 13:55:01   2026-09-28 08:17:44
 ─────────────────────────────────────────────────────────────────────────────────
 Totals: 6 distinct DNI  ·  39 events  ·  sources: 1

 Evidence package written to ./CASO-2026-001/
   consulta_20261008T091203Z.json
   consulta_20261008T091203Z.csv
   consulta_20261008T091203Z.html
   consulta_20261008T091203Z_evidencia.zip  (MANIFEST.sha256 included)
```

## Why vamp-forensic-query vs. Splunk · Elastic SIEM · consultas SQL manuales

| Capability | vamp-forensic-query | Splunk | Elastic SIEM | SQL manual |
|---|---|---|---|---|
| Zero infrastructure — single Python script | ✅ | ❌ server required | ❌ cluster required | ⚠️ DB required |
| Chain-of-custody ZIP with SHA-256 manifest | ✅ | ❌ | ❌ | ❌ |
| ISO 27043 / RFC 3227 compliant evidence output | ✅ | ❌ | ❌ | ❌ |
| Auto-classification DNI / NIE / CIF / email / IPv4 | ✅ | ❌ manual regex | ❌ manual mapping | ❌ manual |
| Signed pericial HTML report | ✅ | ❌ | ❌ | ❌ |
| Ingest CSV + XLSX with column remapping | ✅ | ✅ | ✅ | ⚠️ import step |
| Streaming for sources >500 MB (zero RAM materialization) | ✅ | ✅ | ✅ | ⚠️ varies |
| Reproducible query embedded in evidence artefact | ✅ | ❌ | ❌ | ⚠️ manual |

- **Court-ready by design**: every `--evidence` run produces a sealed ZIP with a `MANIFEST.sha256` that cryptographically ties each artefact to the source files; any post-hoc alteration breaks the chain.
- **No infrastructure, no licence cost**: Splunk and Elastic require servers, ingestion pipelines, and licence agreements that take days to procure in an incident response scenario. `vamp-forensic-query` runs on a laptop in under a minute.
- **Entity-type awareness**: automatic classification of DNI, NIE, CIF, email, and IPv4 means investigators can ask "how many distinct DNIs?" without writing regex or custom ETL.
- **Pericial report as first-class output**: the generated HTML includes the exact query, methodology, legal disclaimer, and custody chain — ready to attach to a judicial proceeding without further editing.

## Check Coverage

| Check ID | Description | Standard | Severity |
|---|---|---|---|
| FQ-001 | Source file SHA-256 computed and recorded in chain-of-custody | ISO 27043 §10, RFC 3227 §2.2 | INFO |
| FQ-002 | MANIFEST.sha256 generated and verified for all evidence artefacts | ISO 27043 §11 | INFO |
| FQ-003 | Entity auto-classification: DNI pattern (8 digits + checksum letter) | ISO 27043 §8 | INFO |
| FQ-004 | Entity auto-classification: NIE (X/Y/Z + 7 digits + letter) | ISO 27043 §8 | INFO |
| FQ-005 | Entity auto-classification: CIF (letter + 7 digits + control character) | ISO 27043 §8 | INFO |
| FQ-006 | Entity auto-classification: email address (RFC 5321 pattern) | ISO 27043 §8 | INFO |
| FQ-007 | Entity auto-classification: IPv4 address | ISO 27043 §8 | INFO |
| FQ-008 | Reproducible query string embedded in JSON evidence artefact | RFC 3227 §2.1 | INFO |
| FQ-009 | Streaming mode activated for sources ≥ 500 MB (zero RAM materialization) | ISO 27043 §9 | INFO |
| FQ-010 | `--sql` mode enforces SELECT-only (INSERT/UPDATE/DELETE/DROP rejected) | ISO 27043 §10 | HIGH |

---

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.3 | Modo streaming para logs >500 MB: `_read_rows` es generador (cero materialización en RAM), SQLite en disco automático cuando fuente ≥500 MB; flag `--stream` para forzarlo |
| v1.2 | Análisis binario (PE/ELF/ZIP/MACH-O), cadena de custodia mejorada |
| v1.1 | Consultas avanzadas, paquete ZIP de evidencia firmado SHA-256 |
