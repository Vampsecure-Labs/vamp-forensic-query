<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-forensic-query/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-forensic-query

© VampSecure Studios — VampSecure Labs Security Research Division

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

**Self-service forensic queries** over logs and user events, **without requiring an LLM**, that produce **court-ready evidence** on their own: a signed report, chain of custody (SHA-256 of sources), and a tamper-proof ZIP package (`MANIFEST.sha256`).

Designed to answer specific investigation questions — "how many distinct national IDs changed password in 2026, which ones and how many times?", "give me the exact timeline for this account" — in a **deterministic and reproducible** way.

### How it works
1. **Ingests** any tabular source (CSV/XLSX) into a normalized event model
   `(entity, type, action, datetime, IP, status, source)`.
2. **Auto-classifies** the entity: `DNI` (8 digits+letter), `NIE`, `CIF`, `email`, `IPv4`.
3. **Queries** via CLI (no AI): `distinct`, `top`, `timeline`, `events`, `sql`.
4. **Generates evidence**: for each query writes the result (CSV+JSON), a **forensic HTML report**
   (with the reproducible query, methodology, chain of custody and legal notice) and, with `--evidence`,
   a **signed ZIP** with `MANIFEST.sha256` for each artefact + `cadena_de_custodia.json`.

### Queries
| Query | Returns |
|-------|---------|
| `distinct` | Distinct entities + occurrence count, first/last event, number of IPs, and type distribution |
| `top` | Like `distinct` but only repeat offenders (`--min-count N`) |
| `timeline` | Exact chronology (datetime + IP + status) for one entity (`--entity`) |
| `events` | All events matching the applied filters |
| `sql` | Free `SELECT` (read-only) over the `events` table |

### Filters
`--action`, `--entity`, `--entity-type {DNI,NIE,CIF,email,IPv4,otro}`, `--ip`, `--year`,
`--from`/`--to` (YYYY-MM-DD), `--min-count`.

### Column mapping
With `--map role=column` or a reusable **profile** (`--profile client.json`):
```json
{ "sep": ";", "action_const": "password_change",
  "map": { "entity": "Usuario", "ts": "CreatedAt", "ip": "Datos" } }
```
`--action-const` fixes the action for the entire source (useful when the file contains a single event type,
e.g. a password-change export). `--sep` re-splits sources whose fields arrive in a single column.

### Examples
```bash
# How many distinct DNIs changed password in 2026 (+ signed evidence)
vamp_forensic_query.py Passwords.xlsx distinct \
  --profile client.json --year 2026 --entity-type DNI \
  --case "CASE-2026-001" --analyst "Expert — VampSecure Labs" --evidence

# Exact timeline for one account
vamp_forensic_query.py Passwords.xlsx timeline --profile client.json --entity 11723541G

# Repeat offenders (>=4 events) of all types, with evidence
vamp_forensic_query.py Passwords.xlsx top --profile client.json --action password_change \
  --year 2026 --min-count 4 --evidence

# Free query
vamp_forensic_query.py Access.csv sql --map entity=Usuario ts=Fecha ip=IP \
  --sql "SELECT ip, COUNT(DISTINCT entity) n FROM events GROUP BY ip HAVING n>=3 ORDER BY n DESC"
```

### Evidence output
Each query with `--evidence` produces in `--out`:
- `query_<UTC>.json` — result + metadata + reproducible query + chain of custody
- `query_<UTC>.csv` — tabulated result
- `query_<UTC>.html` — forensic report
- `query_<UTC>_evidence.zip` — sealed package (`MANIFEST.sha256` + `cadena_de_custodia.json`)

**Integrity:** any single-byte alteration to source files changes their SHA-256 and breaks the chain
of custody; any artefact alteration breaks its hash in the `MANIFEST`. Results are verifiable by
re-running the exact query over files with identical hashes.

### Installation

```bash
pip install vamp-forensic-query
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-forensic-query
```

### Requirements
- Python 3.9+ (stdlib). For `.xlsx` sources: `pip install pandas openpyxl`.

### Finding prefix
Not applicable (this is a query/evidence tool, not a detection tool). It complements
`vamp-log-analyzer` (FORA-NNN detection) by providing the ad-hoc query + evidence layer.

---

### Sample Output

```
$ vamp_forensic_query.py Passwords.xlsx distinct \
    --profile client.json --year 2026 --entity-type DNI \
    --case "CASE-2026-001" --analyst "Expert — VampSecure Labs" --evidence

 vamp-forensic-query v1.4 — VampSecure Labs
 Source: Passwords.xlsx  (SHA-256: 3a9f...c204)  |  Rows ingested: 18 432
 Profile: client.json  |  Entity type filter: DNI  |  Year: 2026
 Case: CASE-2026-001  |  Analyst: Expert — VampSecure Labs

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

 Evidence package written to ./CASE-2026-001/
   query_20261008T091203Z.json
   query_20261008T091203Z.csv
   query_20261008T091203Z.html
   query_20261008T091203Z_evidence.zip  (MANIFEST.sha256 included)
```

### Why vamp-forensic-query vs. Splunk · Elastic SIEM · manual SQL queries

| Capability | vamp-forensic-query | Splunk | Elastic SIEM | Manual SQL |
|---|---|---|---|---|
| Zero infrastructure — single Python script | ✅ | ❌ server required | ❌ cluster required | ⚠️ DB required |
| Chain-of-custody ZIP with SHA-256 manifest | ✅ | ❌ | ❌ | ❌ |
| ISO 27043 / RFC 3227 compliant evidence output | ✅ | ❌ | ❌ | ❌ |
| Auto-classification DNI / NIE / CIF / email / IPv4 | ✅ | ❌ manual regex | ❌ manual mapping | ❌ manual |
| Signed forensic HTML report | ✅ | ❌ | ❌ | ❌ |
| Ingest CSV + XLSX with column remapping | ✅ | ✅ | ✅ | ⚠️ import step |
| Streaming for sources >500 MB (zero RAM materialization) | ✅ | ✅ | ✅ | ⚠️ varies |
| Reproducible query embedded in evidence artefact | ✅ | ❌ | ❌ | ⚠️ manual |

- **Court-ready by design**: every `--evidence` run produces a sealed ZIP with a `MANIFEST.sha256` that cryptographically ties each artefact to the source files; any post-hoc alteration breaks the chain.
- **No infrastructure, no licence cost**: Splunk and Elastic require servers, ingestion pipelines, and licence agreements that take days to procure in an incident response scenario. `vamp-forensic-query` runs on a laptop in under a minute.
- **Entity-type awareness**: automatic classification of DNI, NIE, CIF, email, and IPv4 means investigators can ask "how many distinct DNIs?" without writing regex or custom ETL.
- **Forensic report as first-class output**: the generated HTML includes the exact query, methodology, legal disclaimer, and custody chain — ready to attach to a judicial proceeding without further editing.

### Check Coverage

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

### Version History

| Version | Main changes |
|---------|-------------|
| v1.4 | Bilingual README (EN/ES) |
| v1.3 | Streaming mode for logs >500 MB: `_read_rows` is a generator (zero RAM materialization), automatic SQLite on disk when source ≥500 MB; `--stream` flag to force it |
| v1.2 | Binary analysis (PE/ELF/ZIP/MACH-O), improved chain of custody |
| v1.1 | Advanced queries, SHA-256 signed evidence ZIP package |

---

<a name="español"></a>
## 🇪🇸 Español

Consultas **forenses self-service** sobre logs y eventos de usuario, **sin necesidad de un LLM**,
que generan por sí solas la **evidencia lista para peritaje**: informe firmado, cadena de custodia
(SHA-256 de las fuentes) y paquete ZIP a prueba de manipulación (`MANIFEST.sha256`).

Pensado para responder preguntas concretas de una investigación —"¿cuántos DNI distintos
cambiaron la contraseña en 2026, cuáles y cuántas veces?", "dame la cronología exacta de esta
cuenta"— de forma **determinista y reproducible**.

### Cómo funciona
1. **Ingesta** cualquier fuente tabular (CSV/XLSX) a un modelo normalizado de eventos
   `(entidad, tipo, acción, fecha_hora, IP, estado, fuente)`.
2. **Clasifica** la entidad automáticamente: `DNI` (8 díg.+letra), `NIE`, `CIF`, `email`, `IPv4`.
3. **Consulta** con la CLI (sin IA): `distinct`, `top`, `timeline`, `events`, `sql`.
4. **Genera evidencia**: por cada consulta escribe resultado (CSV+JSON), **informe pericial HTML**
   (con la consulta reproducible, metodología, cadena de custodia y nota legal) y, con `--evidence`,
   un **ZIP firmado** con `MANIFEST.sha256` de cada artefacto + `cadena_de_custodia.json`.

### Consultas
| Consulta | Qué devuelve |
|----------|--------------|
| `distinct` | Entidades distintas + nº de veces, primero/último evento, nº de IPs, y distribución por tipo |
| `top` | Como `distinct` pero solo reincidentes (`--min-count N`) |
| `timeline` | Cronología exacta (fecha-hora + IP + estado) de una entidad (`--entity`) |
| `events` | Todos los eventos que cumplen los filtros |
| `sql` | `SELECT` libre (solo lectura) sobre la tabla `events` |

### Filtros
`--action`, `--entity`, `--entity-type {DNI,NIE,CIF,email,IPv4,otro}`, `--ip`, `--year`,
`--from`/`--to` (YYYY-MM-DD), `--min-count`.

### Mapeo de columnas
Con `--map rol=columna` o un **perfil** reutilizable (`--profile cliente.json`):
```json
{ "sep": ";", "action_const": "password_change",
  "map": { "entity": "Usuario", "ts": "CreatedAt", "ip": "Datos" } }
```
`--action-const` fija la acción para toda la fuente (útil si el fichero es de un solo tipo de evento,
p. ej. un export de cambios de contraseña). `--sep` re-divide fuentes cuyos campos vienen en una sola
columna.

### Ejemplos
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

### Salida de evidencia
Cada consulta con `--evidence` produce en `--out`:
- `consulta_<UTC>.json` — resultado + metadatos + consulta reproducible + cadena de custodia
- `consulta_<UTC>.csv` — resultado tabulado
- `consulta_<UTC>.html` — informe pericial
- `consulta_<UTC>_evidencia.zip` — paquete sellado (`MANIFEST.sha256` + `cadena_de_custodia.json`)

**Integridad:** cualquier alteración de un byte de las fuentes cambia su SHA-256 y rompe la cadena
de custodia; cualquier alteración de un artefacto rompe su hash en el `MANIFEST`. Los resultados son
verificables reejecutando la consulta indicada sobre ficheros de idéntico hash.

### Instalación

```bash
pip install vamp-forensic-query
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-forensic-query
```

### Requisitos
- Python 3.9+ (stdlib). Para fuentes `.xlsx`: `pip install pandas openpyxl`.

### Prefijo de hallazgos
No aplica (es una herramienta de consulta/evidencia, no de detección). Complementa a
`vamp-log-analyzer` (detección FORA-NNN) aportando la capa de consulta ad-hoc + evidencia.

---

### Salida de ejemplo

```
$ vamp_forensic_query.py Contrasenas.xlsx distinct \
    --profile cliente.json --year 2026 --entity-type DNI \
    --case "CASO-2026-001" --analyst "Perito — VampSecure Labs" --evidence

 vamp-forensic-query v1.4 — VampSecure Labs
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

### Por qué vamp-forensic-query frente a Splunk · Elastic SIEM · consultas SQL manuales

| Capacidad | vamp-forensic-query | Splunk | Elastic SIEM | SQL manual |
|---|---|---|---|---|
| Sin infraestructura — script Python único | ✅ | ❌ servidor requerido | ❌ cluster requerido | ⚠️ BD requerida |
| ZIP de cadena de custodia con manifiesto SHA-256 | ✅ | ❌ | ❌ | ❌ |
| Salida de evidencia conforme ISO 27043 / RFC 3227 | ✅ | ❌ | ❌ | ❌ |
| Auto-clasificación DNI / NIE / CIF / email / IPv4 | ✅ | ❌ regex manual | ❌ mapeo manual | ❌ manual |
| Informe pericial HTML firmado | ✅ | ❌ | ❌ | ❌ |
| Ingesta CSV + XLSX con remapeo de columnas | ✅ | ✅ | ✅ | ⚠️ paso de importación |
| Streaming para fuentes >500 MB (cero materialización en RAM) | ✅ | ✅ | ✅ | ⚠️ variable |
| Consulta reproducible embebida en artefacto de evidencia | ✅ | ❌ | ❌ | ⚠️ manual |

- **Listo para el juzgado por diseño**: cada ejecución con `--evidence` produce un ZIP sellado con `MANIFEST.sha256` que vincula criptográficamente cada artefacto a los ficheros fuente; cualquier alteración posterior rompe la cadena.
- **Sin infraestructura, sin coste de licencia**: Splunk y Elastic requieren servidores, pipelines de ingesta y contratos de licencia que tardan días en conseguirse en un escenario de respuesta a incidentes. `vamp-forensic-query` funciona en un portátil en menos de un minuto.
- **Consciencia del tipo de entidad**: la clasificación automática de DNI, NIE, CIF, email e IPv4 permite a los investigadores preguntar "¿cuántos DNI distintos?" sin escribir regex ni ETL personalizado.
- **Informe pericial como salida de primer orden**: el HTML generado incluye la consulta exacta, metodología, aviso legal y cadena de custodia — listo para adjuntar a un procedimiento judicial sin edición adicional.

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|---|---|---|---|
| FQ-001 | SHA-256 del fichero fuente calculado y registrado en la cadena de custodia | ISO 27043 §10, RFC 3227 §2.2 | INFO |
| FQ-002 | MANIFEST.sha256 generado y verificado para todos los artefactos de evidencia | ISO 27043 §11 | INFO |
| FQ-003 | Auto-clasificación de entidad: patrón DNI (8 dígitos + letra de control) | ISO 27043 §8 | INFO |
| FQ-004 | Auto-clasificación de entidad: NIE (X/Y/Z + 7 dígitos + letra) | ISO 27043 §8 | INFO |
| FQ-005 | Auto-clasificación de entidad: CIF (letra + 7 dígitos + carácter de control) | ISO 27043 §8 | INFO |
| FQ-006 | Auto-clasificación de entidad: dirección email (patrón RFC 5321) | ISO 27043 §8 | INFO |
| FQ-007 | Auto-clasificación de entidad: dirección IPv4 | ISO 27043 §8 | INFO |
| FQ-008 | Cadena de consulta reproducible embebida en artefacto JSON de evidencia | RFC 3227 §2.1 | INFO |
| FQ-009 | Modo streaming activado para fuentes ≥ 500 MB (cero materialización en RAM) | ISO 27043 §9 | INFO |
| FQ-010 | Modo `--sql` impone solo SELECT (INSERT/UPDATE/DELETE/DROP rechazados) | ISO 27043 §10 | HIGH |

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.4 | README bilingüe (EN/ES) |
| v1.3 | Modo streaming para logs >500 MB: `_read_rows` es generador (cero materialización en RAM), SQLite en disco automático cuando fuente ≥500 MB; flag `--stream` para forzarlo |
| v1.2 | Análisis binario (PE/ELF/ZIP/MACH-O), cadena de custodia mejorada |
| v1.1 | Consultas avanzadas, paquete ZIP de evidencia firmado SHA-256 |
