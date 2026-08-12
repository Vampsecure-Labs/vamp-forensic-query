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

## Requisitos
- Python 3.9+ (stdlib). Para fuentes `.xlsx`: `pip install pandas openpyxl`.

## Prefijo de hallazgos
No aplica (es una herramienta de consulta/evidencia, no de detección). Complementa a
`vamp-log-analyzer` (detección FORA-NNN) aportando la capa de consulta ad-hoc + evidencia.
