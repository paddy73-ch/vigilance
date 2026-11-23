# Plan: GHSA-Sync auf entdeckte Pakete beschränken (Option 2)

## Ziel
GHSA-Sync soll nur CVE-Daten für Pakete laden, die in den entdeckten Containern tatsächlich vorhanden sind. Das reduziert GitHub API Rate-Limit-Verbrauch, beschleunigt den Sync und hält die DB kompakt.

## Aktueller Stand
- OSV Sync (`sync.py:34-36`): Übergibt bereits `DiscoveredTool`-Objekte an `sync_osv_for_tools()` — filtert bereits tool-spezifisch.
- GHSA Sync (`sync.py:41`): Ruft `sync_ghsa(max_pages=max_pages)` auf ohne Paket-Filter — lädt alle Advisories.
- Matcher (`matcher.py:106`): `match_tool_against_cves()` vergleicht entdeckte Tools mit allen geladenen CVE-Einträgen.
- GitHub Advisory API unterstützt kein server-seitiges Package-Filter-Query-Parameter → Filterung muss client-seitig erfolgen.

## Design-Entscheidung: Option 2 (nur für vorhandene Tools)
Begründung: Lädt nur relevante CVEs, spart API-Rate-Limit, schnellerer Sync, kleinere DB. Ergebnis ist identisch zu Option 1 (Matcher arbeitet ohnehin nur mit entdeckten Tools).

## Implementierungsschritte

### 1. `sync_ghsa()` Paket-Filter-Parameter hinzufügen (`vigilance/cve/ghsa.py`)
- `fetch_advisories()` erhält optionalen Parameter `package_names: Optional[List[str]] = None`
- Nach jedem API-Abruf (pro Seite) werden Advisories gefiltert: nur solche behalten, deren `repo`/`package` in `package_names` vorkommt.
- Fortschritts-Logging pro Seite beibehalten.
- Bei leerem `package_names`: Fallback auf `max_pages` (kleine Anzahl) für Initial-Sync.

### 2. `sync_cve_source()` / `CVESyncOrchestrator.sync_all()` anpassen (`vigilance/cve/sync.py`)
- Vor dem GHSA-Sync: `DiscoveredTool`-Einträge aus DB laden (`tool_name` extrahieren).
- `package_names` Liste an `sync_ghsa()` übergeben.
- Wenn keine Tools in DB: Fallback auf `max_pages=1` (oder konfigurierten Wert).

### 3. CRUD-Helfer für Tool-Namen (`vigilance/database/crud.py`)
- Optional: `get_discovered_tool_names(db)` → `List[str]` — extrahiert eindeutige `tool_name` Werte aus `discovered_tools`.

### 4. Konfiguration (`vigilance/config.py`)
- `max_pages` Default bleibt bei 1 (schneller Initial-Sync bei leerem Tool-Bestand).
- Keine neuen Config-Felder nötig.

## Validierung
- GHSA Sync mit entdeckten Tools: lädt nur relevante Advisories, Status "success", Einträge > 0.
- GHSA Sync ohne entdeckte Tools: Fallback auf `max_pages=1`, lädt 100 neueste Advisories.
- CVE Sync API (`POST /api/cves/sync?source=ghsa`): funktioniert ohne Auth (bereits umgesetzt).
- Manueller Test im Container: `sync_cve_source("ghsa")` schließt in < 60s ab.

## Offene Fragen (keine Blockierer)
- Soll der Fallback bei leerem Tool-Bestand konfigurierbar sein? (Empfehlung: nein, `max_pages=1` reicht für Initial-Sync.)
- Sollen andere Quellen (NVD, Debian, Ubuntu) ebenfalls tool-filtert werden? (Empfehlung: nein, die laden bereits pro Suite/Release und sind geringer volumig.)

## Risiken
- Bei neu entdeckten Tools nach dem Sync fehlen deren CVEs bis zum nächsten Sync-Lauf. Das ist akzeptabel, da der Scan-Job separat läuft und der CVE-Sync täglich um 07:00 UTC wiederholt wird.
- GitHub API Rate Limit bleibt bei leerem Tool-Bestand (Fallback auf 100 Advisories).
