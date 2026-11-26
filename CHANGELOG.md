# Changelog

Alle nennenswerten Änderungen an Vigilance. Die Einträge bis 0.12.0 stammen aus den Pull Requests des
ursprünglichen, privaten Repositorys; dessen Geschichte wurde vor der Veröffentlichung bereinigt.

## 0.18.2 – 2026-11-26

### Behoben
- **Kernel-Lücken auf `linux-libc-dev`:** Debian führt jede Kernel-Lücke beim Quellpaket `linux`, aus dem
  auch `linux-libc-dev` stammt (Header-Dateien zum Kompilieren, kommt mit gcc). Vigilance zeigte deshalb
  auf pve und einigen Containern je über 300 offene, teils kritische Lücken, obwohl dort kein Debian-Kernel
  installiert ist. Sind auf einem Host aus `linux` nur Header- oder Build-Pakete installiert
  (`linux-libc-dev`, `linux-headers-*`, `linux-kbuild-*`), stehen diese Befunde jetzt unter „Nicht
  betroffen“ mit dem Grund „nur Kernel-Header, kein Kernel“. Ist daneben ein Debian-Kernel installiert,
  bleiben sie offen.
- Der Filter „Anderes OS“ und der Abschnitt „Anderes Betriebssystem“ heissen jetzt „Nicht betroffen“, weil
  dort beide Gründe stehen.

## 0.18.1 – 2026-11-26

### Neu
- **Home Assistant OS wird erkannt** und lässt sich wie Windows nicht für den Scan aktivieren: Der
  Menüpunkt ist ausgegraut, ein (i) erklärt den Grund, als System steht „Home Assistant OS“. Erkannt über
  den Guest Agent einer laufenden VM (Recht `VM.GuestAgent.Audit`), sonst über „haos“ oder „Home
  Assistant OS“ in Name oder Beschreibung. Eine VM namens „homeassistant“ gilt nicht als HAOS, weil
  Home Assistant auch auf Debian laufen kann.

## 0.18.0 – 2026-11-26

### Neu
- **Container über den Proxmox-Host abfragen (`pct exec`):** Vigilance meldet sich als `vigilance-scan`
  auf dem Host an und führt Scan, Prüfungen, eigene Checks und Aktionen mit `sudo pct exec <id> -- …`
  aus. In den Containern braucht es dann weder Schlüssel noch sshd noch IP; auch Container mit DHCP ohne
  gemeldete Adresse werden gescannt. Einstellbar pro Node unter Verwaltung › Einstellungen › Proxmox und
  SSH („Zugang zu den Containern“) oder mit `container_access` in `config.yaml`. Standard für neue
  Installationen ist `pct`; bestehende behalten SSH (Migration 007), bis man umschaltet. Die nötige
  sudo-Regel steht im README. Fehlt sie, steht das beim Container. VMs bleiben bei SSH.
- **Hosts werden parallel gescannt:** Bisher kam ein Container nach dem anderen dran. Jetzt liest
  Vigilance bis zu `ssh.parallel_jobs` Container und VMs gleichzeitig und speichert danach der Reihe nach.
  Über `pct` sind es höchstens 8 gleichzeitig pro Node, weil sshd standardmässig 10 Sitzungen pro
  Verbindung erlaubt.

## 0.17.3 – 2026-11-26

### Behoben
- In Proxmox gelöschte Container und VMs (`pct destroy`, `qm destroy`) blieben in Vigilance stehen. Jetzt
  entfernt der nächste Scan sie samt Paketen, Befunden, hostbezogenen Ausnahmen und der Scan-Einstellung
  der VM; der Verlauf der Aktionen bleibt, ohne Verweis auf den Host. Meldet Proxmox gar keine Container
  bzw. VMs, obwohl Vigilance welche kennt, wird nichts entfernt (Token ohne VM.Audit liefert eine leere
  Liste statt eines Fehlers).

## 0.17.2 – 2026-11-26

### Neu
- Windows-VMs haben in der Hostliste und auf ihrer Hostseite ein (i) neben dem Namen. Es erklärt, warum
  Vigilance sie nicht scannt: kein Paketverwalter wie dpkg, apk oder rpm, und Microsoft veröffentlicht
  Lücken pro Windows-Build und Update (KB), nicht pro Paket. Als System steht „Windows“.

### Dokumentation
- README mit Screenshots (Übersicht, Host, offene CVEs mit Fix), hell und dunkel je nach Einstellung
  von GitHub. Aufgenommen mit einer Demo-Kopie: Namen und Adressen geändert, Befunde echt.

## 0.17.1 – 2026-11-26

### Geändert
- Einstellungen: „Meldungen bei neuen Befunden senden“, „Sammelmeldung statt einzelner Meldungen“ und
  „Schlüssel in neue Container selbst eintragen“ sind Schiebeschalter wie bei den CVE-Quellen statt
  Häkchen.

## 0.17.0 – 2026-11-26

### Neu
- **CVE-Abgleich „Nach Scan“:** Im Zeitplan des CVE-Abgleichs gibt es neben „Alle … Stunden“ und „Feste
  Uhrzeiten“ die Wahl „Nach Scan“. Der Abgleich hat dann keine eigenen Läufe mehr und startet, sobald ein
  Scan beendet ist, ob geplant oder von Hand gestartet. Im Feld steht „Nach jedem Scan“, darunter der
  nächste Scan. Schlägt ein Scan fehl, entfällt der Abgleich bis zum nächsten Scan.

## 0.16.0 – 2026-11-26

### Neu
- **Zeitplan mit Uhr:** Neben „Scan alle … Stunden“ und „CVE-Abgleich alle … Stunden“ öffnet ein
  Uhrsymbol den Zeitplan. Dort wählst du statt eines Intervalls feste Uhrzeiten, bis zu zwölf pro Tag, auf
  einer analogen Uhr wie bei Android: zuerst die Stunde (innen 00 und 13–23), dann die Minute; Pfeiltasten
  gehen auch. Wochentage lassen sich abwählen. Es gilt die Zeitzone des Browsers. Unter den Feldern steht
  der nächste Lauf.

### Behoben
- Mit `full_scan_on_start: false` lief der regelmässige Scan nie: Der Auftrag wurde pausiert angelegt.
- `deploy.sh` räumt nach einem erfolgreichen Deployment das alte, nicht mehr getaggte Image weg. Bisher
  blieb pro Deployment eines liegen, bis die Disk von CT 123 voll war und der Build abbrach.

## 0.15.0 – 2026-11-26

### Neu
- **Schlüssel in neue Container selbst eintragen:** Schalter unter Verwaltung › Einstellungen › Proxmox
  und SSH (aus als Standard). Lehnt ein laufender Container den Schlüssel von Vigilance ab, trägt der
  Proxmox-Host ihn über `scripts/vigilance-install-key` ein, und der Scan geht weiter. Das Skript hat den
  Schlüssel fest eingebaut und läuft über eine eigene sudo-Regel für `vigilance-scan`. Fehlt die Regel,
  steht das beim Host.

## 0.14.1 – 2026-11-26

### Behoben
- „Jetzt scannen“ in der Übersicht startete keinen Scan, sondern meldete `Field required`: Der Endpunkt
  `POST /api/scans/trigger` verlangte einen JSON-Body. Der Body ist jetzt optional.
- Scheitert die SSH-Verbindung, nennt Vigilance den Grund statt pauschal „Failed to connect“: Schlüssel
  nicht eingetragen, keine Verbindung, keine Antwort, Host-Schlüssel unbekannt oder geändert.

## 0.14.0 – 2026-11-25

### Neu
- **VMs per Rechtsklick für den Scan aktivieren:** In der Hostliste öffnet ein Rechtsklick auf eine VM
  (oder ihr ⋯-Button) ein Menü mit „Für den Scan aktivieren …“ bzw. „Scan deaktivieren“. Beim Aktivieren
  lässt sich eine IP angeben (sonst der Guest Agent); der Dialog zeigt den Befehl, um den Schlüssel von
  Vigilance in der VM einzutragen, und danach startet ein Scan. Die Wahl liegt in der Datenbank und gilt
  vor `vms:` in `config.yaml`. Windows-VMs lassen sich nicht aktivieren.
- Laufende VMs, die nicht gescannt werden, stehen in einer eigenen Gruppe „Läuft, nicht gescannt“; die
  Übersicht zählt sie nicht als Problem.

## 0.13.1 – 2026-11-25

### Neu
- Hosts: Die Spalte „Host“ ist aufgeteilt in Name, Typ (CT, VM, Host) und Nr. Alle Spalten lassen sich
  per Klick auf den Titel sortieren (auf, ab, zurück zu „dringendste zuerst“); die Sortierung steht in der
  Adresse. Auf dem Handy gibt es dafür eine Auswahlliste.
- Unter „Gestoppt“ stehen alle gestoppten Hosts, auch VMs, die nicht für den Scan eingetragen sind (mit
  Hinweis). Der Scan erfasst dafür Name und Zustand aller VMs; gescannt werden weiterhin nur die unter
  `vms:` eingetragenen.

## 0.13.0 – 2026-11-25

### Neu
- **Protokoll der Behebungen** (`/vulnerabilities/fixed`): „behoben in 7 Tagen“ in der Übersicht führt
  dorthin. Ein Eintrag je Paket, Host und Tag, gegliedert nach Tag, mit Zeitraum- und Hostfilter. „Wie“
  liest Vigilance aus dem heutigen Stand des Pakets: Update (vorher und heute installierte Version),
  Paket entfernt oder Meldung trifft nicht mehr zu. Die Meldungen öffnen die Detailansicht.

### Behoben
- Die Seite Aktionen sagte noch, der Proxmox-Host werde nie verändert, und nannte Hosts „Container“.

## 0.12.1 – 2026-11-25

### Behoben
Gefunden in automatischen Reviews der bisherigen Pull Requests, jeweils mit einem Test, der ohne die
Korrektur fehlschlägt:
- „Vorschläge umsetzen“ schlug ein Update auch vor, wenn die Paketquelle nur eine Version unter der
  Fix-Version anbot; die Lücke wäre offen geblieben.
- Antwortete auf einem Host ein Paketmanager und ein anderer nicht, galten die Pakete des stummen als
  entfernt und ihre Befunde als behoben.
- Ein Ablaufdatum mit Zeitzone wurde bei Ausnahmen ohne Umrechnung nach UTC gespeichert.
- Eine Ausnahme auf einer DSA-Meldung galt nicht für die `DEBIAN-CVE`-Meldung derselben CVE, und die
  Detailansicht zeigte nur die Hosts der angeklickten Meldung.
- `vigilance scan-now` meldete einen fehlgeschlagenen Scan als abgeschlossen.
- Alte Links `/cves?cve_id=…` verloren die gesuchte Meldung.
- Das Alter der Paketlisten zeigte nach jeder Installation „gerade aktualisiert“ (`pkgcache.bin`); jetzt
  zählt die letzte Änderung der Listendateien.
- Der Status „alle“ in der Schwachstellen-API enthielt Befunde ausgeschalteter Quellen.

### Geändert
- Interne Adressen in Tests, Beispielen und Doku durch die Dokumentations-Netze 192.0.2.0/24 und
  198.51.100.0/24 (RFC 5737) ersetzt.
- `deploy.sh` liest das Ziel aus `~/.config/vigilance/deploy.env` oder der Umgebung statt aus dem Skript.
- README überarbeitet: Er beschrieb noch einen fest eingebauten SSH-Schlüssel mit automatischer
  Verteilung, Webhooks und eine MIT-Lizenz, die es alle nicht gibt; Aktionen, VMs, Proxmox-Host und
  Quellen-Schalter fehlten.
- `ansible/` durch `scripts/distribute-ssh-key.sh` ersetzt. Das alte Skript trug einen fest eingetragenen,
  nicht mehr gültigen Schlüssel ein; die Playbooks nutzten einen gelöschten Token.
- `docs/SECURITY-ROTATION.md` entfernt (internes Protokoll einer abgeschlossenen Rotation).
- Ungültige Ruff-Regel `PER` aus `pyproject.toml` entfernt; `ruff check` lief deshalb gar nicht.

## 0.12.0 – 2026-11-24

### Neu
- **VMs wie Container:** VMs, die in `config.yaml` beim Node unter `vms:` stehen, werden per SSH gescannt
  und lassen sich mit „Vorschläge umsetzen“ und „Vollständiges Upgrade“ aktualisieren.
  - Die IP kommt aus `config.yaml` oder vom QEMU Guest Agent. Fehlt dem Proxmox-Token das Recht
    `VM.GuestAgent.Audit` oder antwortet der Agent nicht, nennt die Host-Ansicht den Grund.
  - Windows-VMs werden mit Hinweis übersprungen. Nicht eingetragene VMs erscheinen nirgends.
  - „Alle“ auf der Seite Hosts umfasst Container und eingetragene VMs, nie den Proxmox-Host.
  - „Kernel aufräumen“ gibt es in VMs nicht; der Dialog weist darauf hin, dass ein neuer Kernel erst nach
    einem Neustart der VM aktiv wird.

## 0.11.0 – 2026-11-24

### Neu
- **Gotify unter Verwaltung › Einstellungen:** aktiv, Adresse, App-Token, Mindest-Schwere, Sammelmeldung.
  Gespeicherte Werte gelten vor `.env` und `config.yaml`. Der Token wird nie angezeigt und bei einer
  Testnachricht nicht an eine andere als die gespeicherte Adresse geschickt.
- **CVE-Quellen ein- und ausschalten** (Verwaltung › Quellen). Ausschalten blendet die Befunde der Quelle
  aus und merkt sich ihren Status; Einschalten holt sie zurück und gleicht die Quelle neu ab.
- **„Grenzen“ oben rechts als Umschalter:** Ein zweiter Klick führt zur vorherigen Seite und Scrollposition
  zurück.

### Geändert
- Ist Gotify aus oder unvollständig, versucht Vigilance nicht mehr zu melden.
- `docs/LIMITATIONS.md`: Quellen schalten, Speicherort des Gotify-Tokens, neuer Abschnitt „Zugriff“.

## 0.10.2 – 2026-11-24

### Neu
- In der Übersicht führen „Altpaket entfernen“ und „Update“ zum betroffenen Host oder zur Hostliste,
  gefiltert auf die betroffenen Hosts.
- Zurück-Pfeil in der Host-Ansicht.

## 0.10.1 – 2026-11-24

### Geändert
- „Vorschläge umsetzen“ ist deaktiviert, wenn es nichts umzusetzen gibt. Geprüft wird mit denselben
  Regeln wie bei der Ausführung (`GET /api/actions/available`).

## 0.10.0 – 2026-11-24

### Neu
- Die Übersicht zeigt Container mit überflüssigen Kernel-Paketen; ein Klick öffnet die Vorschau zum
  Entfernen.
- Aktionen für mehrere Hosts laufen parallel (bis zu 4). Ein Host mit `apt-cacher-ng` kommt zuerst und
  allein dran.
- GitHub Actions: Unit-Tests auf SQLite und PostgreSQL, Browser-Tests.
- `VIGILANCE_PUBLIC_URL` für Links in Benachrichtigungen.

### Behoben
- Gotify-Meldungen zu einzelnen neuen Befunden brachen ab (Nachladen im async-Code, falsches Feld für die
  Fix-Version, Link auf die Proxmox-URL statt auf Vigilance).

## 0.9.1 – 2026-11-24

### Neu
- Neues Logo und Favicons.
- Schalter für hellen und dunklen Modus; ohne Wahl folgt Vigilance dem System.

### Behoben
- Ein Browser-Test las die Detailansicht, bevor sie geladen war, und schlug zeitweise fehl.

## 0.9.0 – 2026-11-24

### Neu
- **Aktionen auf dem Proxmox-Host:** „Vorschläge umsetzen“ und `dist-upgrade`, nur einzeln, nur nach
  ausdrücklicher Bestätigung und nur mit einer sudo-Regel für `apt-get`. apt läuft auf dem Host losgelöst
  von der SSH-Verbindung; Vigilance fragt das Ergebnis ab.
- **Kernel im Container:** Der Scan findet Kernel-Pakete in Containern (die dort nie geladen werden) und
  simuliert ihr Entfernen. Eigener Schritt „Kernel aufräumen“; „Vorschläge umsetzen“ nimmt ihn nur mit,
  wenn nichts ausser Kernel-Paketen wegfällt.
- Link „Grenzen“ in der Kopfzeile und in der Fusszeile.

### Behoben
- „Kopieren“ funktioniert auch ohne HTTPS.

## 0.8.1 – 2026-11-24

### Neu
- `docs/LIMITATIONS.md`, angezeigt unter Verwaltung › Grenzen: was Vigilance nicht sieht oder nur ungenau
  beurteilt.
- (i)-Hinweise, zum Beispiel bei Tailscale-Befunden zur betroffenen Funktion.

## 0.8.0 – 2026-11-24

### Neu
- **Tailscale Security Bulletins** als Quelle, nur abgefragt, wenn `tailscale` installiert ist. Fix-Versionen
  und Plattformen werden aus dem Text gelesen; Bulletins zu anderen Produkten erzeugen keinen Befund.
- Pakete aus fremden Paketquellen werden unterschieden in „Geprüft“ (über ein Go-Modul), „Nur
  Debian-Daten“ (z. B. Proxmox-Builds von Debian-Paketen) und „Keine Sicherheitsdaten“.

## 0.7.0 – 2026-11-24

### Neu
- **Betriebssystem einer Meldung:** Nennt die Go-Datenbank betroffene Systeme ohne Linux, steht der Befund
  unter „Anderes OS“. Steht ein anderes System nur im Text, zeigt Vigilance einen Hinweis und blendet
  nichts selbst aus.

## 0.6.0 – 2026-11-24

### Neu
- Herkunft jedes Pakets (Paketquelle) im Host-Detail.
- `tailscale`, `crowdsec` und `containerd.io` aus Herstellerquellen werden über ihr Go-Modul geprüft.
  `docker-ce` bleibt bewusst ohne Zuordnung (keine verlässlichen Fix-Versionen).

### Behoben
- Das Alter der Paketlisten zeigte den Zeitstempel des Debian-Servers statt des letzten `apt update`.

## 0.5.0 – 2026-11-24

### Neu
- **Aktionen:** Updates und das Entfernen von Altpaketen aus Vigilance heraus ausführen, mit Vorschau per
  Simulation, Ausführung im Hintergrund und Verlauf (Befehle, Ausgabe, Exit-Code).
- Der Scan erfasst, welche Fixes in den Paketquellen verfügbar sind (`apt list --upgradable`).

## 0.4.0 – 2026-11-24

### Neu
- Optionaler Scan des Proxmox-Hosts mit eigenem Benutzer ohne Root-Rechte.
- Die Risikoprüfung erkennt den laufenden Kernel und sagt, wenn sie ohne Root nicht alles prüfen konnte.

## 0.3.0 – 2026-11-24

### Neu
- **Lösungsvorschlag** zu jedem Befund mit Fix: Befehl für Update oder Entfernen, mit dem installierten
  Nachfolger.
- **Risikoprüfung vor dem Entfernen** (nur lesend): was apt zusätzlich entfernen würde, laufende Prozesse
  mit geladener Bibliothek, Programme unter `/usr/local` und `/opt`, ob die Version wieder installierbar
  ist.
- Eine Zeile pro Lücke: Advisories zur selben CVE (z. B. `DEBIAN-CVE-…` und `DSA-…`) werden zusammengeführt.

### Geändert
- Altpakete heissen nach dem installierten Paket (z. B. `libapt-pkg6.0`), nicht nach dem Quellpaket.

### Behoben
- Die apt-Simulation schrieb trotz `-s` die Datei `eipp.log` neu; jetzt ändert die Risikoprüfung nichts mehr.

## 0.2.0 – 2026-11-24

### Neu
- **Neue Oberfläche** mit vier Bereichen: Übersicht, Hosts, Schwachstellen, Verwaltung. Eigenes CSS ohne
  CDN, strenge Content-Security-Policy, Handy-Layout.
- Altpakete nach einem Release-Upgrade werden erkannt und als „Entfernen“ vorgeschlagen.
- Gestoppte Container und Container ohne IP werden mit Grund erfasst; Container mit DHCP bekommen ihre IP
  über die Proxmox-API.
- Nicht mehr installierte Pakete werden erkannt, ihre Befunde gelten als behoben.

## 0.1.0 – 2026-11-21 bis 2026-11-24

### Neu
- Erste Version: Inventar über die Proxmox-API, Paket-Scan per SSH, Abgleich mit CVE-Quellen,
  Benachrichtigung über Gotify.
- CVE-Daten werden nur für die gefundenen Pakete und passend zum Release abgefragt (OSV mit `Debian:13`
  usw.); Ablauf Scan → Abgleich → Auswertung. Debian-Versionsvergleich nach dpkg-Regeln, CVSS-Berechnung.
- Befunde, die nicht mehr zutreffen, gelten als behoben statt gelöscht zu werden.

### Sicherheit
- Änderungen nur mit API-Token; der `Remote-User`-Header gilt nur von eingetragenen Proxys.
- Der SSH-Schlüssel wird pro Installation erzeugt; ein fest eingebauter Schlüssel wurde entfernt.
