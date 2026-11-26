# Grenzen von Vigilance

Vigilance zeigt, welche bekannten Sicherheitslücken die installierten Pakete betreffen und wie sie sich
beheben lassen. Diese Seite beschreibt, was Vigilance dabei **nicht** sieht oder nur ungenau beurteilen
kann. Ein leerer Bereich in Vigilance heisst deshalb nicht „sicher“, sondern „keine bekannte Lücke in den
geprüften Daten“.

## Was gescannt wird

- **LXC-Container** auf dem Proxmox-Host, per SSH als root. Gestoppte Container werden nicht gescannt,
  ihre Angaben stammen vom letzten erfolgreichen Scan.
- **Der Proxmox-Host selbst**, wenn `scan_host: true` gesetzt ist, als Benutzer `vigilance-scan` ohne
  Root-Rechte.
- **VMs** (QEMU) nur, wenn sie für den Scan aktiviert sind: per Rechtsklick (oder ⋯) in der Hostliste
  oder in `config.yaml` unter `vms:` beim Node; die Wahl in der Oberfläche gilt vor `config.yaml`. Sie
  werden wie Container gescannt und behandelt: per SSH als root mit dem Schlüssel von Vigilance, nur mit
  apt (Debian, Ubuntu). Die IP kommt aus der Aktivierung, aus `config.yaml` oder vom QEMU Guest Agent;
  dafür braucht der Proxmox-Token das Recht `VM.GuestAgent.Audit`. Nicht aktivierte VMs stehen in der
  Hostliste unter „Läuft, nicht gescannt“ bzw. „Gestoppt“; in der Übersicht zählen sie nicht mit.
- **Nicht gescannt werden** Windows-VMs (auch wenn eingetragen) und Home Assistant OS: Beide haben kein
  apt, und Home Assistant OS lässt sich nicht wie ein Debian-System aktualisieren.
- Erfasst werden die Pakete des Paketmanagers (dpkg, apk, rpm). **Nicht erfasst** werden:
  - Docker-Container und -Images und die Software darin (die Docker-Erkennung ist ausgeschaltet)
  - Sprachpakete ausserhalb des Paketmanagers: pip in virtuellen Umgebungen, npm, Go- und Rust-Programme,
    selbst kompilierte Software unter `/usr/local` oder `/opt`
  - Snap, Flatpak, AppImage
  - Firmware und Microcode, die nicht als Paket installiert sind

## Woher die Sicherheitsdaten kommen

| Pakete | Quelle | Genauigkeit |
|---|---|---|
| Debian- und Ubuntu-Pakete aus den offiziellen Paketquellen | OSV mit dem Debian-/Ubuntu-Release des Hosts (z. B. `Debian:13`) | gut: Debian hat die Version für genau dieses Release bewertet |
| `tailscale`, `crowdsec`, `containerd.io` aus Herstellerquellen | OSV/GitHub über das Go-Modul | gut für Versionen; das Betriebssystem fehlt meist (siehe unten) |
| `tailscale` zusätzlich | Tailscale Security Bulletins (RSS) | mittel: Versionen und Plattformen werden aus dem Text gelesen |
| Proxmox-Builds von Debian-Paketen (apparmor, corosync, ceph, grub …) | Debian-Daten unter gleichem Namen | ungenau: installiert ist der Build von Proxmox, nicht die Debian-Version |
| Proxmox-eigene Pakete (`pve-*`, `proxmox-*`, `libpve-*`), `docker-ce` und weitere Herstellerpakete | keine | **nicht geprüft**; das Host-Detail listet sie unter „Pakete aus fremden Paketquellen“ |

`docker-ce` ist bewusst keinem Go-Modul zugeordnet: Unter `github.com/docker/docker` haben die Meldungen
keine Fix-Version (jede Version gälte als betroffen), und die Versionen von Docker 29 lassen sich nicht
verlässlich auf `github.com/moby/moby/v2` abbilden.

NVD, der Debian Security Tracker und Ubuntu sind standardmässig ausgeschaltet. OSV enthält die Debian-
und Ubuntu-Daten bereits; NVD kennt keine Paketversionen der Distributionen und würde nach Namen raten.

Unter Verwaltung, Quellen lässt sich jede Quelle ein- und ausschalten; die Wahl dort gilt vor
`config.yaml`. Ausschalten blendet die Befunde der Quelle sofort aus (sie zählen nirgends mehr mit),
löscht sie aber nicht. Einschalten holt sie mit ihrem früheren Status zurück und gleicht die Quelle neu
ab. Ohne OSV fehlen fast alle Befunde zu Debian-Paketen. Eine Lücke, die mehrere Quellen melden, bleibt
sichtbar, solange eine davon eingeschaltet ist.

## Ob eine Lücke im Einzelfall zutrifft

- **Konfiguration und Nutzung:** Vigilance sieht nur, dass eine betroffene Version installiert ist. Ob
  der Dienst läuft, von aussen erreichbar ist oder die betroffene Funktion überhaupt genutzt wird, sieht
  es nicht. Beispiel: Ein Tailscale-Bulletin zu Serve, SSH oder Funnel wird gemeldet, auch wenn diese
  Funktion auf dem Host nicht aktiv ist.
- **Betriebssystem:** Alle gescannten Hosts laufen unter Linux. Meldungen, die laut Daten nur andere
  Systeme betreffen, stehen unter „Anderes OS“. Das klappt nur, wenn die Daten das Betriebssystem
  strukturiert angeben (Go-Datenbank, Feld `goos`, bei Tailscale die Zeile „Affected platforms“). Steht es
  nur im Text, zeigt Vigilance „laut Meldung nur …“ und blendet nichts selbst aus.
- **Schwere:** Vigilance übernimmt die Bewertung aus den Daten (CVSS, sonst Debian-Dringlichkeit) und
  passt sie nicht an deine Umgebung an. Viele neue Meldungen haben noch keine Bewertung („Ohne Bewertung“).
- **„Debian: unwichtig“** ist die Einschätzung des Debian-Sicherheitsteams, nicht von Vigilance.

## Tailscale Security Bulletins

- Abgefragt nur, wenn auf einem Host ein Paket `tailscale` installiert ist.
- Fix-Versionen werden mit festen Formulierungen aus dem Text gelesen. Bulletins, bei denen das nicht
  gelingt, erzeugen keinen Befund und werden auf der Seite „Quellen“ genannt.
- Bulletins zum Koordinationsserver, zum Kubernetes-Operator, zu libtailscale, DERP oder
  proxy-to-grafana erzeugen keinen Befund für das Paket `tailscale`.
- Tailscale veröffentlicht nicht jede behobene Lücke als Bulletin (zum Beispiel keine Updates von
  Abhängigkeiten). Diese fehlen.

## Lösungsvorschläge

- **Updates:** Der Scan liest `apt list --upgradable` aus den vorhandenen Paketlisten, ohne `apt update`.
  Ist die Liste alt, kann ein Fix fehlen, der schon verfügbar wäre. Das Alter der Listen wird angezeigt.
  Es ist die letzte Änderung der Listendateien; hat sich auf dem Server seither nichts geändert, kann das
  letzte `apt update` jünger sein als angezeigt, aber nie älter.
- Bietet die Paketquelle zwar eine neuere Version an, die aber noch unter der Fix-Version liegt, schlägt
  Vigilance kein Update vor („Paketquelle bietet nur eine Version unter dem Fix“).
- **„Fix nicht in den Paketquellen“** heisst: Die konfigurierten Quellen bieten die Fix-Version nicht an
  (z. B. `intel-microcode` auf pve, weil `non-free-firmware` fehlt). Das Ändern der Paketquellen schlägt
  Vigilance nicht selbst vor.
- **Altpakete** sind ältere Versionen neben einer neueren desselben Quellpakets. Das erkennt Vigilance an
  den Versionen, nicht an der Herkunft. Auch ein absichtlich behaltener älterer Kernel ist ein Altpaket;
  dazu erscheint ein Hinweis.

## Risikoprüfung vor dem Entfernen

- Simuliert `apt-get -s purge` pro Paket und zeigt, was apt zusätzlich entfernen würde.
- Sucht laufende Prozesse, die eine Bibliothek des Pakets geladen haben. Prozesse in Docker-Containern
  werden dabei ausgelassen (anderer Mount-Namespace). Ohne Root (Proxmox-Host) sind Prozesse anderer
  Benutzer nicht sichtbar; die Oberfläche sagt das.
- Sucht nur unter `/usr/local` und `/opt` nach Programmen, die die Bibliothek verwenden, nur ELF-Dateien,
  höchstens 5000 Dateien pro Verzeichnis. Programme an anderen Orten werden nicht gefunden.
- Das Ergebnis stammt vom letzten Scan. Was sich seither geändert hat, ist nicht berücksichtigt.

## Aktionen (Befehle ausführen)

- Auf laufenden LXC-Containern und eingetragenen VMs mit Debian oder Ubuntu, als root. „Alle“ auf der
  Seite Hosts umfasst beide, nie den Proxmox-Host.
- In einer VM wird ein neuer Kernel erst nach einem Neustart der VM aktiv; Vigilance startet sie nicht neu.
  „Kernel aufräumen“ gibt es nur für Container, eine VM braucht ihren Kernel.
- Der Proxmox-Host nur einzeln (nie zusammen mit „alle Container“), nur mit ausdrücklicher Bestätigung
  und nur, wenn du eine sudo-Regel für `apt-get` angelegt hast. Diese Regel gibt dem Scan-Benutzer
  faktisch Root-Rechte auf dem Host, denn apt-get kann über seine Optionen beliebige Befehle starten.
  Auf dem Host läuft apt losgelöst von der SSH-Verbindung; Vigilance fragt den Fortschritt ab.
  Einen neuen Kernel aktiviert erst ein Neustart von pve, den Vigilance nicht ausführt. Startet
  Vigilance während der Ausführung neu, erscheint die Aktion als „Abgebrochen“, obwohl apt auf dem
  Host weiterlaufen kann; das Ergebnis zeigt dann der nächste Scan.

  Die sudo-Regel legst du auf pve mit `visudo -f /etc/sudoers.d/vigilance-scan` an:

  ```
  Defaults:vigilance-scan env_keep += "DEBIAN_FRONTEND NEEDRESTART_MODE NEEDRESTART_SUSPEND APT_LISTCHANGES_FRONTEND LC_ALL"
  vigilance-scan ALL=(root) NOPASSWD: /usr/bin/apt-get
  ```
- **Schlüssel selbst eintragen** (Schalter unter Verwaltung › Einstellungen, aus als Standard): Lehnt ein
  laufender Container den Schlüssel von Vigilance ab, ruft Vigilance auf dem Proxmox-Host
  `sudo -n /usr/local/sbin/vigilance-install-key <CT-ID>` auf und scannt danach weiter. Das Skript
  enthält den Schlüssel fest, andere Schlüssel lassen sich damit nicht eintragen; es braucht eine eigene
  sudo-Regel (README). Damit kommt Vigilance als root in jeden laufenden Container des Nodes, auch in
  solche, die du ihm nicht freigegeben hast. Für VMs gibt es das nicht. Neue Container erkennt
  Vigilance erst beim nächsten Scan, nicht schon beim Start des Containers.
- „Vorschläge umsetzen“ installiert nur Fixes, die in den Paketquellen liegen, und entfernt nur
  Altpakete mit Risikoprüfung „unbedenklich“.
- Geänderte Konfigurationsdateien bleiben, wie sie sind (`--force-confold`). Neue Standardwerte des
  Pakets werden dadurch nicht übernommen.
- Vigilance startet keine Dienste neu und startet keinen Container neu. Bibliotheken, die laufende
  Programme noch geladen haben, bleiben bis zum Neustart des Programms aktiv.
- Die Vorschau simuliert mit den vorhandenen Paketlisten; bei der Ausführung lädt `apt-get update` sie
  neu. Das tatsächliche Ergebnis kann deshalb leicht abweichen.
- In einem Batch laufen bis zu 4 Container gleichzeitig. Ein Container mit apt-cacher-ng kommt zuerst
  und allein dran. Vigilance erkennt den Cache nur am installierten Paket `apt-cacher-ng`; einen
  anderen Proxy oder Cache (zum Beispiel squid) beachtet es dabei nicht.

## Benachrichtigungen

- Gotify-Meldungen gehen an neue Befunde ab der eingestellten Schwere. Den Link in der Meldung gibt es
  nur, wenn `VIGILANCE_PUBLIC_URL` gesetzt ist (Adresse der Oberfläche, wie der Browser sie aufruft).
- Gotify lässt sich unter Verwaltung, Einstellungen einrichten. Einmal dort gespeichert, gelten diese
  Werte vor `VIGILANCE_GOTIFY_*` und `config.yaml`.
- Der App-Token liegt dann unverschlüsselt in der Datenbank, also auch in deren Sicherungen (der Deploy
  legt vor jedem Update einen Dump unter `/tmp` im Container ab). Die Oberfläche und die API zeigen ihn
  nie an. Wer die Datenbank lesen kann, kann über Gotify Nachrichten in deinem Namen senden, mehr nicht.
- Eine Testnachricht an eine andere Adresse als die gespeicherte geht nur mit neu eingegebenem Token;
  der gespeicherte Token wird nicht an fremde Server geschickt.
- Gemeldet werden nur neue Befunde. Wird eine ausgeschaltete Quelle wieder eingeschaltet, kommen ihre
  zurückgeholten Befunde ohne Meldung zurück.

## Zugriff

- Lesen geht ohne Anmeldung, für Änderungen und Aktionen braucht es den API-Token. Wer die Oberfläche
  erreicht, sieht also alle Hosts, Pakete und Lücken. Schütze den Zugang über das Netz, zum Beispiel
  mit Reverse-Proxy und Firewall, und rufe Vigilance über HTTPS auf, damit der Token verschlüsselt
  übertragen wird.

## Kernel im Container

- Ein LXC-Container lädt nie einen eigenen Kernel. Kernel-Pakete darin erkennt Vigilance und bietet
  „Kernel aufräumen“ an (`apt-get purge --autoremove` mit allen Kernel-Paketen samt Resten).
- `apt autoremove` allein entfernt sie nicht vollständig: apt schützt den neuesten und den vorherigen
  Kernel vor dem automatischen Entfernen, und Reste mit Status „rc“ bleiben ohne `--purge` liegen.
- „Vorschläge umsetzen“ räumt Kernel nur mit auf, wenn die Simulation ausschliesslich Kernel-Pakete und
  deren Abhängigkeiten (initramfs-tools, klibc, busybox …) entfernt. Würde mehr wegfallen (zum Beispiel
  das Meta-Paket `wireguard`), ist es ein eigener Schritt mit Vorschau.

## Zeitverzug

- Scan und CVE-Abgleich laufen in den eingestellten Abständen (Verwaltung, Einstellungen). Eine neue
  Meldung erscheint frühestens beim nächsten Abgleich, eine Paketänderung beim nächsten Scan.
- OSV übernimmt Meldungen aus seinen Quellen mit eigener Verzögerung.
