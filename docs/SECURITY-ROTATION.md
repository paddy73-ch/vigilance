# Schlüssel und Tokens rotieren

Hintergrund: Bis Commit `37072b1` standen der private SSH-Key (in
`vigilance/discovery/proxmox_ssh_setup.py`) und das Proxmox-Token-Secret (in
`config/config.yaml`) im Repository. Beide sind damit in der Git-History, im
Deploy-Archiv und in alten Images enthalten. Ab diesem Branch liegen sie nicht
mehr im Code, gelten aber erst als sicher, wenn sie **ersetzt** sind.

Alle Befehle laufen vom Mac aus über `ssh pve`. Reihenfolge: A → B → C → D.

---

## A. API-Token für Schreibzugriff (einmalig nach dem Deploy)

Bisher ist kein Token gesetzt (`VIGILANCE_API_TOKEN` ist leer), Schreibzugriffe
sind nach dem Deploy also gesperrt, bis ein Token existiert.

```bash
ssh pve 'pct exec 123 -- docker exec vigilance vigilance token-rotate'
```

* Ausgabe (`vig_…`) in Vaultwarden speichern – sie wird nur einmal angezeigt.
* Im Browser oben rechts **Unlock editing** → Token eingeben.
* Später neue Tokens direkt unter *Settings → API Token → Generate new token*.

## B. SSH-Key ersetzen

Der heutige Key hat den Fingerprint `SHA256:T8x9hYBuiYViKdVkdtIFfNfoL+FgZBGAL6rpZ3eTBSQ`
und steht in `/root/.ssh/authorized_keys` aller laufenden LXCs
(100 101 102 104 105 110 111 118 119 121 122 123).

1. Neuen Key erzeugen (als Benutzer `vigilance`, damit die App ihn lesen kann):

   ```bash
   ssh pve 'pct exec 123 -- docker exec -u vigilance vigilance vigilance ssh-key-rotate'
   ```

   Der alte Key bleibt als `id_rsa.old-<Zeitstempel>` liegen.

2. Neuen Public Key verteilen und den alten entfernen (auf pve):

   ```bash
   NEW='ssh-ed25519 AAAA…  vigilance@…'   # Ausgabe aus Schritt 1
   OLD='AAAAIAyXVQwZfiICfF5rW1AGNmTU0L7D0WK45lMo85BjG5vw'
   for c in $(pct list | awk 'NR>1 && $2=="running" {print $1}'); do
     pct exec "$c" -- sh -c "
       f=/root/.ssh/authorized_keys
       [ -f \$f ] || exit 0
       grep -qF '$NEW' \$f || echo '$NEW' >> \$f
       grep -v '$OLD' \$f > \$f.new && cat \$f.new > \$f && rm \$f.new
       echo \"$c: \$(grep -c vigilance \$f) vigilance-key(s)\""
   done
   ```

   (`cat … >` statt `sed -i`, damit ein Symlink als Symlink erhalten bleibt.)
   Falls ein Ansible-Playbook den Key verteilt: dort ebenfalls ersetzen, sonst
   kommt der alte Key beim nächsten Lauf zurück.

3. Scan auslösen (Dashboard → *Scan Now*) und prüfen, dass keine neuen
   `SSH connection failed` im Log stehen:

   ```bash
   ssh pve 'pct exec 123 -- docker logs --since 10m vigilance 2>&1 | grep -c "SSH connection failed"'
   ```

4. Danach die alten Dateien löschen:

   ```bash
   ssh pve 'pct exec 123 -- docker exec vigilance sh -c "rm -f /app/data/ssh/id_rsa*.old-*"'
   ```

## C. Proxmox-API-Token ersetzen (und Rechte verkleinern)

Ist-Zustand: Token `vigilance@pam!vigilance-ct123` hat **PVEVMAdmin auf /vms**
(VMs starten, stoppen, umkonfigurieren). Vigilance braucht nur Lesezugriff
(`VM.Audit`). Der zweite Token `vigilance@pam!vigilance-token` (ohne
Privilege-Separation) wird nicht verwendet.

1. Neuen Token nur mit Leserechten anlegen:

   ```bash
   ssh pve "pveum user token add vigilance@pam vigilance-ro --privsep 1 --comment 'Vigilance CT123 read-only'"
   ssh pve "pveum acl modify / --tokens 'vigilance@pam!vigilance-ro' --roles VigilanceRole"
   ```

   Das Secret wird nur einmal angezeigt.

2. In CT123 `/opt/vigilance/.env` anpassen (die `.env` hat Vorrang vor `config.yaml`):

   ```
   VIGILANCE_PROXMOX_TOKEN_ID=vigilance@pam!vigilance-ro
   VIGILANCE_PROXMOX_TOKEN_SECRET=<neues Secret>
   ```

   Danach neu starten, damit die Umgebung neu gelesen wird:

   ```bash
   ssh pve 'pct exec 123 -- docker compose -p vigilance --project-directory /opt/vigilance/docker -f /opt/vigilance/docker/docker-compose.yml -f /opt/vigilance/docker/docker-compose.override.yml up -d'
   ```

   Beim nächsten Scan übernimmt Vigilance den neuen Token auch in die Datenbank
   (Tabelle `proxmox_nodes`).

3. Scan auslösen und prüfen (`nodes_scanned` wie vorher, keine 401/403 im Log).

4. Alte Tokens und die zu weiten Rechte entfernen:

   ```bash
   ssh pve "pveum user token remove vigilance@pam vigilance-ct123"
   ssh pve "pveum user token remove vigilance@pam vigilance-token"
   ssh pve "pveum acl delete /vms --users vigilance@pam --roles PVEVMAdmin"
   ```

## D. Aufräumen

* Alte Kopie mit Secret auf CT123 löschen:
  `ssh pve 'pct exec 123 -- rm -f /opt/vigilance/config/config.yaml'`
* Git-History: Nach A–C sind die alten Werte wertlos. Ein Umschreiben der
  History (`git filter-repo`) ist dann nicht nötig.
