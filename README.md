# University - HackMyVM (Easy)
 
![University.png](University.png)

## Übersicht

*   **VM:** University
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=University)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 21. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/University_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "University"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Entdeckung eines exponierten `.git`-Verzeichnisses und einer SQL-Dump-Datei (`oas.sql`) auf dem Webserver (Port 80). Die `oas.sql`-Datei enthielt Klartext-Credentials. Zusätzlich wurde der Quellcode eines "Online Admission System" von einem verlinkten GitHub-Repository geklont. Durch Ausnutzen einer unsicheren Dateiupload-Funktion (`fileupload.php` in `/studentpic/`) wurde eine PHP-Webshell hochgeladen, was zu Remote Code Execution (RCE) als `www-data` führte. Eine Reverse Shell wurde etabliert. Als `www-data` wurde eine versteckte Datei `.sandra_secret` gefunden, die das Passwort (`Myyogaiseasy`) für den Benutzer `sandra` enthielt. Nach dem Wechsel zu `sandra` wurde eine `sudo`-Regel entdeckt, die erlaubte, `/usr/local/bin/gerapy` (Version 0.9.6) als `root` ohne Passwort auszuführen. Durch Ausnutzung einer bekannten RCE-Schwachstelle in Gerapy (CVE-2021-43857, authentifiziert) wurde eine Root-Shell erlangt, nachdem zuvor mit `gerapy createsuperuser` ein Admin-Account für Gerapy erstellt und der Gerapy-Server gestartet wurde.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `awk`
*   `tr`
*   `git`
*   `vi` (oder anderer Texteditor)
*   `curl` (impliziert)
*   `nc` (netcat)
*   `python3` (für `http.server` und Reverse Shell)
*   `stty`
*   `ls`
*   `ss`
*   `env`
*   `dmesg`
*   `find`
*   `cat`
*   `su`
*   `sudo`
*   `gerapy` (als Exploit-Ziel und Tool)
*   Standard Linux-Befehle (`cd`, `id`, `pwd`, `reset`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "University" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.128`). Eintrag von `advisor.hmv` (später `university.hmv`) in `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Nginx 1.18.0).
    *   `nmap`-Skript `http-git` fand ein exponiertes `.git`-Verzeichnis unter `/` und verwies auf das GitHub-Repo `https://github.com/rskoolrash/nline-Admission-System`.
    *   `gobuster` auf Port 80 fand diverse PHP-Dateien (`index.php`, `admin.php`, `signup.php`, `fileupload.php`) und eine SQL-Dump-Datei `/oas.sql`.
    *   `nikto` bestätigte das `.git`-Verzeichnis und fehlende Security Header.
    *   Analyse von `oas.sql` (impliziert durch `awk`/`tr`-Pipeline) extrahierte potenzielle Credentials.
    *   Klonen des öffentlichen GitHub-Repos zur Quellcodeanalyse.

2.  **Initial Access (RCE via File Upload zu `www-data`):**
    *   Erstellung einer PHP-Webshell (`benhacker.php` mit `<?php system($_GET['cmd']); ?>`).
    *   Hochladen der Webshell über die `/fileupload.php`-Funktion in das Verzeichnis `/studentpic/`.
    *   Ausführung von Befehlen über die Webshell (`http://192.168.2.128/studentpic/benhacker.php?cmd=id`) bestätigte RCE als `www-data`.
    *   Etablierung einer interaktiven Reverse Shell als `www-data` mittels eines Bash-Payloads über die Webshell. Stabilisierung der Shell.

3.  **Privilege Escalation (von `www-data` zu `sandra`):**
    *   Enumeration als `www-data`. Identifizierung des Benutzers `sandra` in `/home/`.
    *   Im Verzeichnis `/var/www/html` wurde die versteckte Datei `.sandra_secret` gefunden.
    *   `cat .sandra_secret` enthüllte das Passwort `Myyogaiseasy`.
    *   Wechsel zum Benutzer `sandra` mittels `su sandra` und dem Passwort `Myyogaiseasy`.

4.  **Privilege Escalation (von `sandra` zu `root` via `sudo gerapy` Exploit):**
    *   `sudo -l` als `sandra` zeigte: `(root) NOPASSWD: /usr/local/bin/gerapy`.
    *   `sudo /usr/local/bin/gerapy --help` zeigte Gerapy Version 0.9.6.
    *   Erstellung eines Gerapy-Superusers (`benni:Hacker`) mittels `sudo gerapy createsuperuser`.
    *   Starten des Gerapy-Servers auf Port 8000: `sudo gerapy runserver 0.0.0.0:8000`.
    *   Ausnutzung der bekannten RCE-Schwachstelle CVE-2021-43857 in Gerapy < 0.9.8 (Exploit-Skript von Exploit-DB `50640.py`).
    *   Das Python-Exploit-Skript wurde mit den erstellten Credentials (`benni:Hacker`), der Ziel-IP/Port (192.168.2.128:8000, *obwohl im Log 10001 steht*) und Listener-Daten für die Reverse Shell (Angreifer-IP:Port) ausgeführt.
    *   Erlangung einer Root-Shell auf dem Listener des Angreifers.
    *   User-Flag `HMV0948328974325HMV` (vermutlich für `sandra`) und Root-Flag `HMV1111190877987HMV` wurden gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Exponiertes `.git`-Verzeichnis:** Ermöglichte den Download des Quellcodes und die Identifizierung der verwendeten Anwendung (Online Admission System).
*   **SQL-Dump-Datei (`oas.sql`) im Web-Root:** Enthielt potenziell sensible Daten (Credentials).
*   **Unsicherer Datei-Upload:** Die Funktion `fileupload.php` erlaubte das Hochladen und Ausführen einer PHP-Webshell.
*   **Klartext-Passwort in Datei:** Das Passwort für `sandra` war in `.sandra_secret` gespeichert.
*   **Unsichere `sudo`-Konfiguration (`gerapy`):** Die Erlaubnis, `gerapy` (eine Anwendung mit bekannter RCE) als `root` ohne Passwort auszuführen, ermöglichte die vollständige Systemübernahme.
*   **Veraltete Software mit bekannter RCE (Gerapy 0.9.6 / CVE-2021-43857):** Ausnutzung einer bekannten Schwachstelle in einer Webanwendung.

## Flags

*   **User Flag (vermutlich für `sandra`):** `HMV0948328974325HMV`
*   **Root Flag (`/root/root.txt`):** `HMV1111190877987HMV`

## Tags

`HackMyVM`, `University`, `Easy`, `.git Exposure`, `SQL Dump Leak`, `File Upload Vulnerability`, `RCE`, `sudo Exploitation`, `Gerapy`, `CVE-2021-43857`, `Privilege Escalation`, `Linux`, `Web`
