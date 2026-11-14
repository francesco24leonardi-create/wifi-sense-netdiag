# WiFi-Sense & NetDiag — Radio Lab 2,4 GHz

**Nuova guida:** [RADIO_LAB.md](RADIO_LAB.md): eseguibile Windows, Parrot/Kali/Linux,
selezione wlan0, copertura casa e limiti del sensing.

Questa revisione rimuove simulazione, coordinate manuali, distanze dedotte
dall’RSSI e punti geografici dei server ricavati dai centri dei paesi.
L’app non inventa valori mancanti. Un dato ricevuto da un driver o servizio
non è una prova indipendente della sua esattezza: fonte, età e limiti restano
visibili. Nessuna funzione garantisce che tutti i dati siano sempre disponibili.

## Avvio

Python 3.12 consigliato. Windows richiede .NET e Microsoft Edge WebView2;
Linux richiede GTK/WebKitGTK o QtWebEngine secondo pywebview.

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe setup_offline.py --verify
.venv\Scripts\python.exe main.py
```

Per Linux usare python3 e .venv/bin/python; installare anche il backend
grafico richiesto (ad esempio `pip install 'pywebview[qt]'`).

```bash
python main.py --real --interface "Wi-Fi"
python main.py --browser
python main.py --location-provider gpsd
python main.py --headless --port 8765
```

`--demo` non esiste più. Le vecchie impostazioni demo vengono migrate a real;
le vecchie coordinate scritte manualmente vengono ignorate. Le scansioni LAN,
Wi-Fi e BLE partono solo dal pulsante. L’RSSI e l’ICMP al gateway vengono
acquisiti dalla scheda selezionata, se sistema e privilegi lo consentono.

## Posizione del PC

Premere **Consenti posizione di sistema** nella finestra desktop. L’app usa
Windows Geolocation (richiesta avviata sul thread UI) oppure GeoClue2 su Linux.
Il consenso del sistema rimane sotto il controllo dell’utente. Il provider
può usare Wi-Fi, rete cellulare, GPS e servizi Internet: questa modalità,
autorizzata dall’utente, non è dichiarata 100% offline.

Il fix deve contenere coordinate valide, accuratezza positiva, fonte e data
della misura. Dopo 60 secondi senza un fix recente viene nascosto. Il tempo
monotono impedisce che uno spostamento dell’orologio prolunghi la validità.
La posizione predefinita manuale restituita da Windows viene rifiutata.
**Interrompi** cancella l’acquisizione e rimuove l’ultimo fix dalla RAM.
Non vengono salvate coordinate o cronologie su disco né inviate dall’app a
un’API geografica. I servizi di localizzazione del sistema possono comunicare
con i loro provider, secondo le impostazioni privacy del sistema stesso.

Windows: abilitare autonomamente i servizi di posizione nelle impostazioni
privacy, se desiderato. Il programma non modifica queste impostazioni.
Nel modo browser/headless Windows manca il thread nativo della finestra:
il provider risponde non disponibile; usare la finestra pywebview oppure GPSD.

Linux: installare GeoClue2 e un agente di autorizzazione del desktop.
Copiare `wifi-sense-netdiag.desktop` nella cartella applicazioni dell’utente
e impostarne Exec sul comando Python e percorso assoluti del proprio progetto.
Il servizio può negare l’accesso: l’app mostra l’errore senza aggirare la policy.
Per uso offline con un ricevitore GNSS locale, GPSD legge soltanto
127.0.0.1:2947. Senza ricevitore/fix/accuratezza, non compare alcuna posizione.

## Significato dei dati

- RSSI: valore dBm riferito dal driver. 10 Hz indica le letture richieste,
  non garantisce dieci aggiornamenti fisici del sensore. Driver e cache possono
  ripetere lo stesso valore; l’istante interno del sensore resta sconosciuto.
- Varianza, filtro e indice percentuale sono calcoli sul segnale. Il superamento
  della soglia non identifica persone, cause o movimenti attraverso pareti.
  Riscaldamento e dati mancanti producono valori nulli, non falsi zeri.
- RTT, jitter e risposte mancanti derivano dalle sonde ICMP. La telemetria
  scaduta oltre 2 secondi viene invalidata; i flussi oltre 10 secondi scompaiono.
- ARP, mDNS, SSDP e BLE sono osservazioni o dichiarazioni dei dispositivi.
  Un servizio annunciato non autentica un’identità o prova il tipo fisico.
  Eventuali categorie sono indizi separati; OUI è l’assegnatario del prefisso,
  non una verifica del produttore. Gli inventari oltre 60 secondi sono storici.
- RSSI percentuale di netsh/nmcli resta percentuale: non viene trasformata
  in dBm o metri. Il radar è un diagramma, non una localizzazione spaziale.
- Il database IP attribuisce un paese e una versione. Non fornisce una posizione
  verificata del server: nessun punto o arco viene inventato per riempire il globo.
- Un match in threats.json significa corrispondenza nella lista consultata,
  non un attacco confermato. Data e obsolescenza dello snapshot sono mostrate.

## Architettura e sicurezza

main.py: server solo 127.0.0.1, finestra desktop e dispatcher consenso UI.
service.py: stato asyncio, scadenza osservazioni, comandi e chiusura risorse.
location.py: provider OS/GPSD e validazione dei fix.
sensing.py/netio.py: driver RSSI, ICMP, filtro FIR e calibrazione.
scanner.py/lan_scanner.py: discovery locale e metadati di provenienza.
connections.py/geoip.py: connessioni osservate, attribuzione paese e match IOC.
static/: globo cartografico, diagramma inventario e HUD senza dati artificiali.

WebSocket autenticato con token casuale, controlli Host/Origin, limiti dei
messaggi e CSP. Il token viene tolto dall’URL e conservato in sessionStorage
della scheda per F5. Nessun endpoint espone dati senza autenticazione.
Stringhe di rete sono trattate come testo. Software compromesso sul PC o
sensori/provider che mentono non possono essere esclusi da questi controlli.

Asset Three.js/Globe.gl, Natural Earth, DB-IP e IOC sono inclusi localmente.
Lo snapshot Spamhaus aggiornato contiene 1849 intervalli (1759 IPv4, 90 IPv6).
Le date originali sono conservate in data/threats.json; non è un feed live.
È disponibile il pulsante Aggiorna IOC da Internet. Da terminale:

```bash
python setup_offline.py --verify
python setup_offline.py --refresh-threats
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python tests/smoke_local.py
```

Per ricostruire gli asset mancanti con Internet usare `python setup_offline.py`.
Per le dipendenze offline preparare un wheelhouse sulla stessa piattaforma con
`pip wheel -r requirements.txt -w wheelhouse`, quindi installare con
`pip install --no-index --find-links wheelhouse -r requirements.txt`.

Fonti e licenze: vedere licenses/ e asset_manifest.json.
[Windows Geolocation](https://learn.microsoft.com/en-us/uwp/api/windows.devices.geolocation.geolocator),
[GeoClue](https://www.freedesktop.org/software/geoclue/docs/gdbus-org.freedesktop.GeoClue2.Client.html),
[DB-IP](https://db-ip.com/),
[Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/).
Il rapporto VALIDATION.md distingue i test software dalla verifica hardware.
