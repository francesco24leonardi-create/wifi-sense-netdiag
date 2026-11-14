# Radio Lab — WiFi-Sense & NetDiag

## Avvio rapido

Windows x64: aprire `WiFi-Sense-NetDiag.exe`. Python e gli asset sono inclusi.
La finestra nativa usa WebView2/.NET; se non disponibile viene aperto il browser
sul server locale autenticato. Usare **Arresta app** per chiudere il server.
Nel fallback browser la posizione di sistema Windows non è disponibile.
Il pacchetto non installa driver, non cambia firewall né permessi di posizione.

Parrot, Kali e Debian con desktop:

```bash
bash install_debian.sh
bash start_linux.sh --interface wlan0
```

Usare `iw dev` per verificare il nome reale: può essere `wlp2s0`, `wlan1` o altro.
`wlan0` è selezionabile, non viene creata né rinominata un'interfaccia inesistente.
Su altre distribuzioni installare Python 3.11+, venv, GTK3, PyGObject, WebKitGTK
4.1, iproute2, iw e BlueZ con il gestore della distribuzione, quindi eseguire
`bash start_linux.sh`. In alternativa: `bash start_linux.sh --browser`.
Le dipendenze iniziali richiedono Internet; gli asset dell'interfaccia sono locali.

## Wi-Fi sensing e banda

Connettere il PC al SSID **2,4 GHz** del router. Se il router unifica più bande,
separare i nomi dal pannello del router oppure selezionare il BSSID tramite il
gestore di rete del sistema. L'app non disconnette la rete e non modifica il router.
La banda deve essere riferita da `iw`/`netsh`; un numero di canale ambiguo non basta.
L'inventario Wi-Fi visualizza solo banda 2,4 GHz verificata. Su Linux la lettura
NetworkManager usa la cache; l'eventuale scansione `iw` è limitata alle frequenze
2,4 GHz, nel rispetto delle restrizioni del driver. BLE usa la sua radio 2,4 GHz.

La calibrazione richiede circa 6 s di preparazione e 10 s di stanza vuota.
Il filtro passa-banda opera su una griglia temporale regolarizzata mediante
interpolazione limitata; i valori RSSI grezzi visualizzati restano quelli letti.
Lacune maggiori di 2,5 periodi o frequenza effettiva inferiore all'80% del target
invalidano il filtro. Un cambio di AP o banda invalida la soglia calibrata.
Durante le sonde RSSI e RTT continuano, ma i campioni non generano allarmi:
le scansioni stesse possono perturbare la radio. La calibrazione va eseguita
senza scansioni concorrenti.

**Questa versione non rileva in modo verificato persone né attraverso pareti.**
Un aumento della varianza RSSI è una perturbazione del link, non prova della
presenza di una persona. Non vengono disegnate persone fittizie. Per quella
funzione servono acquisizione CSI supportata dall'hardware, un modello appropriato
e validazione con misure reali nell'ambiente. Il progetto ESP-CSI è una fonte
di riferimento, non una dipendenza né una funzione già integrata:
https://github.com/espressif/esp-csi

## Prestazioni e latenza

Selezionare la scheda nel pannello Adattatore. La scelta automatica preferisce
una scheda Wi-Fi con gateway rispetto alla rete Ethernet. Su Windows è disponibile
un fallback IP Helper quando PowerShell/CIM non funziona.
10–50 Hz è il limite software delle letture richieste, **non il massimo hardware**.
L'app mostra letture effettive/s e CPU logiche. Il massimo fisico e la frequenza
di aggiornamento della cache del driver non sono dichiarati come conosciuti.
Aumentare le letture non aumenta necessariamente l'informazione del sensore.
ICMP lavora separatamente, target 10 Hz e timeout 250 ms; la frequenza può calare
con gateway lento. La perdita è la quota di richieste senza risposta entro il timeout.

## Copertura della casa

La mappa è un rilievo locale: scegliere X/Y in metri rispetto a un'origine
conosciuta della pianta, spostare fisicamente il PC, restare fermi almeno 3 s
e premere **Misura questo punto**. Vengono salvati mediana/min/max RSSI,
mediana RTT, conteggio campioni, AP e data. X/Y sono dichiarati dall'utente,
non misurati dal GPS. Nessuna accuratezza geografica viene inventata.
Le aree non misurate restano vuote. **Esporta JSON locale** conserva il rilievo
sul PC; senza esportazione resta solo nella memoria della sessione.

## Discovery e problemi di accesso

- Windows: ARP usa `SendARP` di IP Helper senza richiedere Npcap. La cattura
  passiva opzionale rimane una funzione distinta che può richiedere Npcap.
- Linux: se ARP raw è negato, tentativi TCP limitati alla subnet stimolano la
  risoluzione dei vicini del sistema. Le associazioni ottenute restano etichettate
  come cache; non vengono promosse a presenza verificata.
- mDNS richiede multicast UDP 5353; SSDP richiede multicast UDP 1900. Verificare
  firewall, rete ospiti/isolamento client e servizi annunciati dai dispositivi.
  Nessuna risposta non significa necessariamente un errore.
- BLE richiede adattatore acceso, driver e BlueZ su Linux. Il trasporto BLE
  è osservabile, ma il nome annunciato non autentica l'identità del dispositivo.

Il pannello Diagnostica mostra il provider, l'interfaccia e l'errore originale.
Non vengono concessi automaticamente privilegi root o eccezioni firewall.

## Aggiornamenti, dati e compilazione

**Aggiorna IOC da Internet** scarica esplicitamente i feed ufficiali Spamhaus.
Il file precedente viene conservato in caso di errore; il limite di un download
per ora rispetta il fair use. La data della fonte resta visibile: il passare del
tempo non viene nascosto cambiando artificialmente il timestamp.
Impostazioni e IOC aggiornati risiedono in `%LOCALAPPDATA%/WiFiSenseNetDiag`
o `$XDG_DATA_HOME/WiFiSenseNetDiag` (default `~/.local/share`).
`WIFI_SENSE_DATA_DIR` può indicare una cartella differente.

Build su Windows con Python e dipendenze installate:

```powershell
python -m pip install -r requirements.txt pyinstaller
python build_windows.py
```

Il risultato è `dist/WiFi-Sense-NetDiag.exe`. Non è firmato digitalmente.
Non esiste una singola build binaria universale per Windows e tutte le distribuzioni
Linux: su Linux viene fornito l'avvio dai sorgenti con dipendenze native.
