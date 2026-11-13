# Verifica della revisione «solo osservazioni reali»

Ultima verifica: 14 novembre 2026. Questo rapporto sostituisce quello della
precedente versione con simulatore, ora rimosso dall’applicazione.

## Verifiche software

- **80 test automatici superati**. Coprono autenticazione e limiti WebSocket,
  modalità reale obbligatoria, rifiuto coordinate manuali, assenza di fallback
  inventati, scadenza di telemetria/connessioni, DSP, parser di rete, discovery
  con risultati parziali, provenienza delle osservazioni, paese IP senza
  coordinate del server, match IOC e gestione dei thread.
- Otto test specifici per posizione: coordinate/accuratezza mancanti o non
  valide, timestamp futuri e scaduti, cambio dell’orologio, posizione Windows
  predefinita rifiutata, parser GPSD e GeoClue, consenso negato, cancellazione
  e rimozione del fix alla disattivazione. Sono prove con provider controllati
  nei test; non dimostrano l’accuratezza fisica di GPS o servizi del sistema.
- Test di integrazione con vero Uvicorn su loopback: 20 snapshot autenticati,
  hardware indisponibile iniettato solo nel test; dati mancanti rimangono
  assenti, richiesta demo rifiutata, nessun thread non-daemon residuo.
- Sintassi Python e JavaScript controllata. Asset locali verificati tramite
  SHA-256. ZIP verificato tramite CRC e manifest dei contenuti.
- Verifica visiva in Chromium locale: entrambe le scene renderizzate,
  nessun dispositivo o punto geografico inventato; pulsanti dipendenti dai
  sensori disabilitati quando non disponibili. Nessun errore JavaScript.
  Ricaricamento autenticato e richiesta posizione dalla UI verificati.

## Ambiente e limiti osservati

Python 3.12, Windows, dipendenze in cartelle isolate del workspace.
La dipendenza Windows.Devices.Geolocation 4!10.0.28000.2957 è stata scaricata
dal registro PyPI e importata: enumerazioni e firme dei metodi usati sono
state confrontate con gli stub installati. Non è stato acquisito un fix
fisico dell’utente durante il collaudo.

Nel server browser di verifica il provider posizione ha correttamente
segnalato la dipendenza non presente nel suo percorso isolato: non ha
generato coordinate di ripiego. Per la distribuzione, requirements.txt
include i pacchetti WinRT necessari. Windows in modalità browser/headless
non dispone del dispatcher del consenso sul thread della finestra nativa;
la posizione di sistema richiede la finestra desktop, oppure GPSD locale.

L’ambiente ha negato l’accesso CIM alla scheda e alla tabella TCP
(GetExtendedTcpTable). La dashboard ha mostrato questi errori e valori N/D.
La scansione LAN/BLE, il sensing fisico e la geolocalizzazione reale devono
quindi essere verificati sul computer di destinazione con relativi driver,
runtime e permessi. Non si dichiara che i test software certifichino questi
sensori o i dati forniti da terzi.

Nella verifica precedente, l’avvio pywebview si arrestava prima della
creazione della finestra durante il caricamento .NET/pythonnet, con errore
Python.Runtime.Loader.Initialize. La finestra nativa e il consenso Windows
end-to-end non sono stati validati qui. Il backend e la GUI browser sono
collaudati; il pulsante posizione usa il provider nativo nella finestra desktop.
I percorsi Linux/GeoClue/GPSD sono coperti da test dei dati e gestione del
provider, non da una sessione fisica Linux.

## Interpretazione

L’app elimina simulazioni e valori sostitutivi; non promette infallibilità.
Fonte verificabile significa provenienza dichiarata e controlli sul formato,
sul tempo e sulla disponibilità, non verifica indipendente della realtà.
Un provider può essere impreciso, un dispositivo può annunciare informazioni
false e una lista IOC può essere obsoleta. I limiti sono mostrati nella UI.

La posizione di sistema può usare Internet, come autorizzato dall’utente.
Gli altri asset e database restano locali. Non è stata effettuata una cattura
globale delle comunicazioni del sistema operativo o del motore WebView.

## Ripetere le prove

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python tests/smoke_local.py
python setup_offline.py --verify
python main.py
```
