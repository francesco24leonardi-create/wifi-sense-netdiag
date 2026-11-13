# Asset locali e attribuzione dati

## Geolocalizzazione IP

**IP Geolocation by DB-IP** — https://db-ip.com/

DB-IP Country Lite, edizione novembre 2026. Fonte originale:
https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz

Licenza: **Creative Commons Attribution 4.0 International**.
Testo e riepilogo: https://creativecommons.org/licenses/by/4.0/
Condizioni del fornitore: https://db-ip.com/db/lite.php

Modifiche effettuate: conversione delle colonne CSV in intervalli binari
indicizzati SQLite. Il codice paese è associato al nome Natural Earth.
Non vengono restituite coordinate dei server né disegnati punti basati
sui centri dei paesi. Copertura e accuratezza della versione Lite sono limitate.
Il dataset viene distribuito localmente e non viene interrogata alcuna API.
Il link di attribuzione deve restare visibile nelle schermate che usano i dati.

## Reputazione degli indirizzi IP

**The Spamhaus Project** — https://www.spamhaus.org/

Lo snapshot incluso in `data/threats.json` deriva dai feed ufficiali
DROP IPv4 e IPv6. Metadati originali, data, copyright, URL e hash dei feed sono
conservati nella proprietà `spamhaus_sources` dello stesso file. I CIDR sono
convertiti nello schema IOC locale; non vengono create regole firewall.

Fonte e condizioni: https://www.spamhaus.org/blocklists/do-not-route-or-peer/
Gli aggiornamenti richiedono l'esecuzione esplicita di
`python setup_offline.py --refresh-threats` e l'accesso a Internet in quella
fase. L'applicazione usa esclusivamente lo snapshot locale e ne segnala l'età.
Lo script non riscarica i feed se l'ultimo aggiornamento risale a meno di un'ora.
Una corrispondenza è un dato reputazionale da verificare, non prova di attacco.

## Vettori geografici

**Made with Natural Earth** — https://www.naturalearthdata.com/

Natural Earth v5.1.2, `ne_110m_admin_0_countries.geojson`, scala 1:110m.
Fonte: https://github.com/nvkelso/natural-earth-vector/tree/v5.1.2
I vettori Natural Earth sono nel pubblico dominio:
https://www.naturalearthdata.com/about/terms-of-use/

I confini rappresentati hanno finalità grafiche. I campi `LABEL_X` e `LABEL_Y`
sono usati soltanto come punti rappresentativi del paese.

## Librerie JavaScript

- Three.js 0.170.0: licenza MIT in `THREE.txt`.
- OrbitControls della stessa versione: stesso progetto/licenza. Unica modifica
  locale: import `three` riscritto in `./three.min.js`.
- Globe.gl 2.33.2: licenza MIT in `GLOBE_GL.txt`; bundle ufficiale distribuito
  senza modifiche e con i suoi avvisi incorporati.

Il nome locale `three.min.js` identifica il modulo ES ufficiale
`three.module.min.js`; non è lo storico bundle globale `THREE`.
Gli SHA-256 di sorgenti e file finali sono in `asset_manifest.json`.

Gli avvisi raccolti per le dipendenze runtime sono in `dependencies/`; il loro
indice, le fonti, le versioni risolte e gli hash sono in `THIRD_PARTY.json`.
La raccolta usa i pacchetti npm originali e i vincoli dichiarati, considerando
le versioni disponibili alla pubblicazione di Globe.gl 2.33.2. Il bundle UMD
non contiene un lockfile delle dipendenze: questa provenienza non certifica
l'identità esatta di ogni modulo incorporato. Eventuali voci `warning`
nell'indice indicano documenti non reperiti o dipendenze non risolte.
Gli avvisi originali incorporati nel bundle rimangono intatti. H3 incorpora
codice Uber con licenza Apache 2.0, riportata integralmente in
`APACHE-2.0.txt`; il font Helvetiker contiene il proprio avviso nel bundle.
