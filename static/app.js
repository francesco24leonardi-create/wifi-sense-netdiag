const $=id=>document.getElementById(id);
const num=(value,digits=1)=>typeof value==='number'&&Number.isFinite(value)?value.toFixed(digits):'—';
const categories={pc:'PC',smartphone:'Smartphone',tv:'Smart TV',iot:'IoT',bluetooth:'Bluetooth BLE',router:'Router',radio:'Canale Wi-Fi',unknown:'Non classificato'};
const symbols={pc:'▣',smartphone:'▯',tv:'▰',iot:'◇',bluetooth:'ᛒ',router:'⌁',radio:'≋',unknown:'◈'};
let globe=null,radar=null,socket=null,snapshot=null,reconnectTimer=null,reconnectDelay=700,closing=false,paused=false;
let chartBand='2.4 GHz',samples=[],lastSampleTime=null,selected=null,toastTimer=null,stateReceivedAt=0;
let seenWarnings=new Set(),deviceSignature='',connectionSignature='',uiFrame=0,pendingSnapshot=null;
const sessionTokenKey='wifi-sense.session-token';
const fragmentToken=new URLSearchParams(location.hash.slice(1)).get('token');
let token=fragmentToken||'';
try {
  if(fragmentToken)sessionStorage.setItem(sessionTokenKey,fragmentToken);
  else token=sessionStorage.getItem(sessionTokenKey)||'';
} catch {
  // The fragment still authenticates the first load when storage is denied.
  // A reload in such a restricted WebView requires reopening from main.py.
}
if(location.hash)history.replaceState(null,'',location.pathname+location.search);

function log(message,level='info') {
  const line=document.createElement('div');line.className=`log-line ${level}`;
  const time=document.createElement('time');time.textContent=new Date().toLocaleTimeString('it-IT');
  const text=document.createElement('span');text.textContent=String(message);
  line.append(time,text);$('event-log').prepend(line);
  while($('event-log').children.length>70)$('event-log').lastElementChild.remove();
}

function toast(message,error=false) {
  clearTimeout(toastTimer);$('toast').textContent=message;$('toast').className=`toast${error?' error':''}`;$('toast').hidden=false;
  toastTimer=setTimeout(()=>{$('toast').hidden=true;},6000);
}

function sceneError(message) {
  $('scene-error').hidden=false;$('scene-error-message').textContent=message;log(message,'error');
}

function displayValue(value) {
  if(value===null||value===undefined)return 'Non disponibile';
  if(typeof value==='number')return Number.isFinite(value)?Number.isInteger(value)?String(value):value.toLocaleString('it-IT',{maximumFractionDigits:4}):'Non disponibile';
  if(typeof value==='boolean')return value?'Sì':'No';
  const numericReplacer=(_key,item)=>typeof item==='number'&&Number.isFinite(item)?Number(item.toFixed(4)):item;
  if(Array.isArray(value))return value.length?value.map(v=>typeof v==='object'?JSON.stringify(v,numericReplacer):displayValue(v)).join('\n'):'Nessuno';
  if(typeof value==='object')return JSON.stringify(value,numericReplacer,2);
  return String(value);
}

function inspect(item) {
  if(!item)return;selected=item;
  $('inspector-title').textContent=item.title||'Oggetto selezionato';
  $('inspector-subtitle').textContent=categories[item.kind]||({connection:'Connessione osservata',origin:'Fix geografico del sistema',country:'Cartografia locale',rf:'Indicatore della varianza RSSI',wave:'Elemento del diagramma, non misura del campo'}[item.kind]||'Dettagli tecnici');
  $('inspector-subtitle').textContent+=' · fotografia dell’osservazione selezionata, non stato attuale garantito';
  const container=$('inspector-fields');container.replaceChildren();
  for(const [key,value] of Object.entries(item.data||{})) {
    if(key.startsWith('_'))continue;
    const row=document.createElement('dl');row.className='inspector-row';
    if(key==='threat'&&value?.matched)row.classList.add('alert');
    const label=document.createElement('dt');label.textContent=key.replaceAll('_',' ');
    const data=document.createElement('dd');data.textContent=displayValue(value);
    row.append(label,data);container.append(row);
  }
}

function inspectDevice(device) {
  const {distance_m,distance_note,...observed}=device;
  inspect({title:device.name||device.ip||device.id,kind:device.category||'unknown',data:{...observed,
    disposizione:'Diagramma per categoria; nessuna coordinata, distanza o direzione spaziale misurata.'}});
}

function inspectConnection(connection) {
  if(globe){globe.inspectConnection(connection);return;}
  inspect({title:`${connection.remote_ip}:${connection.remote_port||'—'}`,kind:'connection',data:connection});
}

function command(action,extra={}) {
  if(!socket||socket.readyState!==WebSocket.OPEN){toast('Backend locale non connesso.',true);return false;}
  socket.send(JSON.stringify({type:'command',action,...extra}));return true;
}

function connect() {
  if(closing)return;
  if(!token){$('connection-status').textContent='SESSIONE ASSENTE';$('connection-status').className='status-pill error';toast('Aprire la finestra tramite main.py: manca il token di sessione locale.',true);return;}
  const scheme=location.protocol==='https:'?'wss':'ws';
  socket=new WebSocket(`${scheme}://${location.host}/ws`);
  socket.addEventListener('open',()=>{socket.send(JSON.stringify({type:'auth',token}));reconnectDelay=700;});
  socket.addEventListener('message',event=>{
    let message;try{message=JSON.parse(event.data);}catch{log('Messaggio backend non valido.','error');return;}
    if(message.type==='snapshot') {
      $('connection-status').textContent='WEBSOCKET ATTIVO';$('connection-status').className='status-pill connected';
      pendingSnapshot=message;
      if(!uiFrame)uiFrame=requestAnimationFrame(()=>{uiFrame=0;const state=pendingSnapshot;pendingSnapshot=null;render(state);});
    } else if(message.type==='error'){toast(message.message||'Comando non riuscito.',true);log(message.message||'Errore backend.','error');$('capture-toggle').disabled=false;$('location-start').disabled=false;}
    else if(message.type==='ack'){$('capture-toggle').disabled=false;}
  });
  socket.addEventListener('error',()=>{$('connection-status').textContent='RICONNESSIONE…';});
  socket.addEventListener('close',event=>{
    $('connection-status').textContent='BACKEND OFFLINE';$('connection-status').className='status-pill error';
    $('calibrate').disabled=true;$('scan').disabled=true;
    refreshFreshness(true);
    if([1008,4401,4403].includes(event.code)){toast('Sessione non autorizzata. Riavviare l’applicazione.',true);return;}
    if(!closing){reconnectTimer=setTimeout(connect,reconnectDelay);reconnectDelay=Math.min(10000,reconnectDelay*1.7);}
  });
}

function render(state) {
  snapshot=state;stateReceivedAt=performance.now();
  const t=state.telemetry||{},network=state.network||{},scan=state.scan||{};
  $('interface-name').textContent=network.interface||'Interfaccia non disponibile';
  $('network-address').textContent=`${network.address||'—'} · GW ${network.gateway||'—'}`;
  $('scan-status').textContent=scan.phase||(scan.running?'Acquisizione in corso…':'Pronto per scansione locale.');
  $('visibility-note').textContent=state.capabilities?.visibility||'Visibilità delle sole connessioni osservate dal PC o dalla cattura abilitata.';
  $('capture-toggle').checked=Boolean(state.capabilities?.capture);
  const warnings=[...(state.warnings||[]),...(scan.warnings||[]),...(t.warning?[t.warning]:[])];
  for(const warning of warnings){const value=String(warning);if(!seenWarnings.has(value)){seenWarnings.add(value);log(value,'warning');}}
  if(seenWarnings.size>250)seenWarnings=new Set(warnings.map(String));
  $('status-line').textContent=warnings.at(-1)|| (['active','requesting'].includes(state.location?.status)?'Elaborazione locale · posizione assistita dal sistema operativo.':'Elaborazione locale · dati mancanti o scaduti esplicitamente indicati.');
  if(t.timestamp!==undefined&&t.timestamp!==lastSampleTime) {
    lastSampleTime=t.timestamp;samples.push({time:t.timestamp,filtered:t.filtered,variance:t.variance,threshold:t.threshold});
    const oldest=t.timestamp-30;while(samples.length&&samples[0].time<oldest)samples.shift();if(samples.length>1500)samples.splice(0,samples.length-1500);
  }
  renderDevices(state.devices||[]);refreshFreshness();drawSignal();drawChannels();
}

function ageLabel(age) {
  if(!Number.isFinite(age))return 'non disponibile';
  return age<60?`${age.toFixed(1)} s fa`:`${Math.floor(age/60)} min ${Math.floor(age%60)} s fa`;
}

function refreshFreshness(forceStale=false) {
  if(!snapshot)return;
  const transportAge=(performance.now()-stateReceivedAt)/1000;
  const ageFor=name=>Number.isFinite(snapshot.freshness?.[name])?snapshot.freshness[name]+transportAge:null;
  const age=ageFor('telemetry_age_s'),connectionsAge=ageFor('connections_age_s'),inventoryAge=ageFor('inventory_age_s');
  const stale=forceStale||age===null||age>2,t=stale?{}:(snapshot.telemetry||{}),scan=snapshot.scan||{};
  const rssiValid=Number.isFinite(t.rssi_dbm),indexValid=Number.isFinite(t.intensity)&&Number.isFinite(t.threshold);
  $('data-badge').textContent=stale?(age===null?'N/D':'SCADUTI'):'RECENTI';$('data-badge').className=`tag${stale?' amber':''}`;
  $('rssi').textContent=num(t.rssi_dbm,0);$('jitter').textContent=num(t.jitter_ms);$('rtt').textContent=num(t.rtt_ms);$('sample-rate').textContent=num(t.sample_hz);
  $('intensity').textContent=indexValid?`${num(t.intensity,0)}%`:'—';$('motion-meter').style.width=indexValid?`${Math.max(0,Math.min(100,t.intensity))}%`:'0%';
  $('motion-state').textContent=stale?'Telemetria assente o scaduta':!rssiValid?'RSSI non disponibile':indexValid?(t.rf_perturbation===true?'Soglia della varianza RSSI superata':'Soglia della varianza RSSI non superata'):(t.state||'Indice non disponibile: calibrare');
  document.querySelector('.sensing-card').classList.toggle('motion',indexValid&&t.rf_perturbation===true);
  const calibrating=String(t.state||'').toLocaleLowerCase('it').includes('calibrazione');
  $('calibrate').disabled=stale||!rssiValid||Boolean(scan.running||calibrating);$('scan').disabled=forceStale||!snapshot.network||Boolean(scan.running||calibrating);
  $('calibration-progress').value=Number.isFinite(t.threshold)?1:Number.isFinite(t.calibration_progress)?Math.max(0,Math.min(1,t.calibration_progress)):0;
  const health=Number.isFinite(t.rtt_ms);
  $('health-status').textContent=stale?'Misure ICMP assenti o scadute':health?(t.loss_percent>5?'Risposte ICMP mancanti':'Gateway risponde a ICMP'):'RTT non disponibile';
  $('health-dot').className=`indicator ${health?(t.loss_percent>5?'bad':'good'):''}`;
  $('packet-loss').textContent=Number.isFinite(t.loss_percent)?`${num(t.loss_percent,0)}% loss`:'— loss';
  $('telemetry-age').textContent=`Ultima lettura: ${ageLabel(age)}${stale&&age!==null?' · SCADUTA':''}`;
  $('telemetry-age').classList.toggle('stale',stale);
  $('inventory-age').textContent=`Inventario: ${ageLabel(inventoryAge)}${inventoryAge!==null&&inventoryAge>60?' · STORICO':''}`;
  $('inventory-age').classList.toggle('stale',inventoryAge===null||inventoryAge>60);
  $('device-count').textContent=inventoryAge===null?'—':String((snapshot.devices||[]).length).padStart(2,'0');
  const flowsValid=!forceStale&&connectionsAge!==null&&connectionsAge<=10;
  const connections=flowsValid?(snapshot.connections||[]):[];
  $('connections-age').textContent=`Flussi: ${ageLabel(connectionsAge)}${!flowsValid&&connectionsAge!==null?' · SCADUTI':''}`;$('connections-age').classList.toggle('stale',!flowsValid);
  $('remote-count').textContent=flowsValid?String(connections.length).padStart(2,'0'):'—';
  const threats=connections.filter(c=>c.threat?.matched).length;
  $('threat-count').textContent=flowsValid?`${threats} IOC`:'— IOC';$('threat-count').style.color=threats?'var(--red)':'var(--cyan)';
  $('variance-label').textContent=`${num(t.variance,3)} / ${num(t.threshold,3)} dB²`;
  renderConnections(connections);renderLocation(snapshot.location||{},transportAge,forceStale);
  const displayState={...snapshot,telemetry:stale?null:t,connections,origin:forceStale?null:snapshot.origin};
  globe?.update(displayState);radar?.update(displayState);
}

function renderLocation(location,transportAge,forceStale) {
  const age=Number.isFinite(location.age_s)?location.age_s+transportAge:null;
  const statuses={idle:'Non richiesta',requesting:'Richiesta al sistema',active:'Fix disponibile',stale:'Fix scaduto',unavailable:'Non disponibile',error:'Errore del provider',stopped:'Interrotta'};
  const active=location.status==='active'&&!forceStale&&age!==null&&age<=60;
  $('location-badge').textContent=forceStale?'SCADUTA':(statuses[location.status]||'N/D').toUpperCase();
  $('location-badge').className=`tag${active?'':' amber'}`;
  $('location-status').textContent=location.message||statuses[location.status]||'Nessuna posizione disponibile dal sistema.';
  $('location-source').textContent=location.source||'Non disponibile';
  $('location-accuracy').textContent=Number.isFinite(location.accuracy_m)?`± ${num(location.accuracy_m,1)} m`:'Non disponibile';
  $('location-age').textContent=ageLabel(age);$('location-age').classList.toggle('stale',!active);
  $('location-start').disabled=forceStale||Boolean(location.running);
  $('location-stop').disabled=forceStale||(!location.running&&!['active','stale'].includes(location.status));
  $('geo-note').textContent=active?'Solo fix del PC con accuratezza dichiarata. Il paese IP non è una posizione del server.':'Nessun fix locale valido recente. Paesi IP nell’elenco, senza punti o archi inventati.';
}

function renderDevices(devices) {
  const signature=JSON.stringify(devices.map(d=>[d.id,d.name,d.category,d.rssi_dbm,d.ip]));if(signature===deviceSignature)return;deviceSignature=signature;
  const fragment=document.createDocumentFragment();
  for(const device of devices.slice(0,100)) {
    const button=document.createElement('button');button.className=`device-button ${device.category||''}`;button.type='button';
    const symbol=document.createElement('span');symbol.className='device-symbol';symbol.textContent=symbols[device.category]||symbols.unknown;
    const text=document.createElement('span');text.className='device-text';const name=document.createElement('strong'),detail=document.createElement('small');
    name.textContent=device.name||device.ip||device.id;detail.textContent=`${categories[device.category]||'Sconosciuto'} · ${device.ip||device.mac||'BLE'}`;text.append(name,detail);
    const signal=document.createElement('span');signal.className='device-signal';signal.textContent=device.rssi_dbm==null?'—':`${num(device.rssi_dbm,0)}`;
    button.append(symbol,text,signal);button.addEventListener('click',()=>inspectDevice((snapshot.devices||[]).find(d=>d.id===device.id)||device));fragment.append(button);
  }
  if(!devices.length){const text=document.createElement('p');text.className='muted compact';text.textContent='Nessun dispositivo inventariato. Avvia una scansione.';fragment.append(text);}
  $('device-list').replaceChildren(fragment);
}

function renderConnections(connections) {
  const signature=JSON.stringify(connections.map(c=>[c.id,c.remote_ip,c.remote_port,c.geo?.country,c.threat?.matched]));if(signature===connectionSignature)return;connectionSignature=signature;
  const fragment=document.createDocumentFragment();
  for(const connection of connections.slice(0,100)) {
    const button=document.createElement('button');button.className=`connection-button${connection.threat?.matched?' threat':''}`;button.type='button';
    const text=document.createElement('span'),name=document.createElement('strong'),detail=document.createElement('small');
    name.textContent=`${connection.remote_ip}:${connection.remote_port||'—'}`;detail.textContent=connection.threat?.matched?'MATCH IOC · verifica richiesta':`${connection.protocol||'IP'} · ${connection.process||connection.scope||'Osservato'}`;
    text.append(name,detail);const country=document.createElement('span');country.className='flow-country';country.textContent=connection.geo?.country||'GEO N/D';
    button.append(text,country);button.addEventListener('click',()=>inspectConnection((snapshot.connections||[]).find(c=>c.id===connection.id)||connection));fragment.append(button);
  }
  if(!connections.length){const text=document.createElement('p');text.className='muted compact';text.textContent='Nessuna connessione esterna visibile. Gli IP senza coordinate restano nell’elenco.';fragment.append(text);}
  $('connection-list').replaceChildren(fragment);
}

function canvasContext(id) {
  const canvas=$(id),rect=canvas.getBoundingClientRect(),scale=Math.min(devicePixelRatio,2);
  if(rect.width<2||rect.height<2)return null;
  const width=Math.round(rect.width*scale),height=Math.round(rect.height*scale);
  if(canvas.width!==width||canvas.height!==height){canvas.width=width;canvas.height=height;}
  const ctx=canvas.getContext('2d');ctx.setTransform(scale,0,0,scale,0,0);ctx.clearRect(0,0,rect.width,rect.height);
  return {ctx,width:rect.width,height:rect.height};
}

function drawSignal() {
  const context=canvasContext('signal-chart');if(!context)return;const {ctx,width,height}=context;
  const pad=5,mid=height*.36,lower=height*.92;
  ctx.strokeStyle='#1b3445';ctx.lineWidth=.6;
  for(let i=1;i<8;i++){ctx.beginPath();ctx.moveTo(width*i/8,0);ctx.lineTo(width*i/8,height);ctx.stroke();}
  for(const y of [mid,lower]){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(width,y);ctx.stroke();}
  if(samples.length<2)return;
  const last=samples.at(-1).time,maxWave=Math.max(.4,...samples.map(s=>Math.abs(s.filtered))),maxVar=Math.max(.1,...samples.map(s=>Math.max(s.variance,s.threshold||0)));
  const x=s=>pad+(s.time-last+30)/30*(width-2*pad);
  const plot=(value,color)=>{ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=1.25;let first=true;for(const s of samples){const y=value(s);if(!Number.isFinite(y)){first=true;continue;}if(first){ctx.moveTo(x(s),y);first=false;}else ctx.lineTo(x(s),y);}ctx.stroke();};
  plot(s=>Number.isFinite(s.filtered)?mid-s.filtered/maxWave*height*.29:NaN,'#45e1ed');
  plot(s=>Number.isFinite(s.variance)?lower-s.variance/maxVar*height*.32:NaN,'#67efbc');ctx.setLineDash([3,3]);plot(s=>s.threshold==null?NaN:lower-s.threshold/maxVar*height*.32,'#ffc46d');ctx.setLineDash([]);
}

function drawChannels() {
  const context=canvasContext('channel-chart');if(!context)return;const {ctx,width,height}=context;
  const inventoryAge=snapshot?.freshness?.inventory_age_s;
  const recent=Number.isFinite(inventoryAge)&&inventoryAge+(performance.now()-stateReceivedAt)/1000<=60;
  const points=(recent?(snapshot?.access_points||[]):[]).filter(ap=>ap.band===chartBand&&ap.channel>0&&Number.isFinite(ap.rssi_dbm));
  const maxChannel=chartBand==='2.4 GHz'?14:chartBand==='5 GHz'?177:233;
  const left=17,right=width-8,bottom=height-14,top=6;
  ctx.strokeStyle='#203b4c';ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(left,top);ctx.lineTo(left,bottom);ctx.lineTo(right,bottom);ctx.stroke();
  ctx.font='8px Consolas,monospace';ctx.fillStyle='#56758b';
  const ticks=chartBand==='2.4 GHz'?[1,6,11,14]:chartBand==='5 GHz'?[36,64,100,144,177]:[1,53,117,181,233];
  const x=ch=>left+(ch-1)/(maxChannel-1)*(right-left);
  for(const channel of ticks){ctx.fillText(String(channel),x(channel)-4,height-3);ctx.beginPath();ctx.moveTo(x(channel),top);ctx.lineTo(x(channel),bottom);ctx.stroke();}
  for(let i=0;i<points.length;i++) {
    const ap=points[i],peak=bottom-(Math.max(-100,Math.min(-20,ap.rssi_dbm))+100)/80*(bottom-top),center=x(ap.channel),spread=chartBand==='2.4 GHz'?(right-left)/13*2:7;
    const color=i%2===0?'#45e1ed':'#a58aff';ctx.beginPath();ctx.moveTo(center-spread,bottom);ctx.bezierCurveTo(center-spread*.55,bottom,center-spread*.35,peak,center,peak);ctx.bezierCurveTo(center+spread*.35,peak,center+spread*.55,bottom,center+spread,bottom);
    ctx.strokeStyle=color;ctx.lineWidth=1;ctx.stroke();ctx.lineTo(center-spread,bottom);ctx.fillStyle=i%2===0?'#45e1ed14':'#a58aff14';ctx.fill();
  }
  if(!points.length){ctx.fillStyle='#6f899e';ctx.fillText('Nessun BSSID con RSSI disponibile in questa banda',left+5,Math.max(20,height*.45));}
}

document.querySelectorAll('button[data-view]').forEach(button=>button.addEventListener('click',()=>{
  $('scene-stage').dataset.view=button.dataset.view;document.querySelectorAll('button[data-view]').forEach(b=>b.classList.toggle('active',b===button));
  requestAnimationFrame(()=>{globe?.resize();radar?.resize();});
}));
document.querySelectorAll('[data-band]').forEach(button=>button.addEventListener('click',()=>{chartBand=button.dataset.band;document.querySelectorAll('[data-band]').forEach(b=>b.classList.toggle('active',b===button));drawChannels();}));
$('calibrate').addEventListener('click',()=>{if(command('calibrate')){$('calibrate').disabled=true;log('Calibrazione richiesta: mantenere la stanza vuota per preparazione e misura.');}});
$('scan').addEventListener('click',()=>{if(command('scan')){$('scan').disabled=true;log('Scansione locale richiesta; sensing sospeso durante le sonde.');}});
$('capture-toggle').addEventListener('change',event=>{if(command('capture',{value:event.target.checked}))event.target.disabled=true;});
$('location-start').addEventListener('click',()=>{if(command('location_start'))$('location-start').disabled=true;});
$('location-stop').addEventListener('click',()=>command('location_stop'));
$('reset-view').addEventListener('click',()=>{globe?.resetView();radar?.resetView();});
$('dbip-credit').addEventListener('click',event=>{event.preventDefault();inspect({title:'Fonti geografiche offline',kind:'country',data:{database:'DB-IP Country Lite',attribuzione:'IP Geolocation by DB-IP',fonte:'https://db-ip.com',licenza:'CC BY 4.0 · attribuzione richiesta',cartografia:'Natural Earth · pubblico dominio',precisione:'Attribuzione di paese nel database: posizione fisica del server non verificata.'}});});
$('pause-view').addEventListener('click',()=>{paused=!paused;globe?.setPaused(paused);radar?.setPaused(paused);$('pause-view').textContent=paused?'▶':'Ⅱ';$('pause-view').title=paused?'Riprendi le animazioni 3D':'Sospendi solo le animazioni 3D';});
const chartResize=new ResizeObserver(()=>{drawSignal();drawChannels();});chartResize.observe($('signal-chart'));chartResize.observe($('channel-chart'));
const clockTimer=setInterval(()=>{$('clock').textContent=new Date().toLocaleTimeString('it-IT');refreshFreshness();drawChannels();},1000);
window.addEventListener('beforeunload',()=>{closing=true;clearTimeout(reconnectTimer);clearInterval(clockTimer);clearTimeout(toastTimer);cancelAnimationFrame(uiFrame);socket?.close(1000,'Chiusura finestra');chartResize.disconnect();globe?.dispose();radar?.dispose();});
window.addEventListener('unhandledrejection',event=>{log(`Errore frontend: ${event.reason?.message||event.reason}`,'error');});

log('Avvio delle scene WebGL e della sessione locale.');
connect();
try {
  const [{GlobeScene},{RadarScene}]=await Promise.all([import('./scene_globe.js'),import('./scene_radar.js')]);
  globe=new GlobeScene($('globe-canvas'),inspect,sceneError);radar=new RadarScene($('radar-canvas'),inspect,sceneError);
  if(snapshot){globe.update(snapshot);radar.update(snapshot);}
  log('Globo e radar pronti. Asset caricati esclusivamente dal server locale.');
} catch(error) {sceneError(`${error.message}. Verificare setup_offline.py e il supporto WebGL del WebView.`);}
