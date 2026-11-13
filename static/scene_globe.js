import * as THREE from './libs/three.min.js';
import {isCurrentFix} from './scene_common.js';

export class GlobeScene {
  constructor(container,onInspect,onError=()=>{}) {
    if(typeof window.Globe!=='function')throw new Error('globe.gl.min.js mancante. Eseguire setup_offline.py prima di avviare l’app.');
    this.container=container;this.onInspect=onInspect;this.onError=onError;this.origin=null;this.signature='';
    this.globe=window.Globe({animateIn:false,waitForGlobeReady:false,rendererConfig:{antialias:true,alpha:true,powerPreference:'high-performance'}})(container);
    this.globe.backgroundColor('rgba(0,0,0,0)').showAtmosphere(true).atmosphereColor('#2d95c5').atmosphereAltitude(.13)
      .showGraticules(true).globeImageUrl(null).pointLabel(()=> '').polygonLabel(()=> '')
      .pointLat('lat').pointLng('lon').pointColor(()=> '#67efbc')
      .pointAltitude(.04).pointRadius(.7).pointResolution(12).pointsTransitionDuration(0)
      .polygonCapColor(()=> '#0e2d3e').polygonSideColor(()=> '#0e3146').polygonStrokeColor(()=> '#205169')
      .polygonAltitude(.004).polygonCapCurvatureResolution(5).polygonsTransitionDuration(0)
      .onPointClick(point=>this.inspectPoint(point))
      .onPolygonClick(feature=>this.onInspect({title:feature.properties?.NAME||feature.properties?.ADMIN||'Area geografica',kind:'country',data:{paese:feature.properties?.NAME||feature.properties?.ADMIN,codice:feature.properties?.ISO_A2_EH||feature.properties?.ISO_A2,fonte:'Natural Earth · vettori locali',nota:'Confine cartografico. Non costituisce una posizione di server, dispositivi o traffico.'}}));
    const sphere=this.globe.globeMaterial();sphere.color.set('#071523');sphere.emissive.set('#04101c');sphere.shininess=5;
    this.globe.renderer().setPixelRatio(Math.min(devicePixelRatio,1.75));
    const controls=this.globe.controls();controls.enableDamping=true;controls.dampingFactor=.08;controls.enablePan=true;
    controls.minDistance=145;controls.maxDistance=1800;controls.autoRotate=false;
    this.resetView();
    this.resizeObserver=new ResizeObserver(()=>this.resize());this.resizeObserver.observe(container);this.resize();
    this.loadWorld();
    // Expire a fix even when the backend stops publishing. Country-only IP
    // records are never converted to coordinates, points, particles or arcs.
    this.expiryTimer=setInterval(()=>{if(this.origin&&!isCurrentFix(this.origin)){this.origin=null;this.signature='';this.globe.pointsData([]);}},1000);
  }

  async loadWorld() {
    try {
      const response=await fetch('/static/world.geojson',{cache:'force-cache'});
      if(!response.ok)throw new Error(`world.geojson: HTTP ${response.status}`);
      const world=await response.json();
      if(!Array.isArray(world.features))throw new Error('Il file world.geojson non contiene una FeatureCollection.');
      if(!this.disposed)this.globe.polygonsData(world.features.filter(f=>['Polygon','MultiPolygon'].includes(f.geometry?.type)));
    }catch(error){this.onError(`${error.message} · Verificare gli asset con setup_offline.py --verify.`);}
  }

  inspectConnection(connection) {
    const {geo,...observed}=connection;
    this.onInspect({title:`${connection.remote_ip}:${connection.remote_port||'—'}`,kind:'connection',data:{...observed,
      paese_da_database:geo?.country||'Non disponibile',fonte_paese:geo?.source||'Non disponibile',
      posizione_server:'Non misurata: l’associazione IP–paese non fornisce coordinate del server.',
      valutazione:connection.threat?.matched?'Corrispondenza nella lista IOC locale; non dimostra un attacco':'Nessuna corrispondenza nella lista consultata; non certifica sicurezza'}});
  }

  inspectPoint(point) {
    this.onInspect({title:'Posizione del PC riferita dal sistema',kind:'origin',data:{...point,
      eta_secondi:Math.max(0,Date.now()/1000-point.timestamp),
      interpretazione:'Fix del provider OS con accuratezza dichiarata; non una verifica indipendente della posizione.',
      dimensione_marker:'Dimensione grafica convenzionale: non rappresenta l’area di accuratezza.'}});
  }

  update(state) {
    this.origin=isCurrentFix(state.origin)?state.origin:null;
    const signature=JSON.stringify(this.origin);
    if(signature===this.signature)return;this.signature=signature;
    this.globe.pointsData(this.origin?[{...this.origin,id:'local'}]:[]);
  }

  fittedAltitude(width,height) {
    const verticalHalf=THREE.MathUtils.degToRad(this.globe.camera().fov||50)/2;
    const horizontalHalf=Math.atan(Math.tan(verticalHalf)*width/height);
    return Math.max(2.1,130/Math.sin(Math.min(verticalHalf,horizontalHalf))/100-1);
  }
  resize(){
    const {width,height}=this.container.getBoundingClientRect();if(width<=1||height<=1)return;
    this.globe.width(width).height(height);
    const size=`${Math.round(width)}:${Math.round(height)}`;
    if(size!==this.lastSize){this.lastSize=size;const previous=this.globe.pointOfView();this.globe.controls().target.set(0,0,0);this.globe.pointOfView({lat:previous.lat,lng:previous.lng,altitude:this.fittedAltitude(width,height)},0);}
  }
  resetView(){
    const {width,height}=this.container.getBoundingClientRect();this.globe.controls().target.set(0,0,0);
    const position=isCurrentFix(this.origin)?this.origin:{lat:20,lon:0};
    // Without a fix this is only a cartographic camera orientation, no marker.
    this.globe.pointOfView({lat:position.lat,lng:position.lon,altitude:this.fittedAltitude(Math.max(1,width),Math.max(1,height))},0);
  }
  setPaused(value){if(value)this.globe.pauseAnimation();else this.globe.resumeAnimation();}
  dispose(){this.disposed=true;clearInterval(this.expiryTimer);this.resizeObserver.disconnect();this.globe._destructor();}
}
