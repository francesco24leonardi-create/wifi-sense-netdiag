import * as THREE from './libs/three.min.js';
import {OrbitControls} from './libs/OrbitControls.js';
import {COLORS,disposeTree,hash,inspectionFor,labelSprite,starField} from './scene_common.js';

function material(color, opacity=1) {
  return new THREE.MeshStandardMaterial({color,emissive:color,emissiveIntensity:.23,roughness:.42,metalness:.55,transparent:opacity<1,opacity});
}

function box(group,size,position,color,opacity=1) {
  const mesh=new THREE.Mesh(new THREE.BoxGeometry(...size),material(color,opacity));
  mesh.position.set(...position);group.add(mesh);return mesh;
}

function cylinder(group,radius,height,position,color) {
  const mesh=new THREE.Mesh(new THREE.CylinderGeometry(radius,radius,height,14),material(color));
  mesh.position.set(...position);group.add(mesh);return mesh;
}

function line(group,points,color) {
  const geometry=new THREE.BufferGeometry().setFromPoints(points.map(p=>new THREE.Vector3(...p)));
  const object=new THREE.Line(geometry,new THREE.LineBasicMaterial({color,transparent:true,opacity:.85}));
  group.add(object);return object;
}

function deviceIcon(category,color) {
  const group=new THREE.Group();
  if(category==='pc') {
    box(group,[.95,.66,.14],[0,.33,0],color);box(group,[.82,.52,.025],[0,.33,.085],0x061a2a);
    cylinder(group,.06,.28,[0,-.1,0],color);box(group,[.55,.055,.36],[0,-.26,.02],color);
    box(group,[.43,.69,.4],[.83,.1,-.08],0x296078);box(group,[.05,.05,.025],[.83,.3,.14],COLORS.mint);
  } else if(category==='smartphone') {
    box(group,[.44,.9,.1],[0,.18,0],color);box(group,[.35,.71,.02],[0,.2,.06],0x071827);
    cylinder(group,.025,.02,[0,-.2,.07],color).rotation.x=Math.PI/2;
    box(group,[.1,.02,.02],[0,.58,.065],color);
  } else if(category==='tv') {
    box(group,[1.25,.73,.12],[0,.25,0],color);box(group,[1.1,.6,.015],[0,.25,.071],0x091d30);
    line(group,[[-.42,-.12,0],[-.55,-.38,.2]],color);line(group,[[.42,-.12,0],[.55,-.38,.2]],color);
    const screen=new THREE.Mesh(new THREE.PlaneGeometry(.9,.014),new THREE.MeshBasicMaterial({color,transparent:true,opacity:.6}));screen.position.set(0,.2,.083);group.add(screen);
  } else if(category==='bluetooth') {
    const crystal=new THREE.Mesh(new THREE.OctahedronGeometry(.56,0),material(color,.18));group.add(crystal);
    line(group,[[0,-.47,.13],[0,.47,.13],[.3,.2,.13],[-.25,-.2,.13]],color);
    line(group,[[-.25,.2,.13],[.3,-.2,.13],[0,-.47,.13]],color);
  } else if(category==='router'||category==='radio') {
    box(group,[.94,.23,.6],[0,0,0],color);
    for(const x of [-.35,.35]) cylinder(group,.025,.73,[x,.44,-.16],color);
    for(const x of [-.2,0,.2]) box(group,[.04,.025,.03],[x,.015,.31],COLORS.mint);
    if(category==='radio') {
      for(const r of [.35,.55]) {
        const arc=new THREE.Mesh(new THREE.TorusGeometry(r,.014,5,30,Math.PI),new THREE.MeshBasicMaterial({color}));
        arc.position.y=.63;group.add(arc);
      }
    }
  } else if(category==='iot') {
    const chip=box(group,[.52,.52,.22],[0,.12,0],color);
    box(group,[.27,.27,.03],[0,.12,.13],0x0b2634);
    for(const p of [-.18,0,.18]) {
      line(group,[[-.37,p+.12,0],[-.25,p+.12,0]],color);line(group,[[.25,p+.12,0],[.37,p+.12,0]],color);
      line(group,[[p,-.26,0],[p,-.14,0]],color);line(group,[[p,.38,0],[p,.5,0]],color);
    }
    chip.rotation.y=.08;
  } else {
    const shape=new THREE.Mesh(new THREE.IcosahedronGeometry(.44,0),material(color,.6));group.add(shape);
    const edges=new THREE.LineSegments(new THREE.EdgesGeometry(shape.geometry),new THREE.LineBasicMaterial({color}));group.add(edges);
  }
  return group;
}

export class RadarScene {
  constructor(container,onInspect,onError=()=>{}) {
    this.container=container;this.onInspect=onInspect;this.onError=onError;
    this.scene=new THREE.Scene();this.scene.fog=new THREE.FogExp2(0x06111d,.017);
    this.camera=new THREE.PerspectiveCamera(45,1,.1,180);
    this.renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'high-performance'});
    this.renderer.setPixelRatio(Math.min(devicePixelRatio,1.75));this.renderer.setClearColor(0x06111d,0);
    this.renderer.outputColorSpace=THREE.SRGBColorSpace;this.container.appendChild(this.renderer.domElement);
    this.controls=new OrbitControls(this.camera,this.renderer.domElement);this.controls.enableDamping=true;
    this.controls.dampingFactor=.075;this.controls.minDistance=5;this.controls.maxDistance=40;
    this.controls.maxPolarAngle=Math.PI*.49;this.controls.enablePan=true;
    this.scene.add(new THREE.AmbientLight(0xb9d8ff,1.2));
    const light=new THREE.DirectionalLight(0x6feaff,2.4);light.position.set(5,12,8);this.scene.add(light);
    const rim=new THREE.PointLight(0x9969ff,25,30);rim.position.set(-6,6,-4);this.scene.add(rim);
    this.scene.add(starField(160,65));
    this.base=new THREE.Group();this.devices=new THREE.Group();this.eventGroup=new THREE.Group();
    this.scene.add(this.base,this.devices,this.eventGroup);
    this.picks=[];this.nodes=[];this.events=[];this.signature='';this.eventSignature='';this.perturbation=0;this.paused=false;this.clock=0;this.lastFrame=performance.now();
    this.buildFloor();this.resetView();this.bindPointer();
    this.resizeObserver=new ResizeObserver(()=>this.resize());this.resizeObserver.observe(container);this.resize();
    this.contextLost=e=>{e.preventDefault();this.onError('Contesto WebGL perso. Riavviare la vista o verificare il driver grafico.');};
    this.renderer.domElement.addEventListener('webglcontextlost',this.contextLost);
    this.frame=this.frame.bind(this);this.raf=requestAnimationFrame(this.frame);
  }

  buildFloor() {
    const grid=new THREE.GridHelper(24,24,0x2c6d82,0x173849);grid.position.y=-.9;
    grid.material.transparent=true;grid.material.opacity=.36;this.base.add(grid);
    const floor=new THREE.Mesh(new THREE.CircleGeometry(12,80),new THREE.MeshBasicMaterial({color:0x071b2b,transparent:true,opacity:.35,side:THREE.DoubleSide}));
    floor.rotation.x=-Math.PI/2;floor.position.y=-.94;this.base.add(floor);
    for(const radius of [2,4,6,8,10]) {
      const ring=new THREE.Mesh(new THREE.RingGeometry(radius-.015,radius+.015,100),new THREE.MeshBasicMaterial({color:0x276179,transparent:true,opacity:.4,side:THREE.DoubleSide}));
      ring.rotation.x=-Math.PI/2;ring.position.y=-.87;this.base.add(ring);
    }
    this.center=deviceIcon('router',COLORS.cyan);this.center.scale.setScalar(1.3);this.center.position.y=.2;
    this.center.userData.inspection={title:'Nodo locale / tratta PC ↔ AP',kind:'router',data:{posizione:'Centro convenzionale del radar',misura:'RSSI della sola tratta PC–access point',limite:'La posizione del router rispetto al PC non viene misurata.'}};
    this.base.add(this.center);this.picks.push(this.center);
    this.localPC=deviceIcon('pc',COLORS.mint);this.localPC.scale.setScalar(.65);this.localPC.position.set(-1.2,.12,.3);
    this.localPC.userData.inspection={title:'PC locale',kind:'pc',data:{posizione:'Centro convenzionale della scena; separazione PC–AP non misurata'}};
    this.base.add(this.localPC);this.picks.push(this.localPC);
    const title=labelSprite('PC / GATEWAY','#70d9e6',3);title.position.set(0,1.6,0);this.base.add(title);
    this.rings=[];
    for(let i=0;i<7;i++) {
      const ring=new THREE.Mesh(new THREE.RingGeometry(.98,1.015,96),new THREE.MeshBasicMaterial({color:COLORS.cyan,transparent:true,opacity:.3,side:THREE.DoubleSide,depthWrite:false}));
      ring.rotation.x=-Math.PI/2;ring.position.y=-.65+i*.015;
      ring.userData.inspection={title:'Onda radio — rappresentazione',kind:'wave',data:{significato:'Animazione del campo radio, non misura della propagazione',rilevamento:'Varianza RSSI della tratta PC ↔ AP'}};
      this.base.add(ring);this.rings.push(ring);this.picks.push(ring);
    }
    const geometry=new THREE.PlaneGeometry(22,22,44,44);geometry.rotateX(-Math.PI/2);
    this.deformation=new THREE.Mesh(geometry,new THREE.MeshBasicMaterial({color:COLORS.amber,wireframe:true,transparent:true,opacity:0,depthWrite:false}));
    this.deformation.position.y=-.6;this.base.add(this.deformation);
    this.volume=new THREE.Mesh(new THREE.SphereGeometry(1,28,20),new THREE.MeshBasicMaterial({color:COLORS.amber,wireframe:true,transparent:true,opacity:0,depthWrite:false}));
    this.volume.scale.set(4,2.7,4);this.volume.position.y=1.25;this.base.add(this.volume);
    this.volume.userData.inspection={title:'Perturbazione del collegamento radio',kind:'rf',data:{causa:'Non identificabile dal solo RSSI',localizzazione:'Non disponibile',persone:'Non distinguibili da interferenze o altri cambiamenti del canale',pareti:'Nessuna capacità verificata di rilevare persone attraverso pareti'}};
    this.picks.push(this.volume);
  }

  bindPointer() {
    this.raycaster=new THREE.Raycaster();this.pointer=new THREE.Vector2();this.down=null;
    this.pointerDown=e=>{this.down={x:e.clientX,y:e.clientY};};
    this.pointerUp=e=>{
      if(!this.down||Math.hypot(e.clientX-this.down.x,e.clientY-this.down.y)>6)return;
      const rect=this.renderer.domElement.getBoundingClientRect();
      this.pointer.set(((e.clientX-rect.left)/rect.width)*2-1,-((e.clientY-rect.top)/rect.height)*2+1);
      this.raycaster.setFromCamera(this.pointer,this.camera);
      const hits=this.raycaster.intersectObjects(this.picks,true);
      for(const hit of hits) {
        if(hit.object===this.volume&&this.perturbation<.02)continue;
        const data=inspectionFor(hit.object);if(data){this.onInspect(data);break;}
      }
    };
    this.renderer.domElement.addEventListener('pointerdown',this.pointerDown);
    this.renderer.domElement.addEventListener('pointerup',this.pointerUp);
  }

  update(state) {
    const devices=(state.devices||[]).slice(0,80).map(d=>d.transport==='ble'?{...d,category:'bluetooth',category_note:'Trasporto BLE, tipo fisico non identificato'}:d);
    const points=(state.access_points||[]).slice(0,24).map(ap=>({...ap,id:`ap:${ap.bssid}`,name:ap.ssid||'SSID non annunciato',category:'radio'}));
    const items=[...devices.filter(d=>d.ip!==state.network?.address&&d.ip!==state.network?.gateway),...points];
    const signature=JSON.stringify(items.map(item=>[item.id,item.name,item.category,Boolean(item.stale)]));
    if(signature!==this.signature){this.signature=signature;this.rebuildDevices(items);}
    const current=new Map(items.map(item=>[item.id,item]));
    for(const node of this.nodes){const latest=current.get(node.userData.inspection.data.id);if(latest)Object.assign(node.userData.inspection.data,latest);}
    this.center.visible=Boolean(state.network);this.localPC.visible=Boolean(state.network);
    this.center.userData.inspection.data={...this.center.userData.inspection.data,...(state.network||{}),rssi_dbm:state.telemetry?.rssi_dbm,scope:'Tratta PC–AP; centro convenzionale'};
    this.localPC.userData.inspection.data={...this.localPC.userData.inspection.data,...(state.network||{})};
    this.perturbation=state.telemetry?.rf_perturbation?Math.max(.15,Math.min(1,(state.telemetry.intensity||0)/100)):0;
    this.volume.userData.inspection.data.intensita_percento=state.telemetry?.intensity??null;
  }

  rebuildDevices(items) {
    disposeTree(this.devices);this.nodes=[];this.picks=[this.center,this.localPC,...this.rings,this.volume];
    for(const item of items) {
      const key=item.id||item.mac||item.ip||item.name;
      const angle=(hash(key)%10000)/10000*Math.PI*2;

      const radius=7.5+(hash(key+'r')%150)/100;
      const color=item.category==='bluetooth'?COLORS.purple:item.category==='radio'?COLORS.mint:COLORS.cyan;
      const node=deviceIcon(item.category,color);node.position.set(Math.cos(angle)*radius,.15+(item.category==='bluetooth'?1.2:0),Math.sin(angle)*radius);
      node.rotation.y=-angle+Math.PI/2;node.scale.setScalar(item.category==='radio'?.7:.9);
      node.userData.inspection={title:item.name||item.ip||'Dispositivo',kind:item.category||'unknown',data:{...item,disposizione:'Layout grafico schematico; nessuna posizione o distanza misurata',misura_direzione:'Non disponibile'}};
      const label=labelSprite(item.name||item.ip||'Dispositivo',item.category==='bluetooth'?'#bba2ff':'#8ec6d7',2.6);label.position.y=1.15;node.add(label);
      const distance=labelSprite('LAYOUT NON SPAZIALE','#537f96',2.35);distance.position.y=-.65;node.add(distance);
      this.devices.add(node);this.nodes.push(node);this.picks.push(node);
      const positions=[new THREE.Vector3(0,-.72,0),new THREE.Vector3(node.position.x,-.72,node.position.z)];
      const path=new THREE.Line(new THREE.BufferGeometry().setFromPoints(positions),new THREE.LineDashedMaterial({color,transparent:true,opacity:.12,dashSize:.15,gapSize:.2}));
      path.computeLineDistances();this.devices.add(path);
    }
    this.picks.push(...this.events);
  }

  resize() {
    const {width,height}=this.container.getBoundingClientRect();if(width<2||height<2)return;
    this.camera.aspect=width/height;this.camera.updateProjectionMatrix();this.renderer.setSize(width,height,false);
  }

  resetView() {this.camera.position.set(13,14,18);this.controls.target.set(0,.1,0);this.controls.update();}
  setPaused(value){this.paused=value;}
  frame(now) {
    this.raf=requestAnimationFrame(this.frame);
    const dt=Math.min((now-this.lastFrame)/1000,.1);this.lastFrame=now;
    if(!this.paused)this.clock+=dt;
    if(this.container.clientWidth<2||this.container.clientHeight<2)return;
    const t=this.clock;
    for(let i=0;i<this.rings.length;i++) {
      const phase=(t*.17+i/this.rings.length)%1, size=.8+phase*10;
      this.rings[i].scale.set(size,size,1);this.rings[i].material.opacity=(1-phase)*.27;
    }
    const positions=this.deformation.geometry.attributes.position;
    if(this.perturbation>0||this.lastPerturbation>0) {
      for(let i=0;i<positions.count;i++){const r=Math.hypot(positions.getX(i),positions.getZ(i));positions.setY(i,Math.sin(r*1.7-t*5)*Math.exp(-r*.12)*this.perturbation*.75);}
      positions.needsUpdate=true;
    }
    this.lastPerturbation=this.perturbation;this.deformation.material.opacity=this.perturbation*.32;
    this.volume.material.opacity=this.perturbation*(.045+.025*Math.sin(t*4));this.volume.rotation.y=t*.12;
    for(let i=0;i<this.nodes.length;i++)this.nodes[i].position.y=.15+(this.nodes[i].userData.inspection.kind==='bluetooth'?1.2:0)+Math.sin(t*1.3+i)*.07;
    for(const node of this.events)node.scale.setScalar(1+Math.sin(t*4)*.035);
    this.controls.update();this.renderer.render(this.scene,this.camera);
  }

  dispose() {
    cancelAnimationFrame(this.raf);this.resizeObserver.disconnect();this.controls.dispose();
    this.renderer.domElement.removeEventListener('pointerdown',this.pointerDown);this.renderer.domElement.removeEventListener('pointerup',this.pointerUp);
    this.renderer.domElement.removeEventListener('webglcontextlost',this.contextLost);
    disposeTree(this.scene);this.renderer.dispose();this.renderer.domElement.remove();
  }
}
