import * as THREE from './libs/three.min.js';

export const COLORS = {cyan:0x45e1ed,mint:0x67efbc,amber:0xffc46d,red:0xff557b,purple:0xa58aff,dim:0x234b61};

export function hash(text) {
  let value = 2166136261;
  for (const char of String(text)) value = Math.imul(value ^ char.charCodeAt(0), 16777619);
  return value >>> 0;
}

export function disposeTree(root) {
  const geometries = new Set(), materials = new Set(), textures = new Set();
  root.traverse(node => {
    if (node.geometry) geometries.add(node.geometry);
    for (const material of (Array.isArray(node.material) ? node.material : [node.material])) {
      if (!material) continue;
      materials.add(material);
      for (const value of Object.values(material)) if (value?.isTexture) textures.add(value);
    }
  });
  for (const texture of textures) texture.dispose();
  for (const material of materials) material.dispose();
  for (const geometry of geometries) geometry.dispose();
  root.clear();
}

export function labelSprite(text, color='#b8dbe8', scale=2.5) {
  const canvas = document.createElement('canvas');
  canvas.width=512; canvas.height=96;
  const ctx=canvas.getContext('2d');
  ctx.font='24px Consolas, monospace'; ctx.textAlign='center'; ctx.textBaseline='middle';
  ctx.fillStyle=color;
  const value=String(text).length>35?String(text).slice(0,32)+'…':String(text);
  ctx.fillText(value,256,48,495);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({map:texture,transparent:true,depthWrite:false,depthTest:false}));
  sprite.scale.set(scale,scale*96/512,1);
  return sprite;
}

export function starField(count=250, radius=80) {
  const positions=new Float32Array(count*3);
  let seed=72612;
  const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
  for(let i=0;i<count;i++) {
    const phi=random()*Math.PI*2, cosTheta=random()*2-1, sinTheta=Math.sqrt(1-cosTheta*cosTheta);
    positions.set([radius*sinTheta*Math.cos(phi),radius*cosTheta,radius*sinTheta*Math.sin(phi)],i*3);
  }
  const geometry=new THREE.BufferGeometry();geometry.setAttribute('position',new THREE.BufferAttribute(positions,3));
  return new THREE.Points(geometry,new THREE.PointsMaterial({color:0x51879d,size:.12,transparent:true,opacity:.55,depthWrite:false}));
}

export function inspectionFor(object) {
  let current=object;
  while(current) { if(current.userData?.inspection) return current.userData.inspection; current=current.parent; }
  return null;
}

export function isCurrentFix(fix) {
  if(!fix)return false;
  const age=Date.now()/1000-fix.timestamp;
  return Number.isFinite(fix.lat)&&Math.abs(fix.lat)<=90&&Number.isFinite(fix.lon)&&Math.abs(fix.lon)<=180
    &&Number.isFinite(fix.accuracy_m)&&fix.accuracy_m>0&&Number.isFinite(fix.timestamp)
    &&age>=0&&age<=60&&typeof fix.source==='string'&&fix.source.length>0;
}
