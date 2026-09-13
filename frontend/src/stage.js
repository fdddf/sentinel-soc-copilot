// 3D stage: enterprise network topology + Cognee threat knowledge graph (three.js / 3d-force-graph)
import * as THREE from 'three';
import ForceGraph3D from '3d-force-graph';
import SpriteText from 'three-spritetext';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';

export const C = {
  bg: 0x02040a,
  cyan: '#22d3ee',
  blue: '#3b82f6',
  dim: '#1e3a5f',
  red: '#ff2d55',
  amber: '#fbbf24',
  green: '#34d399',
  magenta: '#e879f9',
  violet: '#8b5cf6',
  white: '#e2e8f0',
};

const KIND_STYLE = {
  // network
  cloud: { color: C.violet, size: 7, shape: 'ico' },
  firewall: { color: C.amber, size: 6, shape: 'box' },
  switch: { color: C.blue, size: 4.5, shape: 'oct' },
  workstation: { color: C.cyan, size: 3.2, shape: 'sphere' },
  server: { color: '#60a5fa', size: 4.2, shape: 'box' },
  dc: { color: '#a78bfa', size: 5, shape: 'box' },
  edge: { color: '#38bdf8', size: 4, shape: 'box' },
  // knowledge graph
  incident: { color: C.red, size: 9, shape: 'ico' },
  asset: { color: C.red, size: 4.5, shape: 'box' },
  observed: { color: '#fb7185', size: 4.5, shape: 'oct' },
  semantic: { color: '#f9a8d4', size: 3.5, shape: 'oct' },
  group: { color: C.magenta, size: 7.5, shape: 'dodeca' },
  predicted: { color: C.amber, size: 5, shape: 'oct' },
  context: { color: '#475569', size: 2.2, shape: 'sphere' },
  software: { color: '#94a3b8', size: 3, shape: 'tetra' },
  mitigation: { color: C.green, size: 4.5, shape: 'torus' },
};

const REL_COLOR = {
  observed: '#fb7185', affected: C.red, similar: '#f9a8d4', uses: '#64748b', predicts: C.amber,
  mitigates: C.green, uses_software: '#475569',
};

let glowTexture;
function glow() {
  if (glowTexture) return glowTexture;
  const cv = document.createElement('canvas');
  cv.width = cv.height = 128;
  const g = cv.getContext('2d');
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, 'rgba(255,255,255,1)');
  grad.addColorStop(0.25, 'rgba(255,255,255,0.45)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  glowTexture = new THREE.CanvasTexture(cv);
  return glowTexture;
}

function geometry(shape, s) {
  switch (shape) {
    case 'box': return new THREE.BoxGeometry(s * 1.3, s * 1.3, s * 1.3);
    case 'oct': return new THREE.OctahedronGeometry(s);
    case 'ico': return new THREE.IcosahedronGeometry(s, 0);
    case 'dodeca': return new THREE.DodecahedronGeometry(s, 0);
    case 'tetra': return new THREE.TetrahedronGeometry(s);
    case 'torus': return new THREE.TorusGeometry(s * 0.8, s * 0.25, 8, 24);
    default: return new THREE.SphereGeometry(s * 0.8, 16, 12);
  }
}

export class Stage {
  constructor(el) {
    this.el = el;
    this.mode = 'network';
    this.objects = new Map(); // node id -> { group, mesh, halo, label, style, state }
    this.effects = [];
    this.linkState = new Map();

    this.graph = new ForceGraph3D(el, { controlType: 'orbit' })
      .backgroundColor('#02040a')
      .showNavInfo(false)
      .nodeRelSize(1)
      .nodeThreeObject((n) => this.makeNode(n))
      .linkColor((l) => this.linkColor(l))
      .linkOpacity(0.55)
      .linkWidth((l) => this.linkWidth(l))
      .linkDirectionalParticles((l) => this.particles(l))
      .linkDirectionalParticleWidth((l) => (this.linkState.get(this.linkKey(l)) === 'attack' ? 2.6 : 1.1))
      .linkDirectionalParticleSpeed((l) => (this.linkState.get(this.linkKey(l)) === 'attack' ? 0.018 : 0.006))
      .linkDirectionalParticleColor((l) => this.particleColor(l))
      .enableNodeDrag(false)
      .onNodeHover((n) => { el.style.cursor = n ? 'pointer' : 'grab'; })
      .onNodeClick((n) => this.onNodeClick && this.onNodeClick(n));

    const w = el.clientWidth, h = el.clientHeight;
    this.bloom = new UnrealBloomPass(new THREE.Vector2(w, h), 0.8, 0.55, 0.12);
    this.graph.postProcessingComposer().addPass(this.bloom);

    this.addBackdrop();
    window.addEventListener('resize', () => this.graph.width(el.clientWidth).height(el.clientHeight));
    this.clock = new THREE.Clock();
    const tick = () => { this.animate(); requestAnimationFrame(tick); };
    tick();
  }

  addBackdrop() {
    const scene = this.graph.scene();
    // star dust
    const n = 2500, pos = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const r = 600 + Math.random() * 1400, th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
      pos[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th);
      pos[i * 3 + 2] = r * Math.cos(ph);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    this.stars = new THREE.Points(g, new THREE.PointsMaterial({ color: 0x3b82f6, size: 2, transparent: true, opacity: 0.6 }));
    scene.add(this.stars);
    // holographic floor grid + rings
    const grid = new THREE.PolarGridHelper(260, 24, 10, 96, 0x0e7490, 0x0b2540);
    grid.position.y = -70;
    grid.material.transparent = true;
    grid.material.opacity = 0.35;
    this.grid = grid;
    scene.add(grid);
    this.ring = new THREE.Mesh(new THREE.RingGeometry(268, 270, 128),
      new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.5, side: THREE.DoubleSide }));
    this.ring.rotation.x = -Math.PI / 2;
    this.ring.position.y = -70;
    scene.add(this.ring);
    scene.add(new THREE.AmbientLight(0xffffff, 0.6));
    const dl = new THREE.DirectionalLight(0xffffff, 1.2);
    dl.position.set(100, 200, 150);
    scene.add(dl);
  }

  makeNode(n) {
    const style = KIND_STYLE[n.kind] || KIND_STYLE.workstation;
    const group = new THREE.Group();
    const mat = new THREE.MeshStandardMaterial({
      color: style.color, emissive: style.color, emissiveIntensity: 0.55, metalness: 0.3, roughness: 0.35,
      transparent: true, opacity: 0.95,
    });
    const mesh = new THREE.Mesh(geometry(style.shape, style.size), mat);
    group.add(mesh);
    const wire = new THREE.Mesh(geometry(style.shape, style.size * 1.35),
      new THREE.MeshBasicMaterial({ color: style.color, wireframe: true, transparent: true, opacity: 0.18 }));
    group.add(wire);
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({
      map: glow(), color: style.color, transparent: true, opacity: 0.35, depthWrite: false, blending: THREE.AdditiveBlending,
    }));
    halo.scale.setScalar(style.size * 3.4);
    group.add(halo);
    const showLabel = !['context'].includes(n.kind);
    let label = null;
    if (showLabel) {
      const text = n.kind === 'context' ? '' : (n.label.length > 34 ? n.label.slice(0, 33) + '…' : n.label);
      label = new SpriteText(text, n.kind === 'group' || n.kind === 'incident' ? 5 : ['observed', 'predicted', 'mitigation', 'asset'].includes(n.kind) ? 3.4 : 2.6, '#cbd5e1');
      label.fontFace = 'ui-monospace, SFMono-Regular, Menlo, monospace';
      label.material.depthWrite = false;
      label.position.y = -(style.size + 4.5);
      group.add(label);
    }
    const obj = { group, mesh, wire, halo, label, style, state: 'normal', node: n, born: this.clock ? this.clock.elapsedTime : 0 };
    this.objects.set(n.id, obj);
    return group;
  }

  setNodeState(id, state) {
    const o = this.objects.get(id);
    if (!o) return;
    o.state = state;
    const color = { alert: C.red, compromised: C.red, risk: C.amber, normal: o.style.color, dim: '#1e293b', focus: C.white }[state] || o.style.color;
    o.mesh.material.color.set(color);
    o.mesh.material.emissive.set(color);
    o.mesh.material.emissiveIntensity = state === 'dim' ? 0.1 : (state === 'normal' ? 0.55 : 1.4);
    o.wire.material.color.set(color);
    o.wire.material.opacity = state === 'normal' ? 0.18 : (state === 'dim' ? 0.05 : 0.5);
    o.halo.material.color.set(color);
    o.halo.material.opacity = state === 'dim' ? 0.05 : (state === 'normal' ? 0.35 : 0.9);
    if (o.label) o.label.color = state === 'dim' ? '#334155' : (['alert', 'compromised'].includes(state) ? '#fecdd3' : state === 'risk' ? '#fde68a' : '#cbd5e1');
  }

  linkKey(l) {
    const s = typeof l.source === 'object' ? l.source.id : l.source;
    const t = typeof l.target === 'object' ? l.target.id : l.target;
    return `${s}->${t}`;
  }
  linkColor(l) {
    if (this.mode === 'graph') return REL_COLOR[l.rel] || '#334155';
    const st = this.linkState.get(this.linkKey(l));
    return st === 'attack' ? C.red : st === 'hot' ? '#fb7185' : '#1d4ed8';
  }
  linkWidth(l) {
    if (this.mode === 'graph') return l.rel === 'predicts' ? 1.6 : l.rel === 'observed' || l.rel === 'affected' ? 1.2 : 0.35;
    const st = this.linkState.get(this.linkKey(l));
    return st === 'attack' ? 2.2 : st === 'hot' ? 1.2 : 0.5;
  }
  particles(l) {
    if (this.mode === 'graph') return ['predicts', 'observed', 'affected'].includes(l.rel) ? 3 : 0;
    const st = this.linkState.get(this.linkKey(l));
    return st === 'attack' ? 6 : st === 'hot' ? 3 : 2;
  }
  particleColor(l) {
    if (this.mode === 'graph') return REL_COLOR[l.rel] || C.cyan;
    const st = this.linkState.get(this.linkKey(l));
    return st === 'attack' || st === 'hot' ? C.red : C.cyan;
  }
  refreshLinks() {
    // re-evaluate accessor functions
    this.graph.linkColor(this.graph.linkColor()).linkWidth(this.graph.linkWidth())
      .linkDirectionalParticles(this.graph.linkDirectionalParticles());
  }

  // ---------------------------------------------------------------- network mode
  showNetwork(topo) {
    this.mode = 'network';
    this.objects.clear();
    this.linkState.clear();
    const segs = ['DMZ', 'SERVERS', 'FINANCE', 'HR', 'ENGINEERING'];
    const R = 120;
    const swPos = {};
    segs.forEach((s, i) => {
      const a = (i / segs.length) * Math.PI * 2 - Math.PI / 2;
      swPos[s] = { x: Math.cos(a) * R, y: 0, z: Math.sin(a) * R, a };
    });
    const bySeg = {};
    topo.nodes.forEach((n) => { (bySeg[n.segment] ||= []).push(n); });
    const nodes = topo.nodes.map((n) => {
      const c = { ...n };
      if (n.id === 'INTERNET') Object.assign(c, { fx: 0, fy: 95, fz: 0 });
      else if (n.id === 'FW-EDGE') Object.assign(c, { fx: 0, fy: 50, fz: 0 });
      else if (n.id === 'CORE-SW') Object.assign(c, { fx: 0, fy: 0, fz: 0 });
      else if (n.kind === 'switch') Object.assign(c, { fx: swPos[n.segment].x, fy: 0, fz: swPos[n.segment].z });
      else {
        const hosts = bySeg[n.segment].filter((h) => h.kind !== 'switch');
        const i = hosts.findIndex((h) => h.id === n.id);
        const p = swPos[n.segment];
        const ang = (i / hosts.length) * Math.PI * 2;
        const rr = 38;
        Object.assign(c, {
          fx: p.x + Math.cos(ang) * rr * Math.cos(p.a) , fy: Math.sin(ang) * rr * 0.9,
          fz: p.z + Math.cos(ang) * rr * Math.sin(p.a) + Math.sin(ang) * 6,
        });
        // push outward so clusters read as petals
        c.fx += Math.cos(p.a) * 28; c.fz += Math.sin(p.a) * 28;
      }
      return c;
    });
    this.graph.d3Force('charge').strength(-30);
    this.graph.graphData({ nodes, links: topo.links.map((l) => ({ ...l })) });
    this.grid.visible = true; this.ring.visible = true;
    this.graph.cameraPosition({ x: 0, y: 190, z: 330 }, { x: 0, y: 0, z: 0 }, 1800);
    this.autoRotate(true, 0.35);
  }

  autoRotate(on, speed = 0.5) {
    const c = this.graph.controls();
    c.autoRotate = on;
    c.autoRotateSpeed = speed;
  }

  nodePos(id) {
    const n = this.graph.graphData().nodes.find((x) => x.id === id);
    return n ? new THREE.Vector3(n.x ?? n.fx ?? 0, n.y ?? n.fy ?? 0, n.z ?? n.fz ?? 0) : new THREE.Vector3();
  }

  focus(id, dist = 170, ms = 1600) {
    const p = this.nodePos(id);
    // look at the host from the side of its segment "petal", so the cluster fans out instead of stacking
    const a = Math.atan2(p.z, p.x) + Math.PI / 2.6;
    const seg = { x: p.x * 0.8, y: 0, z: p.z * 0.8 };
    this.autoRotate(false);
    this.graph.cameraPosition({ x: seg.x + Math.cos(a) * dist, y: dist * 0.75, z: seg.z + Math.sin(a) * dist }, seg, ms);
  }

  overview(ms = 1800) {
    this.graph.cameraPosition({ x: 0, y: 230, z: 360 }, { x: 0, y: 0, z: 0 }, ms);
    setTimeout(() => this.autoRotate(true, 0.3), ms);
  }

  alarm(id) {
    this.setNodeState(id, 'alert');
    this.spawnShockwave(id, C.red, 60, 1.4, 3);
  }

  spawnShockwave(id, color, maxR = 300, secs = 2.2, repeat = 1) {
    const p = this.nodePos(id);
    for (let k = 0; k < repeat; k++) {
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(1, 48, 24),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.35, wireframe: true, depthWrite: false, blending: THREE.AdditiveBlending }));
      mesh.position.copy(p);
      mesh.visible = false;
      this.graph.scene().add(mesh);
      const ring = new THREE.Mesh(new THREE.RingGeometry(0.96, 1, 96),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, side: THREE.DoubleSide, depthWrite: false, blending: THREE.AdditiveBlending }));
      ring.rotation.x = -Math.PI / 2;
      ring.position.copy(p);
      ring.visible = false;
      this.graph.scene().add(ring);
      this.effects.push({ meshes: [mesh, ring], start: this.clock.elapsedTime + k * (secs / 2.2), secs, maxR });
    }
  }

  // scan wave sweeps outward; nodes are revealed as compromised when the wave reaches them
  scan(fromId, compromised, atRisk, lateral) {
    const origin = this.nodePos(fromId);
    this.spawnShockwave(fromId, C.cyan, 320, 2.6, 2);
    const nodes = this.graph.graphData().nodes;
    const secsPerUnit = 2.6 / 320;
    nodes.forEach((n) => {
      if (n.id === fromId) return;
      const d = this.nodePos(n.id).distanceTo(origin);
      setTimeout(() => {
        if (compromised.includes(n.id)) {
          this.setNodeState(n.id, 'compromised');
          this.spawnShockwave(n.id, C.red, 40, 1.2, 2);
        } else if (atRisk.includes(n.id)) {
          this.setNodeState(n.id, 'risk');
        } else {
          this.flash(n.id);
        }
      }, d * secsPerUnit * 1000);
    });
    setTimeout(() => this.attackPaths(fromId, compromised, lateral), 2800);
  }

  flash(id) {
    const o = this.objects.get(id);
    if (!o) return;
    o.flashUntil = this.clock.elapsedTime + 0.35;
  }

  attackPaths(fromId, compromised, lateral) {
    // highlight the topology path patient-zero -> switch -> core -> switch -> victim
    const links = this.graph.graphData().links;
    const parent = {};
    links.forEach((l) => { parent[l.target.id ?? l.target] = l.source.id ?? l.source; });
    const pathUp = (id) => { const p = [id]; while (parent[p[p.length - 1]]) p.push(parent[p[p.length - 1]]); return p; };
    const mark = (a, b, st) => { this.linkState.set(`${a}->${b}`, st); this.linkState.set(`${b}->${a}`, st); };
    const up0 = pathUp(fromId);
    compromised.forEach((v) => {
      const upV = pathUp(v);
      const common = up0.find((x) => upV.includes(x));
      const chain = [...up0.slice(0, up0.indexOf(common) + 1), ...upV.slice(0, upV.indexOf(common)).reverse()];
      for (let i = 0; i < chain.length - 1; i++) mark(chain[i], chain[i + 1], 'attack');
    });
    this.refreshLinks();
    // direct "lateral movement" arcs
    lateral.forEach((lat, i) => setTimeout(() => this.arc(lat.source, lat.target), i * 450));
  }

  arc(a, b) {
    const pa = this.nodePos(a), pb = this.nodePos(b);
    const mid = pa.clone().add(pb).multiplyScalar(0.5);
    mid.y += 70;
    const curve = new THREE.QuadraticBezierCurve3(pa, mid, pb);
    const geo = new THREE.TubeGeometry(curve, 64, 0.6, 8, false);
    const mat = new THREE.MeshBasicMaterial({ color: C.red, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, depthWrite: false });
    const tube = new THREE.Mesh(geo, mat);
    geo.setDrawRange(0, 0);
    this.graph.scene().add(tube);
    const head = new THREE.Sprite(new THREE.SpriteMaterial({ map: glow(), color: C.red, blending: THREE.AdditiveBlending, depthWrite: false }));
    head.scale.setScalar(14);
    this.graph.scene().add(head);
    const total = geo.index.count;
    this.effects.push({ arc: { tube, head, curve, total }, start: this.clock.elapsedTime, secs: 1.4, persistent: true });
    this.arcs = [...(this.arcs || []), tube, head];
  }

  clearArcs() {
    (this.arcs || []).forEach((m) => this.graph.scene().remove(m));
    this.arcs = [];
  }

  // ---------------------------------------------------------------- knowledge graph mode
  showKnowledgeGraph(data) {
    this.clearArcs();
    this.mode = 'graph';
    this.objects.clear();
    this.grid.visible = false;
    this.ring.visible = false;
    const nodes = data.nodes.map((n) => (n.id === 'incident' ? { ...n, fx: 0, fy: 0, fz: 0 } : { ...n }));
    this.graph.d3Force('charge').strength((n) => (n.kind === 'group' ? -260 : n.kind === 'context' ? -25 : -90));
    this.graph.d3Force('link').distance((l) => (l.rel === 'uses' ? 40 : l.rel === 'uses_software' ? 30 : 60));
    this.graph.graphData({ nodes, links: data.links.map((l) => ({ ...l })) });
    this.graph.d3ReheatSimulation();
    this.graph.cameraPosition({ x: 0, y: 60, z: 420 }, { x: 0, y: 0, z: 0 }, 2000);
    setTimeout(() => this.autoRotate(true, 0.6), 2000);
  }

  // ---------------------------------------------------------------- frame loop
  animate() {
    const t = this.clock.getElapsedTime();
    if (this.stars) this.stars.rotation.y = t * 0.01;
    if (this.ring) { this.ring.material.opacity = 0.25 + 0.2 * Math.sin(t * 1.5); }
    this.objects.forEach((o) => {
      o.wire.rotation.y = t * 0.4;
      o.wire.rotation.x = t * 0.25;
      let s = 1;
      if (['alert', 'compromised'].includes(o.state)) s = 1 + 0.28 * Math.sin(t * 6);
      else if (o.state === 'risk' || o.node.kind === 'predicted') s = 1 + 0.18 * Math.sin(t * 3.5);
      else if (o.node.kind === 'incident') s = 1 + 0.12 * Math.sin(t * 2.5);
      // birth animation
      const age = t - (o.born || 0);
      if (age < 0.8) s *= Math.max(0.01, age / 0.8);
      o.group.scale.setScalar(s);
      if (o.flashUntil && t < o.flashUntil) o.halo.material.opacity = 1;
      else if (o.flashUntil) { o.flashUntil = null; this.setNodeState(o.node.id, o.state); }
    });
    this.effects = this.effects.filter((e) => {
      const k = (t - e.start) / e.secs;
      if (k < 0) return true;
      if (e.arc) {
        const { tube, head, curve, total } = e.arc;
        const kk = Math.min(1, k);
        tube.geometry.setDrawRange(0, Math.floor(total * kk));
        head.position.copy(curve.getPoint(kk));
        head.material.opacity = kk < 1 ? 1 : 0.6 + 0.4 * Math.sin(t * 5);
        tube.material.opacity = 0.55 + 0.3 * Math.sin(t * 4);
        return true;
      }
      if (k >= 1) { e.meshes.forEach((m) => this.graph.scene().remove(m)); return false; }
      e.meshes.forEach((m, i) => {
        m.visible = true;
        m.scale.setScalar(Math.max(0.01, e.maxR * k));
        m.material.opacity = (i === 0 ? 0.25 : 0.9) * (1 - k);
      });
      return true;
    });
  }
}
