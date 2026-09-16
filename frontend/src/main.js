import './style.css';
import { marked } from 'marked';
import { Stage, C } from './stage.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const api = {
  get: (p) => fetch(p).then((r) => r.json()),
  post: (p) => fetch(p, { method: 'POST' }).then((r) => { if (!r.ok) throw new Error(p); return r.json(); }),
};

const S = { step: 0, busy: false, alerts: [], held: [], telemetry: [], topo: null };
const stage = new Stage($('#stage'));

// ------------------------------------------------------------------ console log
function logLine(html) {
  const el = document.createElement('div');
  el.innerHTML = html;
  const box = $('#console-lines');
  box.appendChild(el);
  while (box.children.length > 5) box.firstChild.remove();
}
const qlog = (verb, path, detail, ms) =>
  logLine(`<span class="verb">${verb}</span> <span class="q">qdrant</span> ${esc(path)} <span class="dim">${esc(detail)}</span> <span class="n">${ms}ms</span>`);
const clog = (op, detail, ms) =>
  logLine(`<span class="verb">${op}</span> <span class="cg">cognee</span> <span class="dim">${esc(detail)}</span>${ms != null ? ` <span class="n">${ms}ms</span>` : ''}`);

// ------------------------------------------------------------------ chrome
function legend(mode) {
  const items = mode === 'graph'
    ? [['INCIDENT', C.red], ['observed TTP', '#fb7185'], ['threat group', C.magenta], ['predicted next', C.amber], ['mitigation', C.green], ['software', '#94a3b8']]
    : [['workstation', C.cyan], ['server', '#60a5fa'], ['domain controller', '#a78bfa'], ['switch', C.blue], ['compromised', C.red], ['at risk', C.amber]];
  $('#legend').innerHTML = items.map(([n, c]) => `<span style="--c:${c}"><i></i>${n}</span>`).join('');
  $('#view-mode').textContent = mode === 'graph' ? 'COGNEE THREAT GRAPH' : 'NETWORK VIEW';
}

function clock() {
  const base = 9 * 3600 + 24 * 60;
  const start = performance.now();
  setInterval(() => {
    const t = Math.floor(base + (performance.now() - start) / 1000);
    $('#clock').textContent = `${String(Math.floor(t / 3600)).padStart(2, '0')}:${String(Math.floor(t / 60) % 60).padStart(2, '0')}:${String(t % 60).padStart(2, '0')} CEST`;
  }, 250);
}

function renderAlert(a, prepend = true) {
  const el = document.createElement('div');
  el.className = `alert sev-${a.severity}`;
  el.dataset.id = a.id;
  el.innerHTML = `<div class="t"><span>${a.time} · ${a.severity.toUpperCase()}</span><span>#${a.id}</span></div>
    <div class="n">${esc(a.alert)}</div><div class="h">${a.host}</div>`;
  el.onclick = () => stage.focus(a.host);
  const box = $('#alerts');
  prepend ? box.prepend(el) : box.appendChild(el);
  $('#alert-count').textContent = box.children.length;
  return el;
}

function ticker() {
  let i = 0, count = 0;
  const box = $('#ticker');
  setInterval(() => {
    if (!S.telemetry.length) return;
    const e = S.telemetry[i++ % S.telemetry.length];
    const el = document.createElement('div');
    const hot = S.hot && S.hot.includes(e.host);
    el.innerHTML = `<b>${e.host}</b> ${esc(e.parent)} → <span class="${hot ? 'hot' : ''}">${esc(e.process)}</span>`;
    box.prepend(el);
    while (box.children.length > 40) box.lastChild.remove();
    count++;
  }, 140);
  setInterval(() => { $('#eps').textContent = `${Math.round(count * 60 / 5).toLocaleString()} epm`; count = 0; }, 5000);
}

// ------------------------------------------------------------------ step cards
function card(num, title, tech, techClass) {
  const el = document.createElement('div');
  el.className = 'step';
  el.innerHTML = `<div class="step-head"><span class="step-num">${num}</span><span class="step-title">${title}</span>
    <span class="tech ${techClass}">${tech}</span><span class="ms"><span class="spinner"></span></span></div>
    <div class="summary"></div><div class="step-body"></div>`;
  $('#steps').appendChild(el);
  [...$('#steps').children].slice(0, -1).forEach((c) => c.classList.add('collapsed'));
  el.scrollIntoView({ behavior: 'smooth', block: 'end' });
  return {
    el,
    body: el.querySelector('.step-body'),
    done(ms, summary) {
      el.classList.add('done');
      el.querySelector('.ms').textContent = ms != null ? `${ms} ms` : '✓';
      el.querySelector('.summary').innerHTML = summary || '';
    },
  };
}

async function scramble(el, finalText, ms = 1100) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=$(){}[];.';
  const start = performance.now();
  return new Promise((res) => {
    const frame = () => {
      const k = Math.min(1, (performance.now() - start) / ms);
      const n = Math.floor(finalText.length * k);
      let s = finalText.slice(0, n);
      for (let i = n; i < finalText.length; i++) s += finalText[i] === ' ' ? ' ' : chars[(Math.random() * chars.length) | 0];
      el.textContent = s;
      k < 1 ? requestAnimationFrame(frame) : res();
    };
    frame();
  });
}

// ------------------------------------------------------------------ the demo script
const steps = [
  // 0 -> boot out, network in
  async function start() {
    $('#boot').classList.add('gone');
    stage.showNetwork(S.topo);
    legend('network');
    S.alerts.filter((a) => a.host !== 'WS-FIN-07')
      .sort((a, b) => a.t - b.t).forEach((a) => renderAlert(a));
  },
  // 1 -> critical alert lands
  async function alertIn() {
    const crit = S.held.sort((a, b) => a.t - b.t);
    for (const a of crit) {
      const el = renderAlert(a);
      if (a.severity === 'critical') { el.classList.add('active'); S.alert = a; }
      await sleep(350);
    }
    stage.alarm('WS-FIN-07');
    S.hot = ['WS-FIN-07'];
    stage.focus('WS-FIN-07');
    $('#incident-id').textContent = `INC-2026-0916-${String(S.alert.id).padStart(4, '0')}`;
  },
  // 2 -> decode
  async function decode() {
    const c = card(1, 'DECODE & ENRICH', 'local', 'l');
    S.analysis = await api.post(`/api/analyze/${S.alert.id}`);
    const d = S.analysis.steps[0].decode;
    c.body.innerHTML = `<div class="label">raw command line · ${S.alert.host}</div><div class="code">${esc(d.raw)}</div>
      <div class="label">decoded -EncodedCommand (UTF-16LE)</div><div class="code decoded" id="dec"></div>
      <div class="label">indicators</div><div class="pills" id="ind"></div>`;
    await scramble(c.body.querySelector('#dec'), d.decoded || '(none)');
    c.body.querySelector('#ind').innerHTML =
      d.iocs.map((x, i) => `<span class="pill red" style="animation-delay:${i * 80}ms">IOC ${esc(x)}</span>`).join('') +
      d.indicators.map((x, i) => `<span class="pill" style="animation-delay:${(i + 2) * 80}ms">${esc(x)}</span>`).join('');
    c.done(null, `decoded → <span style="color:#fecdd3">${esc((d.decoded || '').slice(0, 58))}…</span>`);
    logLine(`<span class="verb">DECODE</span> base64/UTF-16LE → ${esc(d.iocs.join(', '))}`);
  },
  // 3 -> hybrid retrieval (opens on the comsvcs alert, where dense vs sparse actually differ)
  async function retrieve() {
    const c = card(2, 'MAP TO ATT&CK + SIGMA', 'Qdrant · weighted RRF', 'q');
    const a = S.analysis;
    const order = a.steps.map((_, i) => i).reverse();
    const tabs = order.map((i) => `<span class="tab" data-i="${i}">#${a.steps[i].event_id} ${esc(a.steps[i].alert.slice(0, 28))}…</span>`).join('');
    c.body.innerHTML = `<div class="tabs">${tabs}</div><div id="cols"></div>
      <div class="label">ATT&CK techniques found (one per alert)</div><div class="pills" id="techs"></div>`;
    // each alert's dominant technique = most frequent tag in its hybrid hits
    const tops = a.steps.map((s) => {
      const freq = {};
      s.retrieval.hybrid.hits.forEach((h) => h.attack_ids.forEach((id) => { freq[id] = (freq[id] || 0) + 1; }));
      return Object.entries(freq).sort((x, y) => y[1] - x[1])[0]?.[0];
    });
    let current = order[0];
    const renderTechs = () => {
      const el = c.body.querySelector('#techs');
      if (!el.dataset.ready) return;
      el.innerHTML = a.techniques.slice(0, 6).map((t) => {
        const src = tops.findIndex((x) => x === t.id);
        const tag = src >= 0 ? `#${a.steps[src].event_id} → ` : '';
        return `<span class="pill red ${src === current ? '' : 'faded'}">${tag}${t.id} ${esc(t.name)}</span>`;
      }).join('');
    };
    const renderCols = (i) => {
      current = i;
      const r = a.steps[i].retrieval;
      const top = tops[i];
      const col = (key, name) => {
        const hits = r[key].hits;
        // untagged Sigma rules can't be judged, so they are neutral and left out of the count
        const state = hits.map((h) => (!h.attack_ids.length ? 'na' : h.attack_ids.includes(top) ? 'good' : 'miss'));
        const n = state.filter((x) => x === 'good').length;
        const total = state.filter((x) => x !== 'na').length;
        const grade = n === 0 ? 'bad' : n < total ? 'mid' : 'ok';
        return `<div class="col ${key === 'hybrid' ? 'win' : ''} ${grade}"><div class="col-head"><span>${name}</span><span class="dim">${r[key].ms}ms</span></div>
        <div class="verdict ${grade}">${n === 0 ? '✗' : '✓'} ${n}<span>/${total}</span>${n === 0 ? ' MISS' : ''}</div>
        ${hits.map((h, j) => {
          const tid = h.attack_ids.includes(top) ? top : h.attack_ids[0] || 'no ATT&CK tag';
          return `<div class="hit ${state[j]}" style="animation-delay:${j * 70}ms" title="${esc(h.title)}">
          <div class="hit-title"><span class="mark">${{ good: '✓', miss: '✗', na: '–' }[state[j]]}</span>${esc(h.title.replace(/^T\d{4}(\.\d{3})? /, ''))}</div>
          <div class="hit-sub"><span class="tid">${esc(tid)}</span><span class="k">${h.kind === 'sigma' ? 'Σ rule' : 'technique'}</span></div></div>`;
        }).join('')}</div>`;
      };
      c.body.querySelector('#cols').innerHTML = `<div class="cols">${col('dense', 'DENSE bge')}${col('sparse', 'SPARSE bm25')}${col('hybrid', 'HYBRID rrf 1:3')}</div>`;
      c.body.querySelectorAll('.tab').forEach((t) => t.classList.toggle('on', +t.dataset.i === i));
      renderTechs();
      qlog('QUERY', 'threat_kb', `dense|bm25 → prefetch+weighted RRF (1:3) · "${a.steps[i].decode.behaviour.slice(0, 50)}…"`, r.hybrid.ms);
    };
    c.body.querySelectorAll('.tab').forEach((t) => (t.onclick = () => renderCols(+t.dataset.i)));
    renderCols(order[0]);
    await sleep(900);
    c.body.querySelector('#techs').dataset.ready = '1';
    renderTechs();
    const ms = a.steps.reduce((s, x) => s + x.retrieval.dense.ms + x.retrieval.sparse.ms + x.retrieval.hybrid.ms, 0).toFixed(1);
    c.done(ms, a.techniques.slice(0, 4).map((t) => t.id).join(' · '));
  },
  // 4 -> hunt
  async function hunt() {
    const c = card(3, 'HUNT LOOKALIKES ACROSS FLEET', 'Qdrant · recommend', 'q');
    S.hunt = await api.post(`/api/hunt/${S.alert.id}`);
    const h = S.hunt;
    const maxScore = Math.max(...h.nearest.rows.map((r) => r.score));
    c.body.innerHTML = `<div class="hunt-phase"><span id="phase">① similarity · group_by=host</span><span class="dim" id="phase-ms">${h.nearest.ms}ms</span></div>
      <div class="rows" id="rows"></div>`;
    const rowsEl = c.body.querySelector('#rows');
    const rowMap = new Map();
    const draw = (rows, scale, phase2) => {
      rows.forEach((r, i) => {
        let el = rowMap.get(r.host);
        if (!el) {
          el = document.createElement('div');
          el.className = 'row';
          el.innerHTML = `<span class="host"></span><span class="bar"><i></i></span><span class="beh"></span>`;
          el.style.position = 'absolute'; el.style.left = 0; el.style.right = 0; el.style.top = 0;
          rowsEl.appendChild(el);
          rowMap.set(r.host, el);
        }
        el.style.transform = `translateY(${i * 28}px)`;
        el.style.opacity = 1;
        el.querySelector('.host').textContent = r.host;
        el.querySelector('.bar i').style.width = `${Math.max(4, (r.z / 3) * 100)}%`;
        const beh = r.event.allowlisted ? `⚠ lookalike (allowlisted) ${r.event.behaviour}` : r.event.behaviour;
        el.querySelector('.beh').textContent = `z=${r.z.toFixed(1)}  ${beh}`;
        el.classList.toggle('lookalike', r.event.allowlisted && !phase2);
        el.classList.toggle('pwn', phase2 && h.compromised.includes(r.host));
      });
      [...rowMap.keys()].filter((k) => !rows.find((r) => r.host === k)).forEach((k) => {
        const el = rowMap.get(k); el.style.opacity = 0; el.style.transform += ' translateX(40px)';
      });
      rowsEl.style.height = `${rows.length * 28}px`;
    };
    const N = 6;
    draw(h.nearest.rows.slice(0, N), maxScore, false);
    qlog('QUERY', 'endpoint_logs/points/query/groups', `query=point#${S.alert.id} group_by=host must_not host=${h.source_host}`, h.nearest.ms);
    await sleep(2200);
    c.body.querySelector('#phase').innerHTML = `② recommend · <span style="color:#86efac">+1 positive</span> / <span style="color:#fca5a5">−${h.negatives} allowlisted negatives</span>`;
    c.body.querySelector('#phase-ms').textContent = `${h.recommend.ms}ms`;
    draw(h.recommend.rows.slice(0, N), maxScore, true);
    qlog('QUERY', 'endpoint_logs/points/query/groups', `recommend{positive:[${S.alert.id}], negative:[${h.negatives} ids], strategy:average_vector}`, h.recommend.ms);
    await sleep(600);
    const pwnCount = h.compromised.length;
    const th = document.createElement('div');
    th.className = 'threshold';
    th.style.cssText = `position:absolute;left:0;right:0;top:${pwnCount * 28 - 1}px`;
    th.innerHTML = `<span>z ≥ ${h.z_threshold} → compromised</span>`;
    rowsEl.appendChild(th);
    // 3D: scan wave + reveal
    stage.overview(1400);
    await sleep(1200);
    stage.scan(h.source_host, h.compromised, h.at_risk, h.lateral);
    S.hot = [h.source_host, ...h.compromised];
    h.lateral.forEach((l) => logLine(`<span class="verb">LATERAL</span> ${l.source} → <span class="q">${l.target}</span> via ${l.via} <span class="dim">@ ${l.time}</span>`));
    c.done((h.nearest.ms + h.recommend.ms).toFixed(1), `<span style="color:#fda4af">${pwnCount} silent footholds:</span> ${h.compromised.join(', ')}`);
  },
  // 5 -> Cognee graph
  async function graph() {
    const c = card(4, 'REASON OVER THREAT GRAPH', 'Cognee · graph', 'cg');
    S.graph = await api.post('/api/graph');
    const g = S.graph;
    if (g.techniques_added.length) qlog('QUERY', 'threat_kb', `hunt evidence → +${g.techniques_added.map((t) => t.id).join(', ')}`, '—');
    clog('TRAVERSE', `Incident → Technique ← uses ← ThreatGroup → uses → Technique · ${g.stats.nodes} nodes / ${g.stats.edges} edges`, g.ms);
    stage.showKnowledgeGraph(g.graph);
    legend('graph');
    const maxO = Math.max(...g.groups.map((x) => x.overlap.length));
    c.body.innerHTML = `<div class="stat-line"><span>graph <b>${g.stats.nodes.toLocaleString()}</b> nodes</span><span><b>${g.stats.edges.toLocaleString()}</b> edges</span><span>source <b>MITRE ATT&CK</b></span></div>
      <div class="label">observed TTPs <span class="dim">(alerts + hunt evidence)</span></div>
      <div class="pills">${g.observed.map((id, i) => `<span class="pill red" style="animation-delay:${i * 60}ms">${id}</span>`).join('')}</div>
      <div class="label">likely actor · TTP overlap</div>
      ${g.groups.map((x, i) => `<div class="grow" style="animation-delay:${i * 150}ms"><b>${esc(x.name)} <span class="dim">${x.id}</span></b><span class="bar"><i style="width:${(x.overlap.length / maxO) * 100}%"></i></span><span>${x.overlap.length}</span></div>`).join('')}
      <div class="label">predicted next moves</div><div class="pills">${g.predicted.map((p, i) => `<span class="pill amber" style="animation-delay:${600 + i * 120}ms">${p.id} ${esc(p.name)}</span>`).join('')}</div>
      <div class="label">mitigations</div><div class="pills">${g.mitigations.map((m, i) => `<span class="pill green" style="animation-delay:${1200 + i * 120}ms">${m.id} ${esc(m.name)}</span>`).join('')}</div>
      <div class="saved">⬢ incident written to Cognee memory · add_data_points · ${g.memory_ms} ms</div>`;
    clog('ADD_DATA_POINTS', `${esc($('#incident-id').textContent)} → observed · affected · attributed_to`, g.memory_ms);
    c.done(g.ms, `${esc(g.groups[0]?.name)} · next: ${g.predicted.slice(0, 2).map((p) => p.id).join(', ')}`);
  },
  // 6 -> report
  async function reportStep() {
    $('#report').hidden = false;
    $('#report-meta').textContent = `generated ${new Date().toLocaleTimeString()} · grounded on Qdrant + Cognee results`;
    const body = $('#report-body');
    body.innerHTML = '';
    const res = await fetch('/api/report');
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let text = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      text += dec.decode(value, { stream: true });
      body.innerHTML = marked.parse(text) + '<span class="cursor"></span>';
      body.scrollTop = body.scrollHeight;
    }
    body.innerHTML = marked.parse(text);
  },
];

async function next() {
  if (S.busy || S.step >= steps.length) return;
  S.busy = true;
  try {
    await steps[S.step]();
    S.step++;
  } catch (e) {
    console.error(e);
    logLine(`<span style="color:#ff2d55">ERROR</span> ${esc(e.message)}`);
  } finally {
    S.busy = false;
  }
}

function backToNetwork() {
  if (!S.hunt) return;
  stage.showNetwork(S.topo);
  legend('network');
  setTimeout(() => {
    stage.setNodeState(S.hunt.source_host, 'alert');
    S.hunt.compromised.forEach((h) => stage.setNodeState(h, 'compromised'));
    S.hunt.at_risk.forEach((h) => stage.setNodeState(h, 'risk'));
    stage.attackPaths(S.hunt.source_host, S.hunt.compromised, S.hunt.lateral);
  }, 300);
}

document.addEventListener('keydown', (e) => {
  if (e.code === 'Space' || e.code === 'ArrowRight' || e.code === 'PageDown') { e.preventDefault(); next(); }
  if (e.key === 'Escape') $('#report').hidden = true;
  if (e.key === 'b' || e.key === 'B') backToNetwork();
  if ((e.key === 'g' || e.key === 'G') && S.graph) { stage.showKnowledgeGraph(S.graph.graph); legend('graph'); }
  if (e.key === 'r' || e.key === 'R') location.reload();
  if (e.key === 'f' || e.key === 'F') document.documentElement.requestFullscreen?.();
});
$('#report-close').onclick = () => ($('#report').hidden = true);
$('#boot').onclick = () => S.step === 0 && next();

// ------------------------------------------------------------------ boot
async function boot() {
  clock();
  const log = $('#boot-log');
  const line = (s) => { log.innerHTML += s + '\n'; };
  line('› connecting to qdrant @ localhost:6333 …');
  const [status, topo, alerts, telemetry] = await Promise.all([
    api.get('/api/status'), api.get('/api/topology'), api.get('/api/alerts'), api.get('/api/telemetry'),
  ]);
  S.topo = topo;
  S.telemetry = telemetry;
  S.alerts = alerts;
  S.held = alerts.filter((a) => a.host === 'WS-FIN-07');
  await sleep(250);
  line(`  <span class="ok">✓</span> threat_kb      ${status.qdrant.threat_kb.toLocaleString()} points  (ATT&CK + Sigma · dense+bm25)`);
  await sleep(200);
  line(`  <span class="ok">✓</span> endpoint_logs  ${status.qdrant.endpoint_logs.toLocaleString()} events · 27 hosts`);
  await sleep(200);
  line(`› loading cognee knowledge graph …`);
  await sleep(250);
  line(`  <span class="ok">✓</span> ${status.cognee.nodes.toLocaleString()} nodes · ${status.cognee.edges.toLocaleString()} edges (groups, techniques, software, mitigations)`);
  await sleep(200);
  line(`  <span class="ok">✓</span> embeddings: fastembed bge-small (local) · reasoning: ${status.llm}`);
  $('#chip-qdrant').textContent = `Qdrant · ${(status.qdrant.threat_kb + status.qdrant.endpoint_logs).toLocaleString()} pts`;
  $('#chip-cognee').textContent = `Cognee · ${status.cognee.nodes.toLocaleString()} nodes`;
  ticker();
}
boot();
