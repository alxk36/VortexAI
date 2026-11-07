// The browser renders server-owned simulation state. It never sends attack traffic.
const $ = (id) => document.getElementById(id);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let state, busy = false, filter = 'all', selected = '', lastTick = -1, commandVersion = 0;
let seenEvents = new Set(), particles = [], lastFindingMarkup = '';
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

// Use a single polling loop so slow requests cannot apply out-of-order snapshots.
async function request(path, body) {
  const response = await fetch(`/api/${path}`, body === undefined ? {cache:'no-store'} : {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The lab could not complete that action.');
  return result;
}
async function command(path, body, message) {
  if (busy) return;
  busy = true;
  commandVersion++;
  renderControls();
  try { update(await request(path, body)); $('message').textContent = message; }
  catch (error) { $('message').textContent = error.message; }
  finally { busy = false; renderControls(); }
}
async function poll() {
  if (!busy) {
    const version = commandVersion;
    try {
      const result = await request('state');
      // An action may have started while the read was in flight. Its response wins.
      if (!busy && version === commandVersion) update(result);
    } catch { $('live-label').textContent = 'DISCONNECTED'; $('message').textContent = 'The local lab is unavailable. Start it with npm start, then refresh.'; }
  }
  setTimeout(poll, 650);
}

function renderControls() {
  $('pause').disabled = busy || !state;
  $('reset').disabled = busy || !state;
  $('pause').textContent = state?.running ? 'Pause simulation' : 'Resume simulation';
  document.querySelectorAll('[data-scenario]').forEach(button => {
    button.disabled = busy || Boolean(state?.activeScenario);
  });
  document.querySelectorAll('[data-recommendation]').forEach(button => {
    button.disabled = busy || Boolean(state?.activeScenario);
    button.textContent = state?.activeScenario ? 'Available when scenario finishes' : 'Approve & apply in lab';
  });
}

function update(next) {
  const first = !state;
  const reset = next.tick < lastTick || (next.metrics.totalEvents === 0 && state?.metrics.totalEvents > 0);
  if (reset) { seenEvents.clear(); particles = []; }
  state = next;
  if (first) {
    $('scenarios').innerHTML = state.scenarios.map((s,i) => `<article class="scenario"><span class="scenario-number">SCENARIO / 0${i+1}</span><h3>${escape(s.name)}</h3><p>${escape(s.description)}</p><button data-scenario="${escape(s.id)}">Run simulation <span aria-hidden="true">↗</span></button></article>`).join('');
    $('resource').innerHTML = '<option value="">Select a node…</option>' + state.nodes.map(n => `<option value="${escape(n.id)}">${escape(n.label)}</option>`).join('');
  }
  if (!first && !reducedMotion) {
    for (const event of state.events) {
      if (!seenEvents.has(event.id)) particles.push({event,start:performance.now(),duration:1400});
    }
  }
  seenEvents = new Set(state.events.map(e=>e.id));
  particles = particles.slice(-80);
  lastTick = state.tick;
  $('live-label').textContent = state.running ? 'LIVE · TICK ' + state.tick : 'PAUSED · TICK ' + state.tick;
  for (const [id,key] of [['total-events','totalEvents'],['attack-events','attackEvents'],['blocked-events','blockedEvents'],['open-findings','openFindings']]) $(id).textContent = state.metrics[key].toLocaleString();
  $('agents').innerHTML = ['attacker','searcher','builder'].map((key,i) => {
    const agent = state.agents[key];
    return `<div class="agent ${key}"><div class="agent-symbol" aria-hidden="true">${['↗','◎','◇'][i]}</div><div><div class="agent-heading"><h3>${key[0].toUpperCase()+key.slice(1)}</h3><span class="agent-status">${escape(agent.status)}</span></div><p>${escape(agent.detail)}</p></div></div>`;
  }).join('');
  renderFindings(); renderEvents(); renderControls(); inspectResource();
}

function renderFindings() {
  $('finding-count').textContent = state.findings.length;
  const markup = state.findings.map(f => {
    const r = state.recommendations.find(rec=>rec.id === f.recommendationId);
    const evidence = f.evidenceDetails || f.evidence.map(id=>state.events.find(e=>e.id===id)).filter(Boolean);
    return `<article class="finding ${escape(f.status)}"><div class="finding-top"><span>${escape(f.severity)}</span><span>${f.status === 'resolved' ? 'POLICY APPLIED' : 'OPEN FINDING'}</span></div><h4>${escape(f.title)}</h4><details><summary>${f.evidence.length} evidence event${f.evidence.length===1?'':'s'}</summary>${evidence.map(e=>`<p><span class="evidence">${escape(e.id)}</span> · ${escape(e.action)} → ${escape(e.outcome)}<br>${escape(e.detail)}</p>`).join('')}</details>${r ? `<p><strong>Builder: ${escape(r.title)}</strong></p><p>${escape(r.description)}</p><details><summary>Review tradeoff</summary><p>${escape(r.tradeoff)}</p></details>${r.applied ? `<p class="validation">${r.validation==='blocked-replay' ? '✓ Verified: replay blocked by the new policy.' : 'Policy applied. Run the same scenario to verify it.'}</p>` : `<button data-recommendation="${escape(r.id)}">Approve & apply in lab</button>`}` : ''}</article>`;
  }).join('') || '<div class="empty-state">No findings yet.<br><span>Launch a scenario to begin the investigation.</span></div>';
  // Preserve expanded evidence and focus when unrelated traffic arrives.
  if (markup !== lastFindingMarkup) { $('findings').innerHTML = markup; lastFindingMarkup = markup; }
}

function renderEvents() {
  const events = state.events.filter(e => filter === 'all' || (filter === 'security' ? e.kind !== 'normal' : e.kind === 'normal')).slice(0,24);
  const label = id => state.nodes.find(n=>n.id===id)?.label || id;
  $('events').innerHTML = events.map(e => `<tr><td>${escape(e.tick)}</td><td>${escape(label(e.source))} <span class="muted">→</span> ${escape(label(e.target))}</td><td>${escape(e.action)}</td><td>${escape(e.protocol)}</td><td><span class="event-kind ${escape(e.kind)}">${escape(e.outcome)}</span></td></tr>`).join('') || '<tr><td colspan="5">No matching events yet.</td></tr>';
}

function inspectResource() {
  const node = state?.nodes.find(n=>n.id===selected);
  if (!node) { $('resource-detail').textContent = 'Select a resource on the map to inspect its role.'; return; }
  const count = state.findings.filter(f=>f.nodeId === node.id && f.status === 'open').length;
  $('resource-detail').textContent = `${node.description} ${count ? `${count} open finding${count===1?'':'s'}.` : 'No open findings for this resource.'}`;
}
$('pause').addEventListener('click',()=>command('running',{running:!state.running}, state.running?'Simulation paused.':'Simulation resumed.'));
$('reset').addEventListener('click',()=>command('reset',{},'Lab reset. All policies, findings, and counters returned to the vulnerable baseline.'));
$('scenarios').addEventListener('click',event=>{
  const button = event.target.closest('[data-scenario]');
  if (button) command('scenario',{id:button.dataset.scenario}, state.running?'Scenario started. Follow the event stream and Searcher findings.':'Scenario queued. Resume the simulation to run it.');
});
$('findings').addEventListener('click',event=>{
  const button = event.target.closest('[data-recommendation]');
  if (button) command('recommendation',{id:button.dataset.recommendation},'Policy applied to the virtual cloud. Replay that scenario to verify the fix.');
});
$('event-filter').addEventListener('change',event=>{filter=event.target.value; if(state) renderEvents();});
$('resource').addEventListener('change',event=>{selected=event.target.value;inspectResource();});

// A dependency-free perspective renderer: nodes have real 3D coordinates,
// rotated in camera space and depth-sorted before being projected to Canvas 2D.
// This keeps the demo fully offline while supporting orbit, zoom and selection.
const canvas = $('topology'), ctx = canvas.getContext('2d');
let width=600,height=400,yaw=-.42,pitch=.56,zoom=1,hitNodes=[];
const colors={normal:'#76e7c1',attack:'#ff7e8b',blocked:'#f4c373'};
new ResizeObserver(entries=>{
  const rect=entries[0].contentRect; width=rect.width; height=rect.height;
  const dpr=Math.min(devicePixelRatio || 1,2);
  canvas.width=width*dpr; canvas.height=height*dpr;
  ctx.setTransform(dpr,0,0,dpr,0,0);
}).observe(canvas);

function project(x,y,z) {
  const rx=x*Math.cos(yaw)-z*Math.sin(yaw), rz=x*Math.sin(yaw)+z*Math.cos(yaw);
  const ry=y*Math.cos(pitch)-rz*Math.sin(pitch), depth=y*Math.sin(pitch)+rz*Math.cos(pitch);
  const scale=Math.min(width/11.8,height/8.5)*zoom*15/(15+depth);
  return {x:width*.5+rx*scale,y:height*.51-ry*scale,scale,depth};
}
function line(a,b,color,lineWidth=1,dash=[]) {
  ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.strokeStyle=color;ctx.lineWidth=lineWidth;ctx.setLineDash(dash);ctx.stroke();ctx.setLineDash([]);
}
function plane(x1,z1,x2,z2,y,color,stroke) {
  const points=[[x1,y,z1],[x2,y,z1],[x2,y,z2],[x1,y,z2]].map(p=>project(...p));
  ctx.beginPath();points.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.closePath();ctx.fillStyle=color;ctx.fill();ctx.strokeStyle=stroke;ctx.lineWidth=1;ctx.stroke();
}
function render(now) {
  ctx.clearRect(0,0,width,height);
  // The grid and VPC floor are spatial context, not additional network resources.
  for(let i=-6;i<=6;i++) {
    line(project(i,-.65,-5),project(i,-.65,5),'#1c2a3b');
    line(project(-6,-.65,i),project(6,-.65,i),'#1c2a3b');
  }
  plane(-2.5,-3.8,4.9,3.8,-.6,'#17344b2b','#345571');
  if(state) {
    const nodes=new Map(state.nodes.map(n=>[n.id,n]));
    for(const e of state.edges) {
      const a=nodes.get(e.source),b=nodes.get(e.target);if(!a||!b)continue;
      line(project(a.x,a.y,a.z),project(b.x,b.y,b.z), e.target==='logs'?'#35465c':'#416078',1,e.target==='logs'?[3,5]:[]);
    }
    // Event paths are rendered even when not permanent topology edges (e.g. exposure).
    const active=particles.filter(p=>now-p.start<p.duration);
    particles=active;
    for(const p of active) {
      const a=nodes.get(p.event.source),b=nodes.get(p.event.target);if(!a||!b)continue;
      const t=Math.min((now-p.start)/p.duration,1),color=colors[p.event.kind] || colors.normal;
      const from=project(a.x,a.y,a.z),to=project(b.x,b.y,b.z);
      line(from,to,color+'55',p.event.kind==='normal'?1:2,p.event.kind==='blocked'?[5,4]:[]);
      // Blocked events stop before the target, instead of implying successful entry.
      const travel=p.event.kind==='blocked'?t*.7:t;
      const point=project(a.x+(b.x-a.x)*travel,a.y+(b.y-a.y)*travel+Math.sin(Math.PI*travel)*.3,a.z+(b.z-a.z)*travel);
      ctx.shadowColor=color;ctx.shadowBlur=12;ctx.fillStyle=color;ctx.beginPath();ctx.arc(point.x,point.y,p.event.kind==='normal'?2.5:4,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;
      if(p.event.kind==='blocked'&&t>.8){line({x:point.x-4,y:point.y-4},{x:point.x+4,y:point.y+4},color,2);line({x:point.x+4,y:point.y-4},{x:point.x-4,y:point.y+4},color,2);}
    }
    hitNodes=[];
    const ordered=state.nodes.map(n=>({...n,p:project(n.x,n.y,n.z)})).sort((a,b)=>b.p.depth-a.p.depth);
    for(const n of ordered) drawNode(n);
  }
  requestAnimationFrame(render);
}

function drawNode(n) {
  const p=n.p,size=Math.max(10,Math.min(21,p.scale*.36));
  const finding=state.findings.some(f=>f.nodeId===n.id&&f.status==='open');
  const color=n.id==='attacker'?colors.attack:finding?colors.blocked:n.id==='logs'?'#b49df9':n.id==='client'?'#8fa6c1':colors.normal;
  const ground=project(n.x,-.6,n.z);
  line(ground,p,'#3a536877',1,[2,4]);
  if(selected===n.id){ctx.beginPath();ctx.ellipse(p.x,p.y+size*.4,size*1.7,size,0,0,Math.PI*2);ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.stroke();}
  // Isometric prisms remain legible across orbital angles and small screens.
  const s=size;
  ctx.beginPath();ctx.moveTo(p.x-s,p.y-s*.3);ctx.lineTo(p.x,p.y-s*.85);ctx.lineTo(p.x+s,p.y-s*.3);ctx.lineTo(p.x,p.y+s*.25);ctx.closePath();ctx.fillStyle='#263f53';ctx.fill();ctx.strokeStyle=color;ctx.lineWidth=1;ctx.stroke();
  ctx.beginPath();ctx.moveTo(p.x-s,p.y-s*.3);ctx.lineTo(p.x,p.y+s*.25);ctx.lineTo(p.x,p.y+s);ctx.lineTo(p.x-s,p.y+s*.45);ctx.closePath();ctx.fillStyle='#152736';ctx.fill();ctx.stroke();
  ctx.beginPath();ctx.moveTo(p.x,p.y+s*.25);ctx.lineTo(p.x+s,p.y-s*.3);ctx.lineTo(p.x+s,p.y+s*.45);ctx.lineTo(p.x,p.y+s);ctx.closePath();ctx.fillStyle='#20384b';ctx.fill();ctx.stroke();
  ctx.fillStyle=color;ctx.fillRect(p.x+s*.2,p.y+s*.37,s*.48,2);
  ctx.textAlign='center';ctx.font='11px Segoe UI, sans-serif';
  const textWidth=ctx.measureText(n.label).width;
  // Offset the raised collector's label so it does not cover the data tier below.
  const labelX=n.id==='logs'?p.x+s+textWidth/2+7:p.x;
  const labelY=n.id==='logs'?p.y-3:p.y+s+19;
  ctx.fillStyle='#0e1825e8';ctx.fillRect(labelX-textWidth/2-5,labelY-12,textWidth+10,17);
  ctx.fillStyle=selected===n.id?color:'#c9d7e7';ctx.fillText(n.label,labelX,labelY);
  if(finding){ctx.beginPath();ctx.arc(p.x+s,p.y-s*.7,5,0,Math.PI*2);ctx.fillStyle=colors.blocked;ctx.fill();ctx.fillStyle='#101925';ctx.font='bold 9px Segoe UI';ctx.fillText('!',p.x+s,p.y-s*.7+3);}
  hitNodes.push({id:n.id,x:p.x,y:p.y,r:s+12});
}
let drag;
canvas.addEventListener('pointerdown',event=>{drag={x:event.clientX,y:event.clientY,startX:event.clientX,startY:event.clientY};canvas.setPointerCapture(event.pointerId);});
canvas.addEventListener('pointermove',event=>{
  if(!drag)return;
  yaw+=(event.clientX-drag.x)*.006;pitch=Math.max(.15,Math.min(1.1,pitch+(event.clientY-drag.y)*.005));
  drag.x=event.clientX;drag.y=event.clientY;
});
canvas.addEventListener('pointerup',event=>{
  if(drag&&Math.hypot(event.clientX-drag.startX,event.clientY-drag.startY)<6){
    const rect=canvas.getBoundingClientRect(),x=event.clientX-rect.left,y=event.clientY-rect.top;
    const hit=[...hitNodes].reverse().find(n=>Math.hypot(x-n.x,y-n.y)<n.r);
    if(hit){selected=hit.id;$('resource').value=selected;inspectResource();}
  }drag=null;
});
canvas.addEventListener('pointercancel',()=>{drag=null;});
canvas.addEventListener('wheel',event=>{event.preventDefault();zoom=Math.max(.65,Math.min(1.65,zoom-event.deltaY*.001));},{passive:false});
$('home-view').addEventListener('click',()=>{yaw=-.42;pitch=.56;zoom=1;});
requestAnimationFrame(render);
poll();
