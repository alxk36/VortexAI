// The browser renders server-owned state and requests named, bounded lab operations.
import {projectPoint, screenToPlane, clampTranslation, sanitizeLayout, orbitCamera, nodesInRect} from './grid-math.mjs';
const $ = (id) => document.getElementById(id);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let state, busy = false, filter = 'all', selected = '', lastTick = -1, commandVersion = 0;
let seenEvents = new Set(), particles = [], lastFindingMarkup = '';
let selectedNodes = new Set(), layout = {}, lastMode = '', lastAgentsMarkup = '', lastAiMarkup = '', lastHistoryMarkup = '', lastTrafficMarkup = '', lastTrafficConfig = '', dialogNode = '';
const layoutKey = mode => `vortexai.node-layout.v2.${mode || 'simulation'}`;
const mode = () => state?.runtime?.mode || 'simulation';
const serviceNodeIds = new Set(['gateway','lb','app','storage','iam','db']);
const canEditControls = id => mode()==='simulation' || serviceNodeIds.has(id);
function visualNode(node) { return {...node, ...layout[node.id]}; }
function saveLayout() {
  try { localStorage.setItem(layoutKey(mode()), JSON.stringify(layout)); }
  catch { $('message').textContent = 'The layout changed, but browser storage is unavailable. It will reset on refresh.'; }
}
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
  try { update(await request(path, body)); $('message').textContent = message; return true; }
  catch (error) { $('message').textContent = error.message; return false; }
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
  if (mode() === 'lab') $('pause').textContent = state?.running ? 'Pause lab traffic' : 'Resume lab traffic';
  $('environment-mode').disabled = busy || Boolean(state?.activeScenario);
  $('environment-mode').value = mode();
  $('edit-node').disabled = !selected || busy;
  document.querySelectorAll('[data-ai]').forEach(button => { button.disabled = busy || Boolean(state?.activeScenario); });
  const trafficLocked = busy || !state || mode() !== 'simulation' || Boolean(state?.activeScenario);
  $('traffic-apply').disabled = trafficLocked;
  $('bots-reveal').disabled = trafficLocked || !state?.traffic?.botsEnabled;
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
  const nextMode = next.runtime?.mode || 'simulation';
  const changedMode = nextMode !== lastMode;
  const reset = changedMode || next.tick < lastTick || (next.metrics.totalEvents === 0 && state?.metrics.totalEvents > 0);
  if (reset) { seenEvents.clear(); particles = []; }
  if (changedMode) cancelDrag();
  state = next;
  if (first || changedMode) {
    try { layout = sanitizeLayout(JSON.parse(localStorage.getItem(layoutKey(nextMode)) || '{}'), state.nodes.map(n=>n.id)); }
    catch { layout = {}; }
    lastMode = nextMode;
    $('scenarios').innerHTML = state.scenarios.map((s,i) => `<article class="scenario"><span class="scenario-number">SCENARIO / 0${i+1}</span><h3>${escape(s.name)}</h3><p>${escape(s.description)}</p><button data-scenario="${escape(s.id)}">${nextMode==='lab'?'Run lab scenario':'Run simulation'} <span aria-hidden="true">↗</span></button></article>`).join('');
    $('resource').innerHTML = '<option value="">Select a node…</option>' + state.nodes.map(n => `<option value="${escape(n.id)}">${escape(n.label)}</option>`).join('');
    if (!state.nodes.some(n=>n.id===selected)) { selected=''; selectedNodes.clear(); }
    $('resource').value=selected;
    if ($('node-dialog').open) $('node-dialog').close();
  }
  if (!first && !reset && !reducedMotion) {
    for (const event of state.events) {
      if (!seenEvents.has(event.id)) particles.push({event,start:performance.now(),duration:1400});
    }
  }
  seenEvents = new Set(state.events.map(e=>e.id));
  particles = particles.slice(-80);
  lastTick = state.tick;
  $('live-label').textContent = state.running ? 'LIVE · TICK ' + state.tick : 'PAUSED · TICK ' + state.tick;
  $('environment-badge').textContent = nextMode==='lab'?'Isolated service lab':'Local simulation';
  $('runtime-detail').textContent = state.runtime?.detail || 'In-memory simulation ready.';
  $('environment-label').textContent = nextMode==='lab'?'CONTAINER SERVICE LAB':'SIMULATED ENVIRONMENT';
  $('environment-notice').textContent = nextMode==='lab'?'Real service requests inside the configured lab · Only predefined scenarios and targets':'Synthetic events only · No cloud account · No real attack traffic';
  $('event-note').textContent = `Latest 24 matching events · ${nextMode==='lab'?'Measured service outcomes inside the lab':'Synthetic data-plane and identity audit events'} · Animation follows event records`;
  $('event-count-label').textContent = nextMode==='lab'?'Events observed':'Events generated';
  $('reset-note').textContent = nextMode==='lab'?'Reset restores the disposable services to their vulnerable baseline. All browser tabs share the lab state.':'Reset restores the in-memory model to its vulnerable baseline. All browser tabs share the simulation state.';
  $('ai-detail').textContent = state.ai?.detail || 'Models are not configured. Agent decisions use the explicit fallback.';
  for (const [id,key] of [['total-events','totalEvents'],['attack-events','attackEvents'],['blocked-events','blockedEvents'],['open-findings','openFindings']]) $(id).textContent = state.metrics[key].toLocaleString();
  const agentsMarkup = ['attacker','searcher','builder'].map((key,i) => {
    const agent = state.agents[key];
    return `<div class="agent ${key}"><div class="agent-symbol" aria-hidden="true">${['↗','◎','◇'][i]}</div><div><div class="agent-heading"><h3>${key[0].toUpperCase()+key.slice(1)}</h3><span class="agent-status">${escape(agent.status)}</span></div><p>${escape(agent.detail)}</p><button class="compact agent-run" data-ai="${key}">${['Plan & run scenario','Analyze observations','Propose improvements'][i]}</button></div></div>`;
  }).join('');
  if(agentsMarkup!==lastAgentsMarkup){$('agents').innerHTML=agentsMarkup;lastAgentsMarkup=agentsMarkup;}
  const aiMarkup=(state.ai?.runs || []).slice(0,3).map(run=>`<article class="ai-run"><div><strong>${escape(run.agent)}</strong><span class="small-tag">${run.mode==='model'?'MODEL':run.mode==='error'?'ERROR':'FALLBACK'}</span></div><p>${escape(run.summary)}</p>${(run.plan||[]).length?`<p class="origin-list"><span class="origin-tag external">AI chain</span>${run.plan.map(step=>`<span class="evidence">${escape(step)}</span>`).join(' → ')}</p>`:''}${(run.suspects||[]).length?`<p class="origin-list"><span class="origin-tag external">Suspects</span>${run.suspects.map(s=>`<span class="evidence">${escape(s)}</span>`).join(' ')}</p>`:''}${(run.labels||[]).length?`<p class="origin-list">${run.labels.map(l=>`${originTag(l.origin)}<span class="evidence">${escape(l.id)}</span>`).join(' ')}</p>`:''}${run.reason?`<p class="muted">${escape(run.reason)}</p>`:''}${run.model?`<small>${escape(run.provider)} · ${escape(run.servedBy&&run.servedBy!==run.model?`${run.servedBy} (fallback after ${run.model} declined)`:run.model)}</small>`:''}</article>`).join('');
  if(aiMarkup!==lastAiMarkup){$('ai-runs').innerHTML=aiMarkup;lastAiMarkup=aiMarkup;}
  const historyMarkup=attackHistoryMarkup(state.attackHistory);
  if(historyMarkup!==lastHistoryMarkup){$('attack-history').innerHTML=historyMarkup;lastHistoryMarkup=historyMarkup;}
  renderTraffic();
  renderFindings(); renderEvents(); renderControls(); inspectResource();
}

// Internal vs external comes from the newest AI run that labeled this item:
// the Builder labels recommendations, the Searcher labels evidence events.
const ORIGIN_TEXT = {internal:'Internal · team mistake', external:'External · outside attack'};
const originTag = origin => ORIGIN_TEXT[origin] ? `<span class="origin-tag ${origin}">${ORIGIN_TEXT[origin]}</span>` : '';
function originFor(ids) {
  for (const run of state.ai?.runs || []) {
    const label = (run.labels || []).find(l => ids.includes(l.id));
    if (label) return label.origin;
  }
  return null;
}

// Attack history: how each finished run turned out, newest first, so the
// dashboard shows the Attacker switching paths once a fix blocks one.
const CONTROL_TEXT = {storagePrivate:'private storage', requireMfa:'MFA', databaseLeastPrivilege:'least-privilege database role'};
function attackHistoryMarkup(history) {
  if (!Array.isArray(history) || !history.length) return '';
  const rows = history.slice(0, 6).map(h => {
    const blocked = h.result === 'blocked';
    const by = blocked && Array.isArray(h.blockedBy) && h.blockedBy.length ? ` by ${h.blockedBy.map(c => CONTROL_TEXT[c] || c).join(', ')}` : '';
    return `<li><span class="history-result ${blocked ? 'blocked' : 'succeeded'}">${blocked ? 'Blocked' : 'Got through'}</span> <strong>${escape(h.name || h.scenarioId)}</strong>${escape(by)} <span class="muted">· ${h.source === 'ai' ? 'AI attacker' : 'admin'}</span></li>`;
  }).join('');
  return `<div class="attack-history"><h3>Attack history</h3><ol>${rows}</ol></div>`;
}
// End attack history.

// Live traffic: users online, hidden bots, the Searcher's score and the tripwire log.
const BEHAVIOR_TEXT = {'credential-stuffing':'credential stuffing','storage-scraping':'storage scraping','request-flood':'request flood'};
function botScoreMarkup(score) {
  if (!score) return '';
  const caught = new Set(score.caught || []);
  const rows = (score.bots || []).map(b => `<li><span class="history-result ${caught.has(b.clientId) ? 'blocked' : 'succeeded'}">${caught.has(b.clientId) ? 'Caught' : 'Missed'}</span> <span class="evidence">${escape(b.clientId)}</span> ${escape(BEHAVIOR_TEXT[b.behavior] || b.behavior)}</li>`).join('');
  const alarms = (score.falseAlarms || []).length ? `<li><span class="history-result succeeded">False alarm</span> ${score.falseAlarms.map(id => `<span class="evidence">${escape(id)}</span>`).join(' ')}</li>` : '';
  const headline = score.searcherRunAt
    ? `Searcher caught ${caught.size} of ${(score.bots || []).length} hidden bot${(score.bots || []).length === 1 ? '' : 's'}${(score.falseAlarms || []).length ? `, ${score.falseAlarms.length} false alarm${score.falseAlarms.length === 1 ? '' : 's'}` : ''}${score.searcherMode === 'model' ? ' (AI)' : ' (rule fallback)'}.`
    : 'Run the Searcher before revealing to get a score.';
  return `<div class="attack-history"><h3>${escape(headline)}</h3><ol>${rows}${alarms}</ol></div>`;
}
function autoBlocksMarkup(traffic) {
  const active = new Set((traffic?.blocked || []).map(b => b.clientId));
  const rows = (traffic?.autoBlocks || []).slice(0, 4).map(b => `<li><span class="history-result ${active.has(b.clientId) ? 'succeeded' : 'blocked'}">${active.has(b.clientId) ? 'Blocked' : 'Lifted'}</span> <span class="evidence">${escape(b.clientId)}</span> ${escape(b.reason)}${b.count > 1 ? ` · blocked ${escape(b.count)} times` : ''}${active.has(b.clientId) ? ` <button class="compact quiet" data-unblock="${escape(b.clientId)}">Unblock</button>` : ''}</li>`).join('');
  return rows ? `<div class="attack-history"><h3>Searcher tripwire</h3><ol>${rows}</ol></div>` : '';
}
function overloadMarkup(traffic, running) {
  const latest = (traffic?.overloads || [])[0];
  if (!latest) return '';
  return running
    ? `<div class="attack-history"><h3>Last overload at tick ${escape(latest.tick)}</h3><p class="muted small">${escape(latest.reason)}</p></div>`
    : `<div class="attack-history overload"><h3>System overloaded at tick ${escape(latest.tick)}: simulation paused</h3><p class="small">${escape(latest.reason)}. The gateway's capacity protects the services behind it. Press Resume to continue.</p></div>`;
}
// End live traffic.
function renderTraffic() {
  const traffic = state.traffic;
  if (!traffic) return;
  const config = `${traffic.users}:${traffic.botsEnabled}`;
  if (config !== lastTrafficConfig) { $('traffic-users').value = traffic.users; $('traffic-bots').checked = traffic.botsEnabled; lastTrafficConfig = config; }
  const status = mode() !== 'simulation' ? 'Users and hidden bots run in the in-memory simulation.'
    : `${traffic.users} user${traffic.users === 1 ? '' : 's'} online · ${traffic.botsEnabled ? (traffic.revealed ? `${traffic.revealed.bots.length} bot${traffic.revealed.bots.length === 1 ? '' : 's'} revealed` : 'bots hidden among them') : 'no bots'} · ${traffic.clients.length} active client${traffic.clients.length === 1 ? '' : 's'}`;
  const markup = `${botScoreMarkup(state.botScore)}${overloadMarkup(traffic, state.running)}${autoBlocksMarkup(traffic)}`;
  $('traffic-status').textContent = status;
  if (markup !== lastTrafficMarkup) { const [score, blocks] = [botScoreMarkup(state.botScore), overloadMarkup(traffic, state.running) + autoBlocksMarkup(traffic)]; $('bot-score').innerHTML = score; $('auto-blocks').innerHTML = blocks; lastTrafficMarkup = markup; }
}

function renderFindings() {
  $('finding-count').textContent = state.findings.length;
  const markup = state.findings.map(f => {
    const r = state.recommendations.find(rec=>rec.id === f.recommendationId);
    const evidence = f.evidenceDetails || f.evidence.map(id=>state.events.find(e=>e.id===id)).filter(Boolean);
    return `<article class="finding ${escape(f.status)}"><div class="finding-top"><span>${escape(f.severity)}</span><span>${f.status === 'resolved' ? 'POLICY APPLIED' : 'OPEN FINDING'}</span></div><h4>${escape(f.title)}</h4>${originTag(originFor([f.recommendationId, ...f.evidence]))}<details><summary>${f.evidence.length} evidence event${f.evidence.length===1?'':'s'}</summary>${evidence.map(e=>`<p><span class="evidence">${escape(e.id)}</span> · ${escape(e.action)} → ${escape(e.outcome)}<br>${escape(e.detail)}</p>`).join('')}</details>${r ? `<p><strong>Builder: ${escape(r.title)}</strong></p><p>${escape(r.description)}</p><details><summary>Review tradeoff</summary><p>${escape(r.tradeoff)}</p></details>${r.applied ? `<p class="validation">${r.validation==='blocked-replay' ? '✓ Verified: replay blocked by the new policy.' : 'Policy applied. Run the same scenario to verify it.'}</p>` : `<button data-recommendation="${escape(r.id)}">Approve & apply in lab</button>`}` : ''}</article>`;
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
  $('edit-node').disabled=!node || busy;
  $('selection-hint').textContent = selectedNodes.size ? `${selectedNodes.size} SELECTED · CTRL-DRAG TO MOVE · RIGHT-CLICK FOR OPTIONS` : '360° ORBIT · CTRL TO SELECT / MOVE · ALT-DRAG TO BOX SELECT';
  if (!node) { $('resource-detail').textContent = 'Ctrl-click a resource, or hold Alt and drag a box around several nodes.'; return; }
  const count = state.findings.filter(f=>f.nodeId === node.id && f.status === 'open').length;
  $('resource-detail').textContent = `${node.description} ${count ? `${count} open finding${count===1?'':'s'}.` : 'No open findings for this resource.'} ${canEditControls(node.id)?`Status: ${node.status || 'active'} · Action: ${node.action || 'normal'}.`:''}`;
}
$('pause').addEventListener('click',()=>command('running',{running:!state.running}, state.running?'Traffic generation paused.':'Traffic generation resumed.'));
$('reset').addEventListener('click',()=>command('reset',{},'Lab reset and paused. All policies, findings, and counters returned to the vulnerable baseline. Press Resume to start traffic.'));
$('traffic-apply').addEventListener('click',()=>{
  const users=Number($('traffic-users').value), bots=$('traffic-bots').checked;
  command('traffic',{users,bots},`Traffic set: ${users} user${users===1?'':'s'} online${bots?', with hidden bots among them. Run the Searcher, then reveal.':'.'}`);
});
$('bots-reveal').addEventListener('click',()=>command('bots/reveal',{},'Hidden bots revealed. The score compares them with the newest Searcher run.'));
$('auto-blocks').addEventListener('click',event=>{
  const button=event.target.closest('[data-unblock]');
  if(button) command('unblock',{clientId:button.dataset.unblock},`Admin lifted the tripwire block on ${button.dataset.unblock}.`);
});
$('scenarios').addEventListener('click',event=>{
  const button = event.target.closest('[data-scenario]');
  if (button) command('scenario',{id:button.dataset.scenario}, state.running?'Scenario requested. Review its observed events and findings.':'Scenario queued. Resume traffic to run it.');
});
$('findings').addEventListener('click',event=>{
  const button = event.target.closest('[data-recommendation]');
  if (button) command('recommendation',{id:button.dataset.recommendation},'Policy applied to the selected environment. Replay that scenario to verify the fix.');
});
$('event-filter').addEventListener('change',event=>{filter=event.target.value; if(state) renderEvents();});
$('resource').addEventListener('change',event=>{selected=event.target.value;selectedNodes=new Set(selected?[selected]:[]);inspectResource();});
$('environment-mode').addEventListener('change',event=>command('mode',{mode:event.target.value},'Environment changed. The map now shows this environment’s observations.'));
$('agents').addEventListener('click',event=>{
  const button=event.target.closest('[data-ai]');
  if(button) command('ai/run',{agent:button.dataset.ai},'Agent run finished. Review its result and whether a model or fallback was used.');
});

// Resource inspector: its membership and edits are captured independently of live selection.
let nodeEditor = null;
function commonNodeValue(nodes,field,fallback) {
  const values=new Set(nodes.map(node=>node[field] || fallback));
  return values.size===1?[...values][0]:'';
}
function lockNodeEditor(editor,saving) {
  $('node-status').disabled=saving||!editor.editable;
  $('node-action').disabled=saving||!editor.editable;
  $('node-x').disabled=saving||editor.group;
  $('node-z').disabled=saving||editor.group;
  $('close-node').disabled=saving;
  $('save-node').disabled=saving||(editor.group&&!editor.editable);
  $('save-node').textContent=saving?'Applying changes…':editor.group?`Apply to ${editor.ids.length} nodes`:'Save changes';
}
function openNode(id) {
  if(busy||nodeEditor?.saving)return;
  const node=state.nodes.find(n=>n.id===id);if(!node)return;
  // Context-clicking an existing member edits that group. A different node starts a new selection.
  if(!selectedNodes.has(id))selectedNodes=new Set([id]);
  const nodes=state.nodes.filter(n=>selectedNodes.has(n.id));
  selected=id;$('resource').value=id;inspectResource();dialogNode=id;
  const group=nodes.length>1,editable=nodes.every(n=>canEditControls(n.id));
  nodeEditor={ids:nodes.map(n=>n.id),mode:mode(),group,editable,saving:false,dirty:{status:false,action:false}};
  $('node-dialog-title').textContent=group?`${nodes.length} selected resources`:node.label;
  $('node-description').textContent=group?'Edit options shared by the selected resources. Only fields you explicitly change are applied.':node.description;
  $('node-members').textContent=group?nodes.map(n=>`${n.label} (${n.id})`).join(' · '):'';
  $('node-members').hidden=!group;
  const facts=group?[['Selection',`${nodes.length} resources`],['Open findings',state.findings.filter(f=>nodeEditor.ids.includes(f.nodeId)&&f.status==='open').length]]:[['Resource ID',node.id],['Type / zone',`${node.type} / ${node.zone}`],['Height',`${node.y.toFixed(2)} (fixed)`],['Open findings',state.findings.filter(f=>f.nodeId===id&&f.status==='open').length]];
  $('node-facts').replaceChildren();
  for(const [label,value] of facts){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value);$('node-facts').append(dt,dd);}
  for(const [field,fallback] of [['status','active'],['action','normal']]){
    const control=$(`node-${field}`),common=commonNodeValue(nodes,field,fallback);
    control.options[0].textContent=common?'Keep unchanged':'Mixed — keep unchanged';control.value=common;
  }
  $('node-edit-note').textContent=!editable?'This selection includes conceptual view nodes. Operational controls are available only when every selected node supports them.':mode()==='simulation'?'Paused or quarantined nodes stop modeled traffic; restore them before scenario runs. Observe marks traffic for inspection.':'Paused or quarantined services deny ordinary requests while health and control routes remain available. Observe annotates telemetry; containers and network isolation stay unchanged.';
  $('node-position-fields').hidden=group;
  const position=visualNode(node);$('node-x').value=position.x.toFixed(2);$('node-z').value=position.z.toFixed(2);
  $('node-position-note').textContent=group?'Move the group on the grid to change its layout. Shared status/action changes are sent one node at a time; earlier successful changes are not rolled back if a later request fails.':'Position is saved in this browser; height stays fixed. Untouched status/action fields keep their current per-node values.';
  $('node-error').textContent='';lockNodeEditor(nodeEditor,false);
  if(!$('node-dialog').open)$('node-dialog').showModal();
}
$('edit-node').addEventListener('click',()=>openNode(selected));
$('close-node').addEventListener('click',()=>{if(!nodeEditor?.saving)$('node-dialog').close();});
$('node-dialog').addEventListener('cancel',event=>{if(nodeEditor?.saving)event.preventDefault();});
$('node-dialog').addEventListener('click',event=>{
  if(nodeEditor?.saving||event.target!==$('node-dialog'))return;
  const r=event.target.getBoundingClientRect();
  if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)event.target.close();
});
for(const field of ['status','action'])$(`node-${field}`).addEventListener('change',()=>{
  if(nodeEditor&&!nodeEditor.saving)nodeEditor.dirty[field]=$(`node-${field}`).value!=='';
});
$('node-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const editor=nodeEditor;
  if(!editor||editor.saving)return;
  if(busy){$('node-error').textContent='Wait for the current operation to finish.';return;}
  if(mode()!==editor.mode){$('node-error').textContent='The environment changed. Reopen the resource inspector.';return;}
  const x=Number($('node-x').value),z=Number($('node-z').value);
  if(!editor.group&&(!Number.isFinite(x)||!Number.isFinite(z)||Math.abs(x)>6||Math.abs(z)>6)){$('node-error').textContent='Choose coordinates between -6 and 6.';return;}
  const changes={};
  if(editor.editable)for(const field of ['status','action'])if(editor.dirty[field]&&$(`node-${field}`).value)changes[field]=$(`node-${field}`).value;
  // One busy/version span prevents stale polling between sequential updates. The
  // endpoint accepts full settings, so read each node before merging chosen fields.
  editor.saving=true;busy=true;commandVersion++;lockNodeEditor(editor,true);renderControls();
  let applied=0,unchanged=0,currentId='',submitted=false;
  try {
    if(Object.keys(changes).length)for(const id of editor.ids){
      currentId=id;submitted=false;
      const current=await request('state');
      if((current.runtime?.mode||'simulation')!==editor.mode)throw new Error('The shared environment changed; further updates were stopped.');
      update(current);
      const node=current.nodes.find(n=>n.id===id);
      if(!node)throw new Error('A selected resource is no longer present.');
      const patch={id,status:changes.status??node.status??'active',action:changes.action??node.action??'normal'};
      if(patch.status===(node.status||'active')&&patch.action===(node.action||'normal')){unchanged++;continue;}
      submitted=true;
      const result=await request('node',patch);
      if((result.runtime?.mode||'simulation')!==editor.mode)throw new Error('The shared environment changed during this request; verify its resulting state.');
      update(result);applied++;submitted=false;
    }
    if(!editor.group){layout[editor.ids[0]]={x,z};saveLayout();}
    $('message').textContent=Object.keys(changes).length?`Updated ${applied} of ${editor.ids.length} selected resources${unchanged?`; ${unchanged} already had the requested values`:''}. Untouched fields were preserved.`:editor.group?'No shared options were changed.':'Node position saved. Operational settings were unchanged.';
    $('node-dialog').close();
  } catch(error) {
    const detail=`${applied} of ${editor.ids.length} updates confirmed${unchanged?`; ${unchanged} already matched`:''}. Stopped at ${currentId||'the selection'}. ${error.message}${submitted?' The last request may have reached the server; inspect its current state before retrying.':''} Earlier successful changes remain applied.`;
    $('node-error').textContent=detail;$('message').textContent=detail;
  } finally {editor.saving=false;busy=false;lockNodeEditor(editor,false);renderControls();inspectResource();}
});

// A dependency-free perspective renderer: nodes have real 3D coordinates,
// rotated in camera space and depth-sorted before being projected to Canvas 2D.
// This keeps the demo fully offline while supporting orbit, zoom and selection.
const canvas = $('topology'), ctx = canvas.getContext('2d');
let width=600,height=400,yaw=-.42,pitch=.56,zoom=1,panX=0,panY=0,hitNodes=[];
const camera=()=>({width,height,yaw,pitch,zoom,panX,panY});
const colors={normal:'#76e7c1',attack:'#ff7e8b',blocked:'#f4c373'};
new ResizeObserver(entries=>{
  const rect=entries[0].contentRect; width=rect.width; height=rect.height;
  const dpr=Math.min(devicePixelRatio || 1,2);
  canvas.width=width*dpr; canvas.height=height*dpr;
  ctx.setTransform(dpr,0,0,dpr,0,0);
}).observe(canvas);

function project(x,y,z) {
  return projectPoint({x,y,z},camera());
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
    const nodes=new Map(state.nodes.map(n=>[n.id,visualNode(n)]));
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
    const ordered=[...nodes.values()].map(n=>({...n,p:project(n.x,n.y,n.z)})).sort((a,b)=>b.p.depth-a.p.depth);
    for(const n of ordered) drawNode(n);
  }
  if(drag?.mode==='marquee') {
    const {start,end}=drag;
    ctx.save();
    ctx.fillStyle='#76e7c11a';ctx.strokeStyle=colors.normal;ctx.lineWidth=1.5;ctx.setLineDash([5,3]);
    ctx.fillRect(start.x,start.y,end.x-start.x,end.y-start.y);
    ctx.strokeRect(start.x,start.y,end.x-start.x,end.y-start.y);
    ctx.restore();
  }
  requestAnimationFrame(render);
}

function drawNode(n) {
  const p=n.p,size=Math.max(10,Math.min(21,p.scale*.36));
  const finding=state.findings.some(f=>f.nodeId===n.id&&f.status==='open');
  const color=n.action==='quarantine'?colors.attack:n.status==='paused'?'#8290a5':n.action==='observe'?'#72a9fa':n.id==='attacker'?colors.attack:finding?colors.blocked:n.id==='logs'?'#b49df9':n.id==='client'?'#8fa6c1':colors.normal;
  const ground=project(n.x,-.6,n.z);
  line(ground,p,'#3a536877',1,[2,4]);
  if(selectedNodes.has(n.id)){ctx.beginPath();ctx.ellipse(p.x,p.y+size*.4,size*1.7,size,0,0,Math.PI*2);ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.stroke();}
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
let drag, ctrlHeld=false, altHeld=false;
function screenPoint(event) { const rect=canvas.getBoundingClientRect();return {x:event.clientX-rect.left,y:event.clientY-rect.top}; }
function hitNode(event) { const p=screenPoint(event);return [...hitNodes].reverse().find(n=>Math.hypot(p.x-n.x,p.y-n.y)<n.r); }
function setSelection(id,toggle=false) {
  if(toggle && selectedNodes.has(id)){selectedNodes.delete(id);selected=[...selectedNodes].at(-1)||'';}
  else{if(!toggle)selectedNodes.clear();if(id)selectedNodes.add(id);selected=id;}
  $('resource').value=selected;inspectResource();
}
function updateCursor(){canvas.classList.toggle('select-mode',(ctrlHeld||altHeld)&&!drag||drag?.mode==='marquee');canvas.classList.toggle('moving-node',drag?.mode==='move'&&drag.moved);canvas.classList.toggle('panning',drag?.mode==='pan');}
// Capture the interaction mode at press time. Releasing Ctrl mid-drag must not
// suddenly orbit the camera, and a right-drag must never open a context menu.
canvas.addEventListener('pointerdown',event=>{
  if(!state || drag || ![0,1,2].includes(event.button))return;
  event.preventDefault();
  ctrlHeld=event.ctrlKey;altHeld=event.altKey;
  const hit=hitNode(event);
  let operation=event.altKey&&event.button===0?'marquee':event.button===2?'context':event.ctrlKey&&event.button===0?'select':event.shiftKey?'pan':'orbit';
  const base={pointerId:event.pointerId,button:event.button,x:event.clientX,y:event.clientY,startX:event.clientX,startY:event.clientY,hit:hit?.id,mode:operation,moved:false,selectionBefore:[...selectedNodes],selectedBefore:selected};
  if(operation==='marquee') {
    const point=screenPoint(event);
    Object.assign(base,{start:point,end:point});
  } else if(event.ctrlKey&&[0,2].includes(event.button)&&hit){
    // Defer selection until drag threshold: a Ctrl-click still toggles membership,
    // while dragging an already-selected node moves the entire selected group.
    const ids=selectedNodes.has(hit.id)?selectedNodes:new Set([hit.id]);
    const node=visualNode(state.nodes.find(n=>n.id===hit.id));
    const point=screenToPlane(screenPoint(event),node.y,camera());
    Object.assign(base,{mode:'move',planeY:node.y,anchor:point,originals:state.nodes.filter(n=>ids.has(n.id)).map(visualNode),camera:camera(),translated:false});
  }
  drag=base;canvas.setPointerCapture(event.pointerId);updateCursor();
});
canvas.addEventListener('pointermove',event=>{
  if(!drag||drag.pointerId!==event.pointerId)return;
  const dx=event.clientX-drag.x,dy=event.clientY-drag.y;
  const wasMoved=drag.moved;
  drag.moved ||= Math.hypot(event.clientX-drag.startX,event.clientY-drag.startY)>4;
  if(drag.mode==='orbit')({yaw,pitch}=orbitCamera(camera(),dx,dy));
  if(drag.mode==='pan'){panX=Math.max(-width,Math.min(width,panX+dx));panY=Math.max(-height,Math.min(height,panY+dy));}
  if(drag.mode==='marquee'&&drag.moved) {
    const point=screenPoint(event);
    drag.end={x:Math.max(0,Math.min(width,point.x)),y:Math.max(0,Math.min(height,point.y))};
    selectedNodes=new Set(nodesInRect(hitNodes,drag.start,drag.end));
    selected=selectedNodes.has(drag.selectedBefore)?drag.selectedBefore:[...selectedNodes].at(-1)||'';
    $('resource').value=selected;inspectResource();
  }
  if(drag.mode==='move'&&drag.moved){
    if(!wasMoved){selectedNodes=new Set(drag.originals.map(n=>n.id));selected=drag.hit;$('resource').value=selected;inspectResource();}
    const point=screenToPlane(screenPoint(event),drag.planeY,drag.camera);
    if(point&&drag.anchor){const delta=clampTranslation(drag.originals,point.x-drag.anchor.x,point.z-drag.anchor.z);for(const n of drag.originals)layout[n.id]={x:n.x+delta.dx,z:n.z+delta.dz};drag.translated=true;}
  }
  drag.x=event.clientX;drag.y=event.clientY;updateCursor();
});
canvas.addEventListener('pointerup',event=>{
  if(!drag||drag.pointerId!==event.pointerId)return;
  const finished=drag;drag=null;updateCursor();
  if(canvas.hasPointerCapture(event.pointerId))canvas.releasePointerCapture(event.pointerId);
  if(finished.mode==='move'){
    if(!finished.moved){if(finished.button===0)setSelection(finished.hit,true);else openNode(finished.hit);}
    else if(finished.translated){saveLayout();inspectResource();$('message').textContent=`Moved ${finished.originals.length} node${finished.originals.length===1?'':'s'} on the horizontal plane. Service connections are unchanged.`;}
    else $('message').textContent='The platform is edge-on here. Orbit slightly to move nodes along its plane.';
  }else if(finished.mode==='marquee'){
    if(!finished.moved)setSelection('');
    $('message').textContent=`${selectedNodes.size} node${selectedNodes.size===1?'':'s'} selected. Ctrl-drag a selected node to move the group; right-click it for shared options.`;
  }else if(!finished.moved&&finished.mode==='select'){
    if(finished.hit)setSelection(finished.hit,true);else setSelection('');
  }else if(!finished.moved&&finished.mode==='context'&&finished.hit)openNode(finished.hit);
});
// All context menu behavior on the map is owned by the resource inspector.
canvas.addEventListener('contextmenu',event=>event.preventDefault());
function cancelDrag(){
  if(!drag)return;
  const cancelled=drag;drag=null;
  if(cancelled.mode==='move')for(const n of cancelled.originals)layout[n.id]={x:n.x,z:n.z};
  if(['move','marquee'].includes(cancelled.mode)){selectedNodes=new Set(cancelled.selectionBefore);selected=cancelled.selectedBefore;$('resource').value=selected;inspectResource();}
  if(canvas.hasPointerCapture(cancelled.pointerId))canvas.releasePointerCapture(cancelled.pointerId);
  updateCursor();
}
canvas.addEventListener('pointercancel',cancelDrag);
canvas.addEventListener('lostpointercapture',cancelDrag);
window.addEventListener('blur',()=>{ctrlHeld=false;altHeld=false;cancelDrag();updateCursor();});
window.addEventListener('keydown',event=>{if(event.key==='Control')ctrlHeld=true;if(event.key==='Alt'){altHeld=true;if(drag)event.preventDefault();}if(event.key==='Escape'&&drag)cancelDrag();updateCursor();});
window.addEventListener('keyup',event=>{if(event.key==='Control')ctrlHeld=false;if(event.key==='Alt')altHeld=false;updateCursor();});
canvas.addEventListener('wheel',event=>{event.preventDefault();zoom=Math.max(.65,Math.min(1.65,zoom-event.deltaY*.001));},{passive:false});
$('home-view').addEventListener('click',()=>{yaw=-.42;pitch=.56;zoom=1;panX=0;panY=0;});
$('reset-layout').addEventListener('click',()=>{layout={};saveLayout();$('message').textContent='Node positions restored. Camera and service policies are unchanged.';});
requestAnimationFrame(render);
poll();
