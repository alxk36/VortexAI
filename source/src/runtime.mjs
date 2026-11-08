/** Coordinate browser commands without letting the UI or AI own security state.
 * Simulation is local; lab mode ingests executor observations into the same
 * detectors. Operation locks keep asynchronous reads from undoing newer writes.
 */
import { Simulation } from './simulation.mjs';
import { prepareContext, runAgent, validateDecision, servedModel, DEFAULT_MODEL } from '../ai/agents.mjs';
import { performanceReport, controlText } from './performance.mjs';
import { Hacker } from './hacker.mjs';
import { streams } from './seed.mjs';

const ROLES = ['attacker', 'searcher', 'builder'];
// These addresses are deployment wiring, never input accepted from a browser or model.
const EXECUTOR = 'http://executor:8080';
const ACTION_PATHS = new Set(['/state', '/scenario', '/policy', '/running', '/reset', '/node']);

/** Bounded internal transport; never follow redirects out of the service allowlist. */
async function internalJson(url, token, body, fetchImpl = fetch) {
  const response = await fetchImpl(url, {
    method: body === undefined ? 'GET' : 'POST', redirect: 'error',
    headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000),
  });
  if (!response.body) throw new Error('Internal service returned no body.');
  const reader = response.body.getReader(); const chunks = []; let size = 0;
  for (;;) {
    const {done, value} = await reader.read(); if (done) break;
    size += value.length;
    if (size > 512000) { await reader.cancel(); throw new Error('Internal response exceeds the limit.'); }
    chunks.push(Buffer.from(value));
  }
  const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!response.ok) throw new Error(result.error || `Internal service returned ${response.status}.`);
  return result;
}

/** Coordinates modes and independent workers. It never executes model-generated code. */
export class Runtime {
  constructor({simulation = new Simulation(), container = process.env.VORTEX_CONTAINER === '1', fetchImpl = fetch,
    executorToken = process.env.LAB_EXECUTOR_TOKEN, agentToken = process.env.AGENT_CONTROL_TOKEN, hacker = new Hacker(), seed = null, proof = null} = {}) {
    this.simulation = simulation; this.container = container; this.fetch = fetchImpl; this.seed = seed;
    // Offline measurement from npm run eval:hacker, shown as-is on the dashboard.
    this.proof = proof;
    this.executorToken = executorToken; this.agentToken = agentToken;
    this.mode = 'simulation'; this.real = new Simulation(); this.generation = null;
    this.seen = new Set(); this.realState = null; this.runs = []; this.busy = false; this.syncPromise = null;
    this.attackHistory = []; this.pendingAttack = null; this.botScore = null;
    // Per lab run: applied-fix ledger. Across runs: each agent's learning log.
    this.fixes = []; this.logs = []; this.runNumber = 1; this.seenTraffic = new Set();
    // Across runs: the Hacker's learned values, and the Attacker's earlier results (outsider view).
    this.hacker = hacker; this.hacker.newRun(this.runNumber); this.earlierAttacks = [];
    this.detail = container ? 'Select real services after lab:verify passes.' : 'Start Docker with npm run lab:up to connect real services.';
    this.aiDetail = container ? 'Claude Opus 5.5 connection is checked on each run. Add ANTHROPIC_API_KEY in .env; missing access is labeled fallback.' : 'Agent containers are offline. Explicit rule fallback is available. Add your Anthropic key to .env for the Docker lab.';
  }
  /** Record how a finished attack run turned out, judged only from observed
   * events: a run is blocked when a denied observation names a control. The
   * Attacker later sees only the scenario and result, so it can adapt to fixes.
   */
  recordAttack(scenarioId, source, events, sinceTick, plan) {
    // Background user and bot traffic carries a clientId; only scenario events count here.
    const blockedBy = [...new Set(events.filter(e => e.tick > sinceTick && !e.clientId && e.outcome === 'denied' && e.control).map(e => e.control))];
    const runEvents = events.filter(e => e.tick > sinceTick && !e.clientId && e.kind && e.kind !== 'normal');
    const exploited = [...new Set(runEvents.filter(e => e.outcome === 'allowed' && e.control).map(e => e.control))];
    const touched = [...new Set(runEvents.filter(e => e.control).map(e => e.control))];
    const eventIds = runEvents.map(e => e.id);
    const endTick = Math.max(sinceTick, ...runEvents.map(e => e.tick));
    const name = plan ? `AI chain: ${plan.join(' → ')}` : this.simulation.snapshot().scenarios.find(s => s.id === scenarioId)?.name ?? scenarioId;
    const flagged = eventIds.some(id => this.flaggedIds().has(id));
    const result = blockedBy.length ? 'blocked' : 'succeeded';
    this.attackHistory.unshift({ scenarioId, name, source, result, blockedBy, exploited, touched, eventIds, endTick, flagged, ...(plan ? { plan: [...plan] } : {}), time: new Date().toISOString() });
    this.attackHistory = this.attackHistory.slice(0, 12);
    this.log('attacker', result === 'blocked'
      ? `${name} was blocked by ${blockedBy.map(controlText).join(', ')}; that path is closed.`
      : `${name} got through${exploited.length ? ` (${exploited.map(controlText).join(', ')} open)` : ''}.`);
    // The defense must hold: a breach on a fixed path is a failed fix.
    for (const fix of this.fixes) {
      if (exploited.includes(fix.policyKey) && fix.appliedTick < endTick && fix.failedTick === undefined) {
        fix.failedTick = endTick;
        this.log('builder', `Failed: ${fix.title} did not hold; ${name} got through.`);
      }
    }
    this.refreshFixes();
  }
  /** A finished Hacker attempt: was it noticed, did it break a fix, and what did it learn. */
  recordHack(attempt) {
    const flagged = this.flaggedIds();
    attempt.flagged = attempt.tripped || attempt.eventIds.some(id => flagged.has(id)) || attempt.clientIds.some(id => this.suspects().has(id));
    for (const fix of this.fixes) {
      // Only a step the control let through after the fix counts, not one from before it.
      if (fix.failedTick === undefined && attempt.controlEvents.some(e => e.control === fix.policyKey && e.allowed && e.tick > fix.appliedTick)) {
        fix.failedTick = attempt.endTick;
        this.log('builder', `Failed: ${fix.title} did not hold; the Hacker got through.`);
      }
    }
    for (const lesson of attempt.lessons) this.log('hacker', lesson);
  }
  /** Client addresses any Searcher run has named as suspects. */
  suspects() { return new Set(this.runs.filter(r => r.agent === 'searcher').flatMap(r => r.suspects ?? [])); }
  /** Event IDs the Searcher side has flagged: rule findings, AI citations, blocked-replay checks. */
  flaggedIds() {
    const state = this.mode === 'lab' ? this.real.snapshot() : this.simulation.snapshot();
    return new Set([
      ...state.findings.flatMap(f => f.evidence ?? []),
      ...state.recommendations.map(r => r.validationEvent?.id).filter(Boolean),
      ...this.runs.filter(r => r.agent === 'searcher').flatMap(r => r.evidenceIds ?? []),
    ]);
  }
  /** A fix holds once a replay is blocked by it. */
  refreshFixes() {
    const state = this.mode === 'lab' ? this.real.snapshot() : this.simulation.snapshot();
    for (const fix of this.fixes) {
      if (fix.heldTick !== undefined) continue;
      if (state.recommendations.some(r => r.policyKey === fix.policyKey && r.validation === 'blocked-replay')) {
        fix.heldTick = state.tick;
        this.log('builder', `Held: ${fix.title} blocked the replay.`);
      }
    }
  }
  log(agent, text) {
    const tick = this.mode === 'lab' ? this.realState?.tick ?? 0 : this.simulation.snapshot().tick;
    this.logs.unshift({ agent, run: this.runNumber, tick, text });
    this.logs = this.logs.slice(0, 80);
  }
  /** Searcher-side traffic events worth remembering: tripwire blocks and overloads. */
  logTraffic() {
    const traffic = this.simulation.snapshot().traffic;
    // A burst of blocks (a Hacker rotating addresses, say) becomes one line with a count, not a flood.
    for (const b of [...(traffic?.autoBlocks ?? [])].reverse()) {
      const key = `block:${b.clientId}:${b.tick}`;
      if (this.seenTraffic.has(key)) continue;
      this.seenTraffic.add(key);
      const last = this.logs.find(l => l.agent === 'searcher' && l.run === this.runNumber && l.tripwire);
      if (last && b.tick - last.tick <= 20) {
        last.tripwire += 1;
        last.text = `Tripwire blocked ${last.tripwire} addresses since tick ${last.tick}; latest ${b.clientId}: ${b.reason}.`;
      } else {
        this.log('searcher', `Tripwire blocked ${b.clientId}: ${b.reason}.`);
        this.logs[0].tripwire = 1;
      }
    }
    for (const o of traffic?.overloads ?? []) {
      const key = `overload:${o.tick}`;
      if (!this.seenTraffic.has(key)) { this.seenTraffic.add(key); this.log('searcher', `Overload paused the system: ${o.reason}.`); }
    }
  }
  /** Lab reset or mode switch: numbers start over, learnings carry into the next run. */
  startNewRun() {
    // The Attacker keeps only what an outsider saw: which path, and whether it got through.
    const finished = this.attackHistory.map(h => ({ run: this.runNumber, scenarioId: h.scenarioId, ...(h.plan ? { plan: [...h.plan] } : {}), result: h.result }));
    this.earlierAttacks = [...finished, ...this.earlierAttacks].slice(0, 12);
    this.runNumber += 1; this.fixes = []; this.seenTraffic = new Set();
    this.hacker.newRun(this.runNumber);
  }
  /** Each Claude agent's own lessons from earlier runs, newest first. */
  notesFor(agent) {
    return this.logs.filter(l => l.agent === agent && l.run < this.runNumber).slice(0, 6).map(l => `Run ${l.run}: ${l.text}`);
  }
  /** Simulator runs advance one step per tick; settle once the run has finished. */
  settleAttack() {
    if (!this.pendingAttack) return;
    const state = this.simulation.snapshot();
    if (state.activeScenario) return;
    const { scenarioId, source, startTick, plan } = this.pendingAttack;
    this.pendingAttack = null;
    this.recordAttack(scenarioId, source, state.events, startTick, plan);
  }
  /** Start a scenario in the current mode and track its outcome. */
  async launch(id, source) {
    if (this.mode === 'simulation') {
      const startTick = this.simulation.snapshot().tick;
      this.simulation.runScenario(id);
      this.pendingAttack = { scenarioId: id, source, startTick };
    } else {
      // The lab executor runs the whole chain in one call.
      const startTick = this.realState?.tick ?? 0;
      this.ingest(await this.executor('/scenario', {id}));
      this.recordAttack(id, source, this.realState.events, startTick);
    }
  }
  /** AI-composed chains run only in the in-memory simulator. */
  async launchPlan(actions, source) {
    if (this.mode !== 'simulation') throw new Error('AI-composed attack chains run in the simulator only.');
    const startTick = this.simulation.snapshot().tick;
    this.simulation.runPlan({ actions, name: `AI chain: ${actions.join(' → ')}` });
    this.pendingAttack = { scenarioId: 'custom', source, startTick, plan: [...actions] };
  }
  async executor(path, body) {
    if (!this.container || !this.executorToken) throw new Error('Real services require the verified Docker lab. Run npm run lab:up.');
    if (!ACTION_PATHS.has(path)) throw new Error('Unsupported executor operation.');
    return internalJson(EXECUTOR + path, this.executorToken, body, this.fetch);
  }
  // A new executor generation invalidates old evidence IDs and replay proof.
  // Reuse the detectors, but never generate synthetic traffic for real services.
  ingest(remote) {
    if (!remote || !Array.isArray(remote.events) || !remote.policies) throw new Error('Invalid lab telemetry.');
    if (remote.generation !== this.generation) {
      this.real.reset(); this.seen.clear(); this.generation = remote.generation;
    }
    // Reuse evidence-based detectors, but never call the synthetic traffic clock.
    for (const event of [...remote.events].reverse()) {
      if (!this.seen.has(event.id)) { this.real._tick = event.tick; this.real._emit(event); this.seen.add(event.id); }
    }
    this.seen = new Set(remote.events.map(e=>e.id));
    this.real._tick = remote.tick;
    this.real.running = remote.running;
    this.real._policies = structuredClone(remote.policies);
    this.realState = structuredClone(remote);
    this.detail = remote.containmentVerified ? 'Real HTTP services · containment checks passed · disposable lab data.' : 'Containers reachable; traffic locked until npm run lab:verify succeeds.';
  }
  async sync() {
    // Callers share the in-flight read instead of observing stale state while
    // another caller waits for it. Mutations wait for this read before starting.
    if (this.syncPromise) return this.syncPromise;
    this.syncPromise = (async()=>{
      try { this.ingest(await this.executor('/state')); }
      finally { this.syncPromise = null; }
    })();
    return this.syncPromise;
  }
  // Present one UI contract for both modes, stripping capabilities that the
  // real executor cannot perform (such as model-composed attack chains).
  snapshot() {
    const result = this.mode === 'lab' ? this.real.snapshot() : this.simulation.snapshot();
    if (this.mode === 'lab') {
      result.activeScenario = structuredClone(this.realState?.activeScenario || null);
      if (this.busy && !result.activeScenario) result.activeScenario = {id:'operation',name:'Lab operation',step:0,total:1};
      result.events = structuredClone(this.realState?.events || []);
      result.metrics = {...result.metrics, ...structuredClone(this.realState?.metrics || {})};
      result.nodes = result.nodes.map(node=>({...node,...structuredClone(this.realState?.nodeSettings?.[node.id] || {}),description: node.id==='db' ? 'Real SQLite-backed service in a disposable container. Administrative export is controlled separately from normal reads.' : node.id==='logs' ? 'Collected HTTP observations returned by the real services. No packet capture is claimed.' : `Lab resource: ${node.label}. Real service traffic is observed inside the isolated container network.`}));
      result.scenarios=result.scenarios.map(s=>({...s,description:{'exposed-storage':'Request disposable objects anonymously from the real storage service; private access blocks the replay.','credential-abuse':'Three failed demo sign-ins precede a known lab password. The demonstration second-factor gate blocks the password-only replay.','lateral-movement':'A fixed demo token invokes an intentionally overpowered application export route. Restricting the database role blocks export.'}[s.id]}));
      result.edges = result.edges.map(edge=>({...edge,label:edge.label.replace('HTTPS','HTTP').replace('SQL','HTTP / SQLite')}));
      // The real-service executor runs only its scripted scenarios.
      delete result.attackActions;
    }
    result.runtime = {mode:this.mode,available:this.container,detail:this.detail,containmentVerified:!!this.realState?.containmentVerified};
    result.ai = {available:this.container,detail:this.aiDetail,runs:structuredClone(this.runs)};
    result.attackHistory = structuredClone(this.attackHistory);
    result.botScore = structuredClone(this.botScore);
    const hacker = this.hacker.view();
    result.hacker = { ...hacker, available: this.mode === 'simulation' };
    const hackerRun = this.mode === 'simulation' ? {
      attempts: this.hacker.attempts.filter(a => a.run === this.runNumber),
      // Whole-run counters: the attempt records above are only the most recent window.
      stats: this.hacker.runStats.get(this.runNumber) ?? null,
      previousFirstBreach: this.hacker.previousRun()?.firstBreachAt ?? null, trend: hacker.trend,
    } : null;
    result.performance = performanceReport({ attackHistory: this.attackHistory, fixes: this.fixes, botScore: this.botScore, autoBlocked: (result.traffic?.autoBlocks ?? []).map(b => b.clientId), ...(result.weakSpots ? { weakSpots: result.weakSpots } : {}), hacker: hackerRun });
    result.learningLogs = structuredClone(this.logs.slice(0, 40));
    // Memory across runs for the Claude agents; prepareContext decides what each one sees.
    result.runNumber = this.runNumber;
    result.seed = this.seed;
    result.proof = structuredClone(this.proof);
    result.earlierAttacks = structuredClone(this.earlierAttacks);
    result.agentNotes = { searcher: this.notesFor('searcher'), builder: this.notesFor('builder') };
    return result;
  }
  async tick() {
    // Do not start a new read while an operation owns the state. A read already
    // underway is awaited by locked(), so it cannot overwrite a newer mutation.
    if (this.busy) return;
    if (this.mode === 'simulation') {
      this.simulation.tick();
      const attempt = this.hacker.tick(this.simulation);
      if (attempt) this.recordHack(attempt);
      this.settleAttack(); this.logTraffic(); this.refreshFixes();
    }
    else {
      try { await this.sync(); }
      catch { this.detail = 'Lab telemetry disconnected. Last observed state retained; no synthetic replacement.'; }
    }
  }
  async locked(action) {
    if (this.busy) throw new Error('An operation is in progress. Wait for it to finish.');
    this.busy = true;
    try {
      if (this.syncPromise) await this.syncPromise;
      await action();
    }
    finally { this.busy = false; }
    // Completed operations must not return the temporary "operation" scenario.
    return this.snapshot();
  }
  async setMode(mode) {
    if (!['simulation','lab'].includes(mode)) throw new Error('Unknown environment mode.');
    if (this.busy || this.snapshot().activeScenario) throw new Error('Finish the active operation before switching environment.');
    return this.locked(async()=>{
      // A pending telemetry read may have revealed an externally started run.
      if ((this.mode==='lab'?this.realState:this.simulation.snapshot())?.activeScenario) throw new Error('Finish the active operation before switching environment.');
      if (mode === 'lab') {
        await this.sync();
        if (!this.realState?.containmentVerified) throw new Error('Real-service traffic is locked. Run npm run lab:verify first.');
        // Resuming a mode does not silently undo a user's pause choice.
      } else if (this.mode === 'lab') {
        this.ingest(await this.executor('/running',{running:false}));
      }
      const changed = this.mode !== mode;
      if (changed) this.startNewRun();
      this.mode = mode; this.runs = []; this.attackHistory = []; this.pendingAttack = null; this.botScore = null;
    });
  }
  async runScenario(id) {
    return this.locked(async()=>{ await this.launch(id, 'admin'); });
  }
  // An approval is recorded only after the chosen environment accepts the fix.
  async applyRecommendation(id) {
    return this.locked(async()=>{
      if (this.mode === 'simulation') this.simulation.applyRecommendation(id);
      else {
        await this.sync();
        if (this.realState.activeScenario) throw new Error('Wait for the lab scenario to finish.');
        const rec = this.real.snapshot().recommendations.find(r=>r.id===id);
        if (!rec) throw new Error('Unknown recommendation.');
        // Mark the proposal applied only after the real service acknowledges it.
        const remote = await this.executor('/policy',{key:rec.policyKey});
        this.real.applyRecommendation(id); this.ingest(remote);
      }
      // Ledger entry: the fix counts as held only once a replay is blocked.
      const state = this.mode === 'lab' ? this.real.snapshot() : this.simulation.snapshot();
      const applied = state.recommendations.find(r => r.id === id);
      if (applied?.applied && !this.fixes.some(f => f.policyKey === applied.policyKey && f.appliedTick === applied.appliedTick)) {
        this.fixes = this.fixes.filter(f => f.policyKey !== applied.policyKey);
        this.fixes.push({ policyKey: applied.policyKey, title: applied.title, appliedTick: applied.appliedTick ?? state.tick });
        this.log('builder', `Applied: ${applied.title}.`);
      }
    });
  }
  async setRunning(running) {
    if (typeof running !== 'boolean') throw new Error('running must be a boolean.');
    return this.locked(async()=>{
      if (this.mode==='simulation') this.simulation.setRunning(running);
      else this.ingest(await this.executor('/running',{running}));
    });
  }
  async reset() {
    return this.locked(async()=>{
      // Reset lab leaves the environment paused so the admin starts traffic deliberately.
      if (this.mode==='simulation') {
        // A pinned demo seed covers its first cloud only: Reset moves on to a genuinely random one.
        if (this.seed !== null) { this.seed = null; this.simulation.useRandomLayouts(); }
        this.simulation.reset(); this.simulation.setRunning(false);
      }
      else { this.ingest(await this.executor('/reset',{})); this.ingest(await this.executor('/running',{running:false})); }
      this.startNewRun(); this.runs=[]; this.attackHistory=[]; this.pendingAttack=null; this.botScore=null;
    });
  }
  /** Presenter tool: start over exactly like a fresh server on this seed, so every judge group
   * sees the same first cloud. Run 1, Hacker learning wiped and off, history and logs cleared, paused. */
  async restartDemo(seed) {
    if (!Number.isInteger(seed) || seed < 0 || seed > 2 ** 32 - 1) throw new Error('seed must be a whole number from 0 to 4294967295.');
    this.simulatorOnly();
    return this.locked(async()=>{
      const random = streams(seed);
      this.simulation = new Simulation({ layout: 'random', random: random.traffic, layoutRandom: random.layout });
      this.simulation.setRunning(false);
      this.hacker = new Hacker({ random: random.hacker });
      this.seed = seed; this.runNumber = 1;
      this.runs = []; this.attackHistory = []; this.pendingAttack = null; this.botScore = null;
      this.fixes = []; this.logs = []; this.seenTraffic = new Set(); this.earlierAttacks = [];
      this.hacker.newRun(this.runNumber);
    });
  }
  /** Turn the Hacker on or off. It runs only in the in-memory simulator. */
  async setHacker(enabled) {
    if (typeof enabled !== 'boolean') throw new Error('enabled must be true or false.');
    this.simulatorOnly();
    return this.locked(async()=>{ this.hacker.enabled = enabled; });
  }
  /** Wipe what the Hacker has learned, to compare an untrained run with a trained one. */
  async forgetHacker() {
    return this.locked(async()=>{
      this.hacker.forget();
      this.log('hacker', 'Learning wiped: starting from scratch.');
    });
  }
  async updateNode(id, status, action) {
    if(!['active','paused'].includes(status)||!['normal','observe','quarantine'].includes(action))throw new Error('Invalid node controls.');
    return this.locked(async()=>{
      if(this.mode==='simulation')this.simulation.updateNode(id,status,action);
      else {
        if(!['gateway','lb','app','storage','iam','db'].includes(id))throw new Error('This node is a visual role, not an editable real service.');
        this.ingest(await this.executor('/node',{id,status,action}));
      }
    });
  }
  /** Users online and hidden bots exist only in the in-memory simulator. */
  simulatorOnly() { if (this.mode !== 'simulation') throw new Error('Users and hidden bots are available in the simulator. Switch to In-memory simulation.'); }
  async setTraffic({ users, bots } = {}) {
    this.simulatorOnly();
    return this.locked(async()=>{ this.simulation.setTraffic({ users, bots }); this.botScore = null; });
  }
  /** Reveal the attackers hidden in the traffic (bots, and the addresses the Hacker used this run)
   * and score the newest Searcher run against them. Only real users count as false alarms. */
  async revealBots() {
    this.simulatorOnly();
    return this.locked(async()=>{
      const { bots } = this.simulation.revealBots();
      const run = this.runs.find(r => r.agent === 'searcher');
      const suspects = new Set(run?.suspects ?? []);
      const botIds = new Set(bots.map(b => b.clientId));
      const hackerIds = [...new Set(this.hacker.attempts.filter(a => a.run === this.runNumber).flatMap(a => a.clientIds))];
      const hackerSet = new Set(hackerIds);
      this.botScore = {
        bots, searcherRunAt: run?.time ?? null, searcherMode: run?.mode ?? null,
        caught: bots.filter(b => suspects.has(b.clientId)).map(b => b.clientId),
        missed: bots.filter(b => !suspects.has(b.clientId)).map(b => b.clientId),
        hacker: { addresses: hackerIds.length, caught: hackerIds.filter(id => suspects.has(id)) },
        falseAlarms: [...suspects].filter(id => !botIds.has(id) && !hackerSet.has(id)),
      };
      const { caught, missed, falseAlarms, hacker } = this.botScore;
      const behavior = id => bots.find(b => b.clientId === id)?.behavior;
      const hackerText = hacker.addresses ? `; Hacker: ${hacker.caught.length} of ${hacker.addresses} addresses flagged` : '';
      this.log('searcher', `Reveal: flagged ${caught.length} of ${bots.length} bot${bots.length === 1 ? '' : 's'}${hackerText}${missed.length ? `; missed ${missed.map(id => `${id} (${behavior(id)})`).join(', ')}` : ''}${falseAlarms.length ? `; ${falseAlarms.length} false alarm${falseAlarms.length === 1 ? '' : 's'}` : ''}.`);
    });
  }
  async unblockClient(clientId) {
    this.simulatorOnly();
    return this.locked(async()=>{ this.simulation.unblockClient(clientId); });
  }
  // Take one bounded context, validate the worker response again, and retain
  // explicit model/fallback provenance. Only Attacker decisions launch actions.
  async runAI(agent) {
    if (!ROLES.includes(agent)) throw new Error('Unknown agent.');
    return this.locked(async()=>{
      if (this.mode==='lab') await this.sync();
      if ((this.mode==='lab'?this.realState:this.simulation.snapshot()).activeScenario) throw new Error('Finish the current scenario before an AI assessment.');
      const context=prepareContext(agent,this.snapshot());
      let result;
      if (this.container && this.agentToken) {
        try {
          const remote=await internalJson(`http://${agent}:8080/run`,this.agentToken,{context},this.fetch);
          if(remote.agent!==agent || !['model','fallback'].includes(remote.mode) || remote.provider!=='anthropic' || remote.model!==DEFAULT_MODEL) throw new Error('Invalid agent metadata.');
          const decision=validateDecision(agent,{summary:remote.summary,scenarioId:remote.scenarioId,evidenceIds:remote.evidenceIds,recommendationIds:remote.recommendationIds,labels:remote.labels,suspects:remote.suspects,plan:remote.plan},context);
          const servedBy=remote.mode==='model'?servedModel(remote.servedBy):undefined;
          result={agent,mode:remote.mode,model:DEFAULT_MODEL,provider:'anthropic',...decision,...(servedBy?{servedBy}:{}),...(remote.mode==='fallback'?{reason:'Broker used deterministic fallback; no model decision was available.'}:{})};
        }
        catch { result=await runAgent(agent,context); result.reason='Agent service unavailable; deterministic fallback used.'; }
      } else result=await runAgent(agent,context);
      this.runs.unshift({...result,time:new Date().toISOString()});this.runs=this.runs.slice(0,12);
      if (agent === 'searcher') {
        // Attack runs whose events the Searcher cited count as flagged.
        const cited = new Set(result.evidenceIds);
        for (const h of this.attackHistory) if (!h.flagged && (h.eventIds ?? []).some(id => cited.has(id))) h.flagged = true;
        // Hacker attempts count as flagged when their events are cited or their address is a suspect.
        const named = new Set(result.suspects ?? []);
        for (const a of this.hacker.attempts) if (a.run === this.runNumber && !a.flagged && (a.eventIds.some(id => cited.has(id)) || a.clientIds.some(id => named.has(id)))) a.flagged = true;
        const origins = ['internal', 'external'].map(o => [o, (result.labels ?? []).filter(l => l.origin === o).length]).filter(([, n]) => n).map(([o, n]) => `${n} ${o}`).join(', ');
        const n = result.suspects?.length ?? 0, m = result.evidenceIds.length;
        this.log('searcher', `Flagged ${n} suspect client${n === 1 ? '' : 's'} and ${m} event${m === 1 ? '' : 's'}${origins ? ` (${origins})` : ''}.`);
      }
      if (agent === 'builder' && result.recommendationIds.length) {
        const recs = (this.mode === 'lab' ? this.real.snapshot() : this.simulation.snapshot()).recommendations;
        this.log('builder', `Recommended first: ${recs.find(r => r.id === result.recommendationIds[0])?.title ?? result.recommendationIds[0]}.`);
      }
      this.aiDetail = result.mode!=='model' ? `${agent}: rule fallback. ${result.reason || 'Start the agent containers and add the Anthropic key.'}`
        : result.servedBy && result.servedBy!==result.model ? `${agent}: answered by ${result.servedBy} (${result.model} declined; server-side fallback).`
        : `${agent}: answered by ${result.model}.`;
      // Only validated scenario/catalog choices execute. Simulation also accepts
      // validated chains; Searcher and Builder decisions remain advisory.
      if (agent==='attacker' && result.plan?.length) await this.launchPlan(result.plan, 'ai');
      else if (agent==='attacker' && result.scenarioId) {
        const catalog=this.simulation.snapshot().scenarios;
        if (!catalog.some(s=>s.id===result.scenarioId)) throw new Error('Agent selected an unsupported scenario.');
        await this.launch(result.scenarioId, 'ai');
      }
    });
  }
}
