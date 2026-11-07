/** Coordinate browser commands without letting the UI or AI own security state.
 * Simulation is local; lab mode ingests executor observations into the same
 * detectors. Operation locks keep asynchronous reads from undoing newer writes.
 */
import { Simulation } from './simulation.mjs';
import { prepareContext, runAgent, validateDecision, servedModel, DEFAULT_MODEL } from '../ai/agents.mjs';

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
    executorToken = process.env.LAB_EXECUTOR_TOKEN, agentToken = process.env.AGENT_CONTROL_TOKEN} = {}) {
    this.simulation = simulation; this.container = container; this.fetch = fetchImpl;
    this.executorToken = executorToken; this.agentToken = agentToken;
    this.mode = 'simulation'; this.real = new Simulation(); this.generation = null;
    this.seen = new Set(); this.realState = null; this.runs = []; this.busy = false; this.syncPromise = null;
    this.attackHistory = []; this.pendingAttack = null; this.botScore = null;
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
    const name = plan ? `AI chain: ${plan.join(' → ')}` : this.simulation.snapshot().scenarios.find(s => s.id === scenarioId)?.name ?? scenarioId;
    this.attackHistory.unshift({ scenarioId, name, source, result: blockedBy.length ? 'blocked' : 'succeeded', blockedBy, ...(plan ? { plan: [...plan] } : {}), time: new Date().toISOString() });
    this.attackHistory = this.attackHistory.slice(0, 12);
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
    return result;
  }
  async tick() {
    // Do not start a new read while an operation owns the state. A read already
    // underway is awaited by locked(), so it cannot overwrite a newer mutation.
    if (this.busy) return;
    if (this.mode === 'simulation') { this.simulation.tick(); this.settleAttack(); }
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
      if (this.mode==='simulation') { this.simulation.reset(); this.simulation.setRunning(false); }
      else { this.ingest(await this.executor('/reset',{})); this.ingest(await this.executor('/running',{running:false})); }
      this.runs=[]; this.attackHistory=[]; this.pendingAttack=null; this.botScore=null;
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
  /** Reveal the hidden bots and score the newest Searcher run against them. */
  async revealBots() {
    this.simulatorOnly();
    return this.locked(async()=>{
      const { bots } = this.simulation.revealBots();
      const run = this.runs.find(r => r.agent === 'searcher');
      const suspects = new Set(run?.suspects ?? []);
      const botIds = new Set(bots.map(b => b.clientId));
      this.botScore = {
        bots, searcherRunAt: run?.time ?? null, searcherMode: run?.mode ?? null,
        caught: bots.filter(b => suspects.has(b.clientId)).map(b => b.clientId),
        missed: bots.filter(b => !suspects.has(b.clientId)).map(b => b.clientId),
        falseAlarms: [...suspects].filter(id => !botIds.has(id)),
      };
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
<<<<<<< HEAD
      this.aiDetail = result.mode!=='model' ? `${agent}: rule fallback. ${result.reason || 'Start the agent containers and add the Anthropic key.'}`
        : result.servedBy && result.servedBy!==result.model ? `${agent}: answered by ${result.servedBy} (${result.model} declined; server-side fallback).`
        : `${agent}: answered by ${result.model}.`;
      // Only the allowlisted scenario choice is executable. Searcher/Builder stay read-only.
=======
      this.aiDetail = result.mode!=='model' ? `${agent}: fallback used. ${result.reason || 'Configure the Anthropic key and start the agent containers.'}`
        : result.servedBy && result.servedBy!==result.model ? `${result.servedBy}: ${agent} completed a validated response after ${result.model} declined (Anthropic server-side fallback).`
        : `${result.model}: ${agent} completed a validated response.`;
      // Only validated scenario/catalog choices execute. Simulation also accepts
      // validated chains; Searcher and Builder decisions remain advisory.
>>>>>>> 79c9fa8 (README.md Update)
      if (agent==='attacker' && result.plan?.length) await this.launchPlan(result.plan, 'ai');
      else if (agent==='attacker' && result.scenarioId) {
        const catalog=this.simulation.snapshot().scenarios;
        if (!catalog.some(s=>s.id===result.scenarioId)) throw new Error('Agent selected an unsupported scenario.');
        await this.launch(result.scenarioId, 'ai');
      }
    });
  }
}
