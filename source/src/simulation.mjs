/**
 * VortexAI's in-memory cloud is a state machine with fixed scenario outcomes
 * and injectable randomness for background users/bots. These resources are not
 * network endpoints; this module has no network, process, or filesystem access.
 */
const NODES = [
  { id: 'client', label: 'Users', type: 'client', zone: 'Internet', x: -4, y: 0, z: -1.7, description: 'Legitimate users send synthetic HTTPS requests to the cloud edge.' },
  { id: 'attacker', label: 'Attacker', type: 'attacker', zone: 'Internet', x: -4, y: 0, z: 2, description: 'A bounded scenario generator. All targets and traffic exist only in memory.' },
  { id: 'gateway', label: 'Gateway', type: 'gateway', zone: 'Public edge', x: -2.2, y: 0.3, z: -0.7, description: 'The public entry point accepts modeled HTTPS traffic.' },
  { id: 'lb', label: 'Load balancer', type: 'loadbalancer', zone: 'Public edge', x: -0.7, y: 0.3, z: -1.6, description: 'Distributes modeled requests to the private application tier.' },
  { id: 'app', label: 'Application', type: 'compute', zone: 'Private services', x: 0.6, y: 0.4, z: 0, description: 'Serves requests and uses a service identity to access private data.' },
  { id: 'iam', label: 'Identity', type: 'identity', zone: 'Control plane', x: -0.5, y: 2.6, z: -2.8, description: 'Models sign-in, rejected credentials, and an optional MFA requirement.' },
  { id: 'db', label: 'Database', type: 'database', zone: 'Private data', x: 3.1, y: 0.4, z: -1.5, description: 'Allows application reads; the intentionally weak initial role can also export administrative data.' },
  { id: 'storage', label: 'Object storage', type: 'storage', zone: 'Private data', x: 3.1, y: 0.4, z: 1.2, description: 'A misconfigured public storage resource until its private access control is applied.' },
  { id: 'logs', label: 'Telemetry', type: 'telemetry', zone: 'Observability', x: 2, y: 2.8, z: 3.5, description: 'Collects structured observations for the Searcher. This is audit telemetry, not application traffic.' },
];

const EDGES = [
  ['client', 'gateway', 'HTTPS ingress'], ['gateway', 'lb', 'HTTPS route'],
  ['lb', 'app', 'Application request'], ['app', 'iam', 'Service identity'],
  ['app', 'db', 'Private SQL'], ['app', 'storage', 'Private object API'],
  ['gateway', 'logs', 'Access logs'], ['iam', 'logs', 'Identity audit'],
  ['app', 'logs', 'Application audit'], ['db', 'logs', 'Database audit'],
  ['storage', 'logs', 'Storage audit'],
].map(([source, target, label]) => ({ source, target, label }));

const SCENARIOS = [
  { id: 'exposed-storage', name: 'Exposed storage', description: 'An anonymous external actor lists and reads a public object store. Private access blocks the same replay.', steps: 3 },
  { id: 'credential-abuse', name: 'Credential abuse', description: 'Repeated failed sign-ins precede a successful stolen-password sign-in. MFA blocks the modeled password-only replay.', steps: 5 },
  { id: 'lateral-movement', name: 'Lateral movement', description: 'Assumes a stolen low-privilege application token. An overpowered service role enables a database export; least privilege blocks it.', steps: 4 },
];

// The Builder can explain/order this fixed menu; it cannot invent a policy key.
const REMEDIATIONS = {
  storagePrivate: {
    title: 'Make object storage private',
    description: 'Deny anonymous list/read operations and allow object access only through the application service identity.',
    tradeoff: 'Public downloads must use an authenticated delivery path or explicitly scoped signed links.',
  },
  requireMfa: {
    title: 'Require MFA for interactive sign-in',
    description: 'Require a second factor for interactive user sign-in. A stolen password alone no longer creates a session in this model.',
    tradeoff: 'Users need an enrolled second factor and an account recovery process; this does not model stolen sessions or MFA bypass.',
  },
  databaseLeastPrivilege: {
    title: 'Restrict the application database role',
    description: 'Keep application reads available, but remove administrative export permission from the application service identity.',
    tradeoff: 'Administrative exports require a separate approved identity. This limits the blast radius; it does not revoke the stolen application token.',
  },
};

import { TrafficModel } from './traffic.mjs';

// Allowlisted attack steps. The scripted scenarios are fixed lists of these,
// and the AI Attacker may compose its own chains from the same list. A step
// only changes in-memory state; `requires` names a step that must come earlier.
// Descriptions say what a step attempts, never which control would stop it.
const ATTACK_ACTIONS = Object.freeze([
  { id: 'discover', description: 'Probe the public gateway to find exposed resources.', requires: [], nodes: ['attacker', 'gateway'] },
  { id: 'storage-list', description: 'List objects in object storage without signing in.', requires: [], nodes: ['attacker', 'storage'] },
  { id: 'storage-read', description: 'Read an object from object storage without signing in.', requires: [], nodes: ['attacker', 'storage'] },
  { id: 'password-guess', description: 'Try a wrong password against the lab administrator account.', requires: [], nodes: ['attacker', 'iam'] },
  { id: 'stolen-password-signin', description: 'Sign in as the lab administrator with a stolen password.', requires: [], nodes: ['attacker', 'iam'] },
  { id: 'admin-request', description: 'Use that administrator session to call an admin function in the application.', requires: ['stolen-password-signin'], nodes: ['app'] },
  { id: 'token-replay', description: 'Replay a stolen low-privilege application token at the gateway.', requires: [], nodes: ['attacker', 'gateway'] },
  { id: 'app-flaw-request', description: 'Abuse an application flaw so the request runs as the app service identity.', requires: ['token-replay'], nodes: ['gateway', 'app'] },
  { id: 'db-admin-export', description: 'Use the service identity to run an administrative database export.', requires: ['app-flaw-request'], nodes: ['app', 'db'] },
  { id: 'exfiltrate', description: 'Send the exported data out to the attacker.', requires: ['db-admin-export'], nodes: ['db'] },
]);
const ACTION_BY_ID = Object.fromEntries(ATTACK_ACTIONS.map(a => [a.id, a]));
const SCENARIO_ACTIONS = Object.freeze({
  'exposed-storage': ['discover', 'storage-list', 'storage-read'],
  'credential-abuse': ['password-guess', 'password-guess', 'password-guess', 'stolen-password-signin', 'admin-request'],
  'lateral-movement': ['token-replay', 'app-flaw-request', 'db-admin-export', 'exfiltrate'],
});
const MAX_PLAN_STEPS = 8;

/** Why a composed chain is not allowed, or null when it is. */
export function planProblem(actions) {
  if (!Array.isArray(actions) || actions.length < 1 || actions.length > MAX_PLAN_STEPS) return `A plan needs 1 to ${MAX_PLAN_STEPS} steps.`;
  for (const [index, actionId] of actions.entries()) {
    const action = typeof actionId === 'string' ? ACTION_BY_ID[actionId] : undefined;
    if (!action) return 'The plan contains an unknown attack action.';
    const missing = action.requires.find(req => !actions.slice(0, index).includes(req));
    if (missing) return `${actionId} requires ${missing} earlier in the plan.`;
  }
  return null;
}

const clone = (value) => structuredClone(value);
const timeAt = (tick) => new Date(tick * 1000).toISOString().slice(11, 19);

export class Simulation {
  constructor({ random = Math.random } = {}) { this._traffic = new TrafficModel({ random }); this.reset(); }

  /** Reset is a new lab run: controls, findings, counters, and queues are cleared. */
  reset() {
    this.running = true;
    this._tick = 0;
    this._sequence = 0;
    this._events = [];
    this._findings = [];
    this._recommendations = [];
    this._failures = new Map();
    this._active = null;
    this._nodeSettings = Object.fromEntries(NODES.map(n=>[n.id,{status:'active',action:'normal'}]));
    this._policies = { storagePrivate: false, requireMfa: false, databaseLeastPrivilege: false };
    this._metrics = { totalEvents: 0, attackEvents: 0, blockedEvents: 0, attackAttempts: 0 };
    this._agents = {
      attacker: { status: 'Ready', detail: 'Choose a bounded scenario to test the virtual cloud.' },
      searcher: { status: 'Monitoring', detail: 'Observing identity, data access, and application events.' },
      builder: { status: 'Waiting', detail: 'Recommendations appear when observed evidence identifies a weak control.' },
    };
    this._traffic.reset();
    return this.snapshot();
  }

  /** Clone externally visible state so callers cannot mutate policies, queues,
   * or retained evidence by modifying a response object. */
  snapshot() {
    return clone({
      running: this.running,
      tick: this._tick,
      nodes: NODES.map(n=>({...n,...this._nodeSettings[n.id]})),
      edges: EDGES,
      events: this._events,
      findings: this._findings,
      recommendations: this._recommendations,
      policies: this._policies,
      scenarios: SCENARIOS,
      attackActions: ATTACK_ACTIONS.map(({ id, description, requires }) => ({ id, description, requires: [...requires] })),
      activeScenario: this._active ? {
        id: this._active.id, name: this._active.name,
        step: this._active.index, total: this._active.steps.length,
        ...(this._active.plan ? { plan: [...this._active.plan] } : {}),
      } : null,
      metrics: { ...this._metrics, openFindings: this._findings.filter(f => f.status === 'open').length },
      agents: this._agents,
      traffic: this._traffic.view(this._tick),
    });
  }

  setRunning(running) {
    if (typeof running !== 'boolean') throw new TypeError('running must be a boolean.');
    this.running = running;
    return this.snapshot();
  }

  /** UI policy controls are finite model state, never commands for the host. */
  updateNode(id,status,action) {
    if (!Object.hasOwn(this._nodeSettings,id)) throw new Error('Unknown node.');
    if (!['active','paused'].includes(status) || !['normal','observe','quarantine'].includes(action)) throw new Error('Invalid node status or action.');
    if (this._active) throw new Error('Finish the scenario before changing node controls.');
    this._nodeSettings[id]={status,action};
    return this.snapshot();
  }

  /** Advance normal/background traffic and at most one scenario step per tick.
   * Pausing freezes model time, including attack progress and timed blocks,
   * rather than merely stopping the animation. */
  tick() {
    if (!this.running) return this.snapshot();
    this._tick += 1;
    this._normalTraffic();
    this._traffic.tick(this);
    if (this._active) {
      const current = this._active;
      const action = current.steps[current.index];
      current.index += 1;
      action(current.context);
      this._agents.attacker.detail = `${current.name}: step ${current.index} of ${current.steps.length}.`;
      if (current.index === current.steps.length) {
        this._agents.attacker = {
          status: current.context.blocked ? 'Blocked' : 'Completed',
          detail: current.context.blocked
            ? `${current.name}: the modeled control blocked the attack effect.`
            : `${current.name}: scenario finished; inspect the observed evidence.`,
        };
        this._active = null;
      }
    }
    return this.snapshot();
  }

  /** Scenario identifiers, not arbitrary hosts or commands, are the only input. */
  runScenario(id) {
    const scenario = SCENARIOS.find(item => item.id === id);
    if (!scenario) throw new Error('Unknown scenario. Choose one of the built-in simulations.');
    if (this._active) throw new Error('A scenario is already running. Finish it or reset the lab first.');
    const required = {'exposed-storage':['attacker','gateway','storage'],'credential-abuse':['attacker','iam','app'],'lateral-movement':['attacker','gateway','app','db']}[id];
    if (required.some(node=>this._nodeSettings[node].status==='paused'||this._nodeSettings[node].action==='quarantine')) throw new Error('Restore the scenario resources to active, non-quarantined status before running it.');
    this._active = { id, name: scenario.name, index: 0, context: { blocked: false }, steps: this._scenarioSteps(id) };
    this._metrics.attackAttempts += 1;
    this._agents.attacker = { status: this.running ? 'Simulating' : 'Queued', detail: `${scenario.name}: ${scenario.steps} synthetic steps queued.` };
    return this.snapshot();
  }

  /** Run a composed chain of allowlisted steps (the AI Attacker's own attack). */
  runPlan({ actions, name = '' } = {}) {
    if (this._active) throw new Error('A scenario is already running. Finish it or reset the lab first.');
    const problem = planProblem(actions);
    if (problem) throw new Error(problem);
    const nodes = new Set(actions.flatMap(actionId => ACTION_BY_ID[actionId].nodes));
    if ([...nodes].some(node => this._nodeSettings[node].status === 'paused' || this._nodeSettings[node].action === 'quarantine')) {
      throw new Error('Restore the plan resources to active, non-quarantined status before running it.');
    }
    const label = typeof name === 'string' && name.trim() ? name.trim().slice(0, 80) : `Custom chain: ${actions.join(' → ')}`;
    this._active = { id: 'custom', name: label, index: 0, context: { blocked: false }, steps: actions.map(a => this._attackStep(a)), plan: [...actions] };
    this._metrics.attackAttempts += 1;
    this._agents.attacker = { status: this.running ? 'Simulating' : 'Queued', detail: `${label}: ${actions.length} synthetic steps queued.` };
    return this.snapshot();
  }

  /** The Builder never applies its own recommendation: only this admin action can. */
  // Apply only a proposed catalog remedy between scenarios. Replay validation
  // is separate: _observe must later see a denial caused by that control.
  applyRecommendation(id) {
    const recommendation = this._recommendations.find(item => item.id === id);
    if (!recommendation) throw new Error('Unknown recommendation. Run a scenario to collect evidence first.');
    // Keep baseline and replay runs distinct; changing a control mid-run would
    // wrongly imply that enabling MFA revokes an already issued session.
    if (this._active) throw new Error('Wait for the scenario to finish before applying a recommendation.');
    if (recommendation.applied) return this.snapshot();
    this._policies[recommendation.policyKey] = true;
    recommendation.applied = true;
    recommendation.validation = 'pending';
    recommendation.appliedTick = this._tick;
    const finding = this._findings.find(item => item.id === recommendation.findingId);
    finding.status = 'resolved';
    finding.resolvedTick = this._tick;
    this._agents.builder = { status: 'Awaiting replay', detail: 'Control applied by admin. Replay the matching scenario to validate the modeled fix.' };
    this._agents.searcher = { status: 'Monitoring', detail: 'Control changed; continuing to observe traffic for new evidence.' };
    return this.snapshot();
  }

  /** Users online and hidden bots (simulator only). Changing them starts a new population. */
  setTraffic({ users, bots } = {}) {
    if (this._active) throw new Error('Wait for the scenario to finish before changing traffic.');
    this._traffic.configure({ users, bots });
    return this.snapshot();
  }

  /** Show which clients were hidden bots. Until this call no snapshot names them. */
  revealBots() { return this._traffic.reveal(this._tick); }

  /** Admin override for the Searcher's flood tripwire. */
  unblockClient(clientId) {
    if (typeof clientId !== 'string') throw new Error('A client address is required.');
    this._traffic.unblock(clientId);
    this._agents.searcher = { status: 'Monitoring', detail: `Admin lifted the tripwire block on ${clientId}.` };
    return this.snapshot();
  }

  _normalTraffic() {
    // Stop at an unavailable resource: downstream work must not appear to succeed.
    const dataNodeForGate = this._tick % 2 ? 'db' : 'storage';
    const path = ['client','gateway','lb','app',dataNodeForGate];
    const blocked = path.findIndex(id=>this._nodeSettings[id].status==='paused'||this._nodeSettings[id].action==='quarantine');
    if (blocked >= 0) {
      for (let i=1;i<=Math.max(1,blocked);i++) this._emit({source:path[i-1],target:path[i],kind:i>=blocked?'blocked':'normal',outcome:i>=blocked?'denied':'allowed',protocol:'HTTPS',action:'request',bytes:128,detail:i>=blocked?'The simulator node is paused or quarantined. No downstream request is generated.':'Request advances toward the next available resource.'});
      return;
    }
    // More users online means more request chains per tick, each from one user's address.
    for (let chain = 0; chain < this._traffic.chainsPerTick(); chain++) this._userChain(this._traffic.pickUser());
  }

  _userChain(clientId) {
    const base = { kind: 'normal', outcome: 'allowed', authenticated: true, principal: 'application-user' };
    if (this._traffic.users > 1 && this._traffic.random() < 0.08) {
      // Ordinary users sign in now and then, and occasionally mistype a password.
      const typo = this._traffic.random() < 0.15;
      this._emit({ ...base, clientId, source: 'client', target: 'iam', protocol: 'HTTPS', action: 'sign-in', principal: this._traffic.accountFor(clientId), authentication: 'password+mfa', outcome: typo ? 'denied' : 'allowed', authenticated: !typo, kind: typo ? 'blocked' : 'normal', bytes: 300, detail: typo ? 'A user mistyped their password.' : 'A user signed in with a second factor.' });
    }
    this._emit({ ...base, clientId, source: 'client', target: 'gateway', protocol: 'HTTPS', action: 'request', bytes: 820, detail: 'Authenticated user requests the application.' });
    this._emit({ ...base, source: 'gateway', target: 'lb', protocol: 'HTTPS', action: 'route', bytes: 820, detail: 'Gateway forwards the accepted request.' });
    this._emit({ ...base, source: 'lb', target: 'app', protocol: 'HTTPS', action: 'request', bytes: 820, detail: 'Load balancer selects the application service.' });
    const dataNode = this._tick % 2 ? 'db' : 'storage';
    this._emit({ ...base, source: 'app', target: dataNode, protocol: dataNode === 'db' ? 'SQL/TLS' : 'HTTPS', action: 'read', bytes: 2400, principal: 'app-service', detail: 'Application performs an authorized data read using its service identity.' });
    this._emit({ ...base, source: dataNode, target: 'app', protocol: dataNode === 'db' ? 'SQL/TLS' : 'HTTPS', action: 'response', bytes: 4600, principal: 'app-service', detail: 'The data service returns a synthetic application response.' });
    this._emit({ ...base, source: 'app', target: 'lb', protocol: 'HTTPS', action: 'response', bytes: 5200, detail: 'The application returns the completed synthetic response to the load balancer.' });
    this._emit({ ...base, source: 'lb', target: 'gateway', protocol: 'HTTPS', action: 'response', bytes: 5200, detail: 'The load balancer forwards the response through the public gateway.' });
    this._emit({ ...base, clientId, source: 'gateway', target: 'client', protocol: 'HTTPS', action: 'response', bytes: 5200, detail: 'The gateway returns the response to the legitimate user, completing the round trip.' });
    this._emit({ ...base, source: 'app', target: 'logs', protocol: 'AUDIT', action: 'audit', bytes: 180, principal: 'app-service', detail: 'Structured telemetry records the request outcome.' });
  }

  /** Scripted scenarios are fixed lists of the same steps the AI Attacker may compose. */
  _scenarioSteps(id) { return SCENARIO_ACTIONS[id].map(action => this._attackStep(action)); }

  /** One allowlisted attack step: it only changes in-memory state and emits events. */
  _attackStep(actionId) {
    const attack = (fields) => this._emit({ kind: 'attack', authenticated: false, bytes: 128, ...fields });
    switch (actionId) {
      case 'discover': return () => attack({ source: 'attacker', target: 'gateway', protocol: 'HTTPS', action: 'discover', outcome: 'allowed', detail: 'Synthetic discovery identifies the lab storage resource; no real host is contacted.' });
      case 'storage-list': return context => {
        context.blocked = this._policies.storagePrivate;
        attack({ source: 'attacker', target: 'storage', protocol: 'HTTPS', action: 'list-objects', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'anonymous', control: 'storagePrivate', detail: context.blocked ? 'Private access denies the anonymous object listing.' : 'The public storage policy permits anonymous object listing.' });
      };
      case 'storage-read': return context => {
        context.blocked = this._policies.storagePrivate;
        attack({ source: 'attacker', target: 'storage', protocol: 'HTTPS', action: 'read-object', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'anonymous', control: 'storagePrivate', bytes: context.blocked ? 128 : 12000, detail: context.blocked ? 'Anonymous object reads are denied by the new private-access policy.' : 'Anonymous access reads a synthetic customer object. No real data exists.' });
      };
      case 'password-guess': return context => {
        context.guesses = (context.guesses ?? 0) + 1;
        attack({ source: 'attacker', target: 'iam', protocol: 'HTTPS', action: 'sign-in', outcome: 'denied', kind: 'blocked', principal: 'lab-admin', authentication: 'password', detail: `Synthetic password attempt ${context.guesses} is rejected.` });
      };
      case 'stolen-password-signin': return context => {
        context.blocked = this._policies.requireMfa;
        context.session = !context.blocked;
        attack({ source: 'attacker', target: 'iam', protocol: 'HTTPS', action: 'sign-in', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'lab-admin', authentication: 'password', authenticated: !context.blocked, control: 'requireMfa', detail: context.blocked ? 'A valid modeled password is insufficient: the MFA requirement denies the session.' : 'A modeled stolen password creates an administrator session after repeated failures.' });
      };
      case 'admin-request': return context => {
        // Session availability is the outcome of the earlier stolen-password sign-in.
        const denied = !context.session;
        attack({ source: 'attacker', target: 'app', protocol: 'HTTPS', action: 'admin-request', outcome: denied ? 'denied' : 'allowed', kind: denied ? 'blocked' : 'attack', principal: 'lab-admin', authenticated: !denied, detail: denied ? 'No modeled administrator session is available; the request is denied.' : 'The unauthorized actor uses the synthetic administrator session.' });
      };
      case 'token-replay': return context => {
        context.token = true;
        attack({ source: 'attacker', target: 'gateway', protocol: 'HTTPS', action: 'token-replay', outcome: 'allowed', authenticated: true, principal: 'app-user', detail: 'Scenario assumption: an external actor holds a stolen low-privilege application token.' });
      };
      case 'app-flaw-request': return context => {
        context.serviceIdentity = true;
        attack({ source: 'gateway', target: 'app', protocol: 'HTTPS', action: 'application-request', outcome: 'allowed', authenticated: true, principal: 'app-user', detail: 'A modeled application flaw lets this authenticated request invoke the service identity.' });
      };
      case 'db-admin-export': return context => {
        context.blocked = this._policies.databaseLeastPrivilege;
        context.exported = !context.blocked;
        attack({ source: 'app', target: 'db', protocol: 'SQL/TLS', action: 'admin-export', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', authenticated: true, principal: 'app-service', control: 'databaseLeastPrivilege', detail: context.blocked ? 'The application role has read-only permissions; administrative export is denied.' : 'The overly privileged application role performs an administrative data export.' });
      };
      case 'exfiltrate': return context => {
        const denied = !context.exported;
        attack({ source: denied ? 'app' : 'db', target: denied ? 'logs' : 'attacker', protocol: denied ? 'AUDIT' : 'HTTPS', action: denied ? 'export-denied-audit' : 'export-response', outcome: denied ? 'denied' : 'allowed', kind: denied ? 'blocked' : 'attack', authenticated: true, principal: 'app-service', bytes: denied ? 180 : 24000, detail: denied ? 'Audit records the blocked export. Application reads still work.' : 'The export is represented as a synthetic response to the external actor.' });
      };
      default: throw new Error('Unknown attack action.');
    }
  }

  // All synthetic observations pass through this path so metrics, bounded
  // history, evidence rules, and per-client traffic accounting stay consistent.
  _emit(fields) {
    const event = { id: `event-${++this._sequence}`, tick: this._tick, time: timeAt(this._tick), ...fields };
    if ([fields.source,fields.target].some(id=>this._nodeSettings[id]?.action==='observe')) event.detail += ' [Enhanced observation enabled for this node.]';
    this._events.unshift(event);
    this._events.length = Math.min(this._events.length, 160);
    this._metrics.totalEvents += 1;
    if (event.kind === 'attack') this._metrics.attackEvents += 1;
    if (event.kind === 'blocked') this._metrics.blockedEvents += 1;
    // The detector gets observation fields only, not the simulator's attack label.
    const { kind: _label, ...observation } = event;
    this._observe(observation);
    if (event.clientId) this._traffic.observe(event, this);
  }

  // Detect from observed actions/identity/outcomes, never presentation labels.
  // Denials can validate an approved fix; only allowed violations open findings.
  _observe(event) {
    if (event.action === 'sign-in' && event.outcome === 'denied') {
      const key = `${event.source}:${event.principal}`;
      const history = this._failures.get(key) || [];
      history.push(event);
      this._failures.set(key, history.filter(item => event.tick - item.tick <= 12).slice(-8));
    }
    if (event.outcome === 'denied' && event.control) {
      const recommendation = this._recommendations.find(item => item.policyKey === event.control && item.applied);
      if (recommendation) {
        recommendation.validation = 'blocked-replay';
        recommendation.validationEvent = clone(event);
        this._agents.builder = { status: 'Validated', detail: 'Observed replay was blocked by the applied control. Other attack paths remain outside this test.' };
      }
    }
    // Denied events can validate a control, but do not prove an exploitable weakness.
    if (event.outcome !== 'allowed') return;
    if (event.target === 'storage' && ['list-objects', 'read-object'].includes(event.action) && event.principal === 'anonymous' && !event.authenticated) {
      this._diagnose('storagePrivate', 'Anonymous access to cloud storage', 'critical', 'storage', [event]);
    }
    if (event.target === 'iam' && event.action === 'sign-in' && event.authentication === 'password') {
      const failures = (this._failures.get(`${event.source}:${event.principal}`) || []).filter(item => event.tick - item.tick <= 12);
      if (failures.length >= 3) this._diagnose('requireMfa', 'Password sign-in succeeds after repeated failures', 'high', 'iam', [...failures, event]);
    }
    if (event.target === 'db' && event.action === 'admin-export' && event.principal === 'app-service') {
      this._diagnose('databaseLeastPrivilege', 'Application identity can export administrative data', 'critical', 'db', [event]);
    }
  }

  _diagnose(policyKey, title, severity, nodeId, evidence) {
    let finding = this._findings.find(item => item.policyKey === policyKey);
    if (!finding) {
      finding = { id: `finding-${policyKey}`, title, severity, nodeId, policyKey, evidence: [], evidenceDetails: [], status: 'open', recommendationId: `recommendation-${policyKey}`, firstSeenTick: this._tick };
      this._findings.unshift(finding);
      this._recommendations.unshift({ id: finding.recommendationId, findingId: finding.id, ...REMEDIATIONS[policyKey], policyKey, applied: false, validation: 'pending' });
    } else if (finding.status === 'resolved') {
      // An observed allowed violation outranks a previously acknowledged policy.
      // Real services can restart or drift; a past blocked replay must never stay
      // displayed as proof that the now-successful path remains mitigated.
      finding.status = 'open';
      finding.regressionTick = this._tick;
      delete finding.resolvedTick;
      const recommendation = this._recommendations.find(item => item.id === finding.recommendationId);
      recommendation.applied = false;
      recommendation.validation = 'pending';
      delete recommendation.validationEvent;
      delete recommendation.appliedTick;
    }
    for (const event of evidence) {
      if (!finding.evidence.includes(event.id)) {
        finding.evidence.push(event.id);
        finding.evidenceDetails.push(clone(event));
      }
    }
    // Preserve compact evidence copies after the rolling activity feed expires.
    finding.evidence = finding.evidence.slice(-8);
    finding.evidenceDetails = finding.evidenceDetails.slice(-8);
    const regression = finding.regressionTick !== undefined;
    this._agents.searcher = {
      status: regression ? 'Regression detected' : 'Finding detected',
      detail: regression ? `A previously mitigated path succeeded again: ${title}. Review the new evidence.` : title,
    };
    this._agents.builder = {
      status: 'Recommendation ready',
      detail: regression ? `Re-approval and a fresh replay are required: ${REMEDIATIONS[policyKey].title}.` : REMEDIATIONS[policyKey].title,
    };
  }
}
