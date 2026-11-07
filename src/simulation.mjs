/**
 * VortexAI's entire cloud is a deterministic state machine. These objects are
 * virtual resources, never network endpoints: this module does not import any
 * network, process, filesystem, shell, or cloud-provider capability.
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

const clone = (value) => structuredClone(value);
const timeAt = (tick) => new Date(tick * 1000).toISOString().slice(11, 19);

export class Simulation {
  constructor() { this.reset(); }

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
    this._policies = { storagePrivate: false, requireMfa: false, databaseLeastPrivilege: false };
    this._metrics = { totalEvents: 0, attackEvents: 0, blockedEvents: 0, attackAttempts: 0 };
    this._agents = {
      attacker: { status: 'Ready', detail: 'Choose a bounded scenario to test the virtual cloud.' },
      searcher: { status: 'Monitoring', detail: 'Observing identity, data access, and application events.' },
      builder: { status: 'Waiting', detail: 'Recommendations appear when observed evidence identifies a weak control.' },
    };
    return this.snapshot();
  }

  /** Return defensive copies so API clients cannot mutate the environment. */
  snapshot() {
    return clone({
      running: this.running,
      tick: this._tick,
      nodes: NODES,
      edges: EDGES,
      events: this._events,
      findings: this._findings,
      recommendations: this._recommendations,
      policies: this._policies,
      scenarios: SCENARIOS,
      activeScenario: this._active ? {
        id: this._active.id, name: this._active.name,
        step: this._active.index, total: this._active.steps.length,
      } : null,
      metrics: { ...this._metrics, openFindings: this._findings.filter(f => f.status === 'open').length },
      agents: this._agents,
    });
  }

  setRunning(running) {
    if (typeof running !== 'boolean') throw new TypeError('running must be a boolean.');
    this.running = running;
    return this.snapshot();
  }

  /** Each tick produces one normal request chain plus at most one attack step. */
  tick() {
    if (!this.running) return this.snapshot();
    this._tick += 1;
    this._normalTraffic();
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
    this._active = { id, name: scenario.name, index: 0, context: { blocked: false }, steps: this._scenarioSteps(id) };
    this._metrics.attackAttempts += 1;
    this._agents.attacker = { status: this.running ? 'Simulating' : 'Queued', detail: `${scenario.name}: ${scenario.steps} synthetic steps queued.` };
    return this.snapshot();
  }

  /** The Builder never applies its own recommendation: only this admin action can. */
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

  _normalTraffic() {
    const base = { kind: 'normal', outcome: 'allowed', authenticated: true, principal: 'application-user' };
    this._emit({ ...base, source: 'client', target: 'gateway', protocol: 'HTTPS', action: 'request', bytes: 820, detail: 'Authenticated user requests the application.' });
    this._emit({ ...base, source: 'gateway', target: 'lb', protocol: 'HTTPS', action: 'route', bytes: 820, detail: 'Gateway forwards the accepted request.' });
    this._emit({ ...base, source: 'lb', target: 'app', protocol: 'HTTPS', action: 'request', bytes: 820, detail: 'Load balancer selects the application service.' });
    const dataNode = this._tick % 2 ? 'db' : 'storage';
    this._emit({ ...base, source: 'app', target: dataNode, protocol: dataNode === 'db' ? 'SQL/TLS' : 'HTTPS', action: 'read', bytes: 2400, principal: 'app-service', detail: 'Application performs an authorized data read using its service identity.' });
    this._emit({ ...base, source: dataNode, target: 'app', protocol: dataNode === 'db' ? 'SQL/TLS' : 'HTTPS', action: 'response', bytes: 4600, principal: 'app-service', detail: 'The data service returns a synthetic application response.' });
    this._emit({ ...base, source: 'app', target: 'lb', protocol: 'HTTPS', action: 'response', bytes: 5200, detail: 'The application returns the completed synthetic response to the load balancer.' });
    this._emit({ ...base, source: 'lb', target: 'gateway', protocol: 'HTTPS', action: 'response', bytes: 5200, detail: 'The load balancer forwards the response through the public gateway.' });
    this._emit({ ...base, source: 'gateway', target: 'client', protocol: 'HTTPS', action: 'response', bytes: 5200, detail: 'The gateway returns the response to the legitimate user, completing the round trip.' });
    this._emit({ ...base, source: 'app', target: 'logs', protocol: 'AUDIT', action: 'audit', bytes: 180, principal: 'app-service', detail: 'Structured telemetry records the request outcome.' });
  }

  _scenarioSteps(id) {
    const attack = (fields) => this._emit({ kind: 'attack', authenticated: false, bytes: 128, ...fields });
    if (id === 'exposed-storage') return [
      () => attack({ source: 'attacker', target: 'gateway', protocol: 'HTTPS', action: 'discover', outcome: 'allowed', detail: 'Synthetic discovery identifies the lab storage resource; no real host is contacted.' }),
      context => {
        context.blocked = this._policies.storagePrivate;
        attack({ source: 'attacker', target: 'storage', protocol: 'HTTPS', action: 'list-objects', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'anonymous', control: 'storagePrivate', detail: context.blocked ? 'Private access denies the anonymous object listing.' : 'The public storage policy permits anonymous object listing.' });
      },
      context => {
        context.blocked = this._policies.storagePrivate;
        attack({ source: 'attacker', target: 'storage', protocol: 'HTTPS', action: 'read-object', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'anonymous', control: 'storagePrivate', bytes: context.blocked ? 128 : 12000, detail: context.blocked ? 'Anonymous object reads are denied by the new private-access policy.' : 'Anonymous access reads a synthetic customer object. No real data exists.' });
      },
    ];
    if (id === 'credential-abuse') return [
      ...[1, 2, 3].map(attempt => () => attack({ source: 'attacker', target: 'iam', protocol: 'HTTPS', action: 'sign-in', outcome: 'denied', kind: 'blocked', principal: 'lab-admin', authentication: 'password', detail: `Synthetic password attempt ${attempt} is rejected.` })),
      context => {
        context.blocked = this._policies.requireMfa;
        attack({ source: 'attacker', target: 'iam', protocol: 'HTTPS', action: 'sign-in', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'lab-admin', authentication: 'password', authenticated: !context.blocked, control: 'requireMfa', detail: context.blocked ? 'A valid modeled password is insufficient: the MFA requirement denies the session.' : 'A modeled stolen password creates an administrator session after repeated failures.' });
      },
      context => {
        // Session availability is the sign-in outcome from the preceding step.
        attack({ source: 'attacker', target: 'app', protocol: 'HTTPS', action: 'admin-request', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', principal: 'lab-admin', authenticated: !context.blocked, detail: context.blocked ? 'No modeled administrator session is available; the request is denied.' : 'The unauthorized actor uses the synthetic administrator session.' });
      },
    ];
    return [
      () => attack({ source: 'attacker', target: 'gateway', protocol: 'HTTPS', action: 'token-replay', outcome: 'allowed', authenticated: true, principal: 'app-user', detail: 'Scenario assumption: an external actor holds a stolen low-privilege application token.' }),
      () => attack({ source: 'gateway', target: 'app', protocol: 'HTTPS', action: 'application-request', outcome: 'allowed', authenticated: true, principal: 'app-user', detail: 'A modeled application flaw lets this authenticated request invoke the service identity.' }),
      context => {
        context.blocked = this._policies.databaseLeastPrivilege;
        attack({ source: 'app', target: 'db', protocol: 'SQL/TLS', action: 'admin-export', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', authenticated: true, principal: 'app-service', control: 'databaseLeastPrivilege', detail: context.blocked ? 'The application role has read-only permissions; administrative export is denied.' : 'The overly privileged application role performs an administrative data export.' });
      },
      context => {
        attack({ source: context.blocked ? 'app' : 'db', target: context.blocked ? 'logs' : 'attacker', protocol: context.blocked ? 'AUDIT' : 'HTTPS', action: context.blocked ? 'export-denied-audit' : 'export-response', outcome: context.blocked ? 'denied' : 'allowed', kind: context.blocked ? 'blocked' : 'attack', authenticated: true, principal: 'app-service', bytes: context.blocked ? 180 : 24000, detail: context.blocked ? 'Audit records the blocked export. Application reads still work.' : 'The export is represented as a synthetic response to the external actor.' });
      },
    ];
  }

  _emit(fields) {
    const event = { id: `event-${++this._sequence}`, tick: this._tick, time: timeAt(this._tick), ...fields };
    this._events.unshift(event);
    this._events.length = Math.min(this._events.length, 160);
    this._metrics.totalEvents += 1;
    if (event.kind === 'attack') this._metrics.attackEvents += 1;
    if (event.kind === 'blocked') this._metrics.blockedEvents += 1;
    // The detector gets observation fields only, not the simulator's attack label.
    const { kind: _label, ...observation } = event;
    this._observe(observation);
  }

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
    this._agents.searcher = { status: 'Finding detected', detail: title };
    this._agents.builder = { status: 'Recommendation ready', detail: REMEDIATIONS[policyKey].title };
  }
}
