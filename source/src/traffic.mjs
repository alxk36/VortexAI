/**
 * Synthetic users and hidden bots for the in-memory simulator.
 *
 * Bots are not the Attacker agent. They are background actors mixed in with
 * normal users: nothing in a snapshot says which clients are bots until the
 * admin reveals them, so the Searcher has to find them from behavior. All
 * traffic is in-memory events between predefined nodes. Client addresses come
 * from the RFC 5737 documentation ranges and never refer to real hosts.
 */
export const MAX_USERS = 60;
const BEHAVIORS = Object.freeze(['credential-stuffing', 'storage-scraping', 'request-flood']);
const WINDOW_TICKS = 40;        // per-client history kept for the activity summary
const FLOOD_LIMIT = 8;          // requests from one client in one tick that trip the breaker
const BLOCK_TICKS = 20;         // how long the tripwire blocks a flooding client
const CLIENT_SUMMARY_CAP = 70;
const CAPACITY = 40;            // allowed gateway requests per tick before the whole system pauses

export class TrafficModel {
  constructor({ random = Math.random } = {}) {
    this.random = random;
    this.users = 1;
    this.botsEnabled = false;
    this.reset();
  }

  /** A new population: settings are kept, bots are re-drawn, history is cleared. */
  reset() {
    const addresses = this._shuffle(ADDRESS_POOL).slice(0, this.users + 3);
    this.userIds = addresses.slice(0, this.users);
    const botCount = this.botsEnabled ? 1 + Math.floor(this.random() * Math.min(3, 1 + Math.floor(this.users / 10))) : 0;
    this.bots = addresses.slice(this.users, this.users + botCount).map(clientId => ({
      clientId,
      behavior: BEHAVIORS[Math.floor(this.random() * BEHAVIORS.length)],
      startTick: 2 + Math.floor(this.random() * 6),
      nextFlood: 0,
    }));
    this.history = new Map();      // clientId -> [{tick, action, target, outcome, principal, authenticated}]
    this.blocks = new Map();       // clientId -> untilTick
    this.autoBlocks = [];          // tripwire log, newest first
    this.revealed = null;
    this.overloads = [];           // capacity-breaker log, newest first
    this.load = { tick: -1, requests: 0 };
    this.overloadedTick = -1;
    this.joinBurst = 0;
    this.joined = { tick: -1, count: 0 };
  }

  configure({ users, bots }) {
    if (!Number.isInteger(users) || users < 1 || users > MAX_USERS) throw new Error(`users must be a whole number from 1 to ${MAX_USERS}.`);
    if (typeof bots !== 'boolean') throw new Error('bots must be true or false.');
    const previous = this.users;
    this.users = users;
    this.botsEnabled = bots;
    this.reset();
    // New users all arrive at the gateway in the next tick, like a sudden wave of sign-ups.
    this.joinBurst = Math.max(0, users - previous);
  }

  /** Normal request chains per tick grow with the number of users online. */
  chainsPerTick() { return Math.min(3, Math.ceil(this.users / 20)); }
  pickUser() { return this.userIds[Math.floor(this.random() * this.userIds.length)]; }
  /** Each user signs in with their own account. */
  accountFor(clientId) { return `user-${this.userIds.indexOf(clientId) + 1}`; }
  isBlocked(clientId, tick) { return (this.blocks.get(clientId) ?? -1) >= tick; }

  /** Hidden bot activity for this tick. Bot events never carry the attack label. */
  tick(sim) {
    const tick = sim._tick;
    for (const [clientId, until] of this.blocks) if (until < tick) this.blocks.delete(clientId);
    if (this.joinBurst) {
      this.joined = { tick, count: this.joinBurst };
      for (const clientId of this.userIds.slice(-this.joinBurst)) {
        sim._emit({ kind: 'normal', clientId, source: 'client', target: 'gateway', protocol: 'HTTPS', action: 'request', outcome: 'allowed', authenticated: true, principal: 'application-user', bytes: 820, detail: 'A user who just joined opens the application.' });
      }
      this.joinBurst = 0;
    }
    for (const bot of this.bots) {
      if (tick < bot.startTick) continue;
      if (bot.behavior === 'credential-stuffing' && this.random() < 0.7) {
        const account = `user-${1 + Math.floor(this.random() * 60)}`;
        const success = !sim._policies.requireMfa && this.random() < 0.08;
        this._botEvent(sim, bot, { target: 'iam', action: 'sign-in', principal: account, authentication: 'password',
          outcome: success ? 'allowed' : 'denied', authenticated: success, bytes: 300,
          detail: success ? 'Password sign-in accepted.' : 'Password sign-in rejected.' });
      } else if (bot.behavior === 'storage-scraping' && this.random() < 0.6) {
        const denied = sim._policies.storagePrivate;
        this._botEvent(sim, bot, { target: 'storage', action: this.random() < 0.5 ? 'list-objects' : 'read-object', principal: 'anonymous',
          authenticated: false, outcome: denied ? 'denied' : 'allowed', bytes: denied ? 128 : 6000, ...(denied ? { control: 'storagePrivate' } : {}),
          detail: denied ? 'Private access denies anonymous object access.' : 'Anonymous object access completed.' });
      } else if (bot.behavior === 'request-flood' && tick >= bot.nextFlood) {
        bot.nextFlood = tick + 4 + Math.floor(this.random() * 3);
        const burst = 10 + Math.floor(this.random() * 5);
        for (let i = 0; i < burst; i++) {
          this._botEvent(sim, bot, { target: 'gateway', action: 'request', principal: 'anonymous', authenticated: false,
            outcome: 'allowed', bytes: 900, detail: 'Request accepted at the gateway.' });
        }
      }
    }
  }

  _botEvent(sim, bot, fields) {
    const paused = ['paused'].includes(sim._nodeSettings[fields.target]?.status) || sim._nodeSettings[fields.target]?.action === 'quarantine';
    const blocked = this.isBlocked(bot.clientId, sim._tick);
    const event = { source: 'client', protocol: 'HTTPS', clientId: bot.clientId, ...fields };
    if (blocked) Object.assign(event, { outcome: 'denied', authenticated: false, control: 'autoBlock', bytes: 64, detail: 'Searcher tripwire is blocking this client.' });
    else if (paused) Object.assign(event, { outcome: 'denied', detail: 'The target node is paused or quarantined.' });
    // Hidden: an allowed bot event looks like normal traffic; a denied one looks like any other denial.
    event.kind = event.outcome === 'denied' ? 'blocked' : 'normal';
    sim._emit(event);
  }

  /** Called for every event that carries a client address. Runs the flood tripwire. */
  observe(event, sim) {
    const tick = event.tick;
    // Capacity breaker: too many allowed gateway requests in one tick pauses the whole system.
    if (event.target === 'gateway' && event.action === 'request' && event.outcome === 'allowed') {
      if (this.load.tick !== tick) this.load = { tick, requests: 0 };
      this.load.requests += 1;
      if (this.overloadedTick === tick) this.overloads[0].requests = this.load.requests;
      else if (this.load.requests >= CAPACITY) this._overload(sim, tick);
    }
    const list = this.history.get(event.clientId) ?? [];
    list.push({ tick, action: event.action, target: event.target, outcome: event.outcome, principal: event.principal, authenticated: event.authenticated === true });
    while (list.length && list[0].tick <= tick - WINDOW_TICKS) list.shift();
    this.history.set(event.clientId, list);
    if (event.target !== 'gateway' || event.action !== 'request' || this.isBlocked(event.clientId, tick)) return;
    const thisTick = list.filter(e => e.tick === tick && e.target === 'gateway' && e.action === 'request').length;
    if (thisTick < FLOOD_LIMIT) return;
    this.blocks.set(event.clientId, tick + BLOCK_TICKS);
    const reason = `${thisTick} requests in one tick (limit ${FLOOD_LIMIT})`;
    // One log entry per client: a repeat offender moves to the top with a count.
    const earlier = this.autoBlocks.findIndex(b => b.clientId === event.clientId);
    const count = earlier >= 0 ? (this.autoBlocks[earlier].count ?? 1) + 1 : 1;
    if (earlier >= 0) this.autoBlocks.splice(earlier, 1);
    this.autoBlocks.unshift({ clientId: event.clientId, tick, untilTick: tick + BLOCK_TICKS, reason, count });
    this.autoBlocks = this.autoBlocks.slice(0, 12);
    const again = count > 1 ? ` again (blocked ${count} times)` : '';
    if (this.overloadedTick !== tick) sim._agents.searcher = { status: 'Auto-blocked client', detail: `Blocked ${event.clientId}${again}: ${reason}. Auto-expires in ${BLOCK_TICKS} ticks.` };
  }

  _overload(sim, tick) {
    this.overloadedTick = tick;
    sim.running = false;
    this.overloads.unshift({ tick, requests: this.load.requests, capacity: CAPACITY, joined: this.joined.tick === tick ? this.joined.count : 0 });
    this.overloads = this.overloads.slice(0, 12);
    sim._agents.searcher = { status: 'System overloaded', detail: `Gateway hit ${CAPACITY} requests in one tick; paused to protect services. Press Resume.` };
  }

  unblock(clientId) {
    if (!this.blocks.has(clientId)) throw new Error('That client is not blocked.');
    this.blocks.delete(clientId);
    const entry = this.autoBlocks.find(b => b.clientId === clientId && !b.liftedByAdmin);
    if (entry) entry.liftedByAdmin = true;
  }

  reveal(tick) {
    this.revealed = { tick, bots: this.bots.map(b => ({ clientId: b.clientId, behavior: b.behavior })) };
    return structuredClone(this.revealed);
  }

  /** Flow-log style per-client activity. Contains no bot labels. */
  clients(tick) {
    const rows = [];
    for (const [clientId, list] of this.history) {
      const recent = list.filter(e => e.tick > tick - WINDOW_TICKS);
      if (!recent.length) continue;
      const perTick = new Map();
      for (const e of recent) if (e.target === 'gateway' && e.action === 'request') perTick.set(e.tick, (perTick.get(e.tick) ?? 0) + 1);
      const signIns = recent.filter(e => e.action === 'sign-in');
      rows.push({
        clientId,
        requests: recent.filter(e => e.target === 'gateway' && e.action === 'request').length,
        peakPerTick: Math.max(0, ...perTick.values()),
        failedSignIns: signIns.filter(e => e.outcome === 'denied').length,
        successfulSignIns: signIns.filter(e => e.outcome === 'allowed').length,
        accountsTried: new Set(signIns.map(e => e.principal)).size,
        anonymousStorage: recent.filter(e => e.target === 'storage' && e.principal === 'anonymous').length,
        denied: recent.filter(e => e.outcome === 'denied').length,
        lastSeenTick: recent.at(-1).tick,
      });
    }
    return rows.sort((a, b) => b.lastSeenTick - a.lastSeenTick || a.clientId.localeCompare(b.clientId)).slice(0, CLIENT_SUMMARY_CAP);
  }

  /** Public view for snapshots: settings, activity and tripwire log, never bot identities before reveal. */
  view(tick) {
    return {
      users: this.users, botsEnabled: this.botsEnabled, maxUsers: MAX_USERS,
      clients: this.clients(tick),
      blocked: [...this.blocks.entries()].filter(([, until]) => until >= tick).map(([clientId, untilTick]) => ({ clientId, untilTick })),
      autoBlocks: structuredClone(this.autoBlocks),
      capacity: CAPACITY,
      overloads: this.overloads.map(o => ({ ...o, reason: `${o.joined ? `${o.joined} users joined at once: ` : ''}${o.requests} requests in one tick (capacity ${o.capacity})` })),
      revealed: this.revealed ? structuredClone(this.revealed) : null,
    };
  }

  _shuffle(items) {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i--) { const j = Math.floor(this.random() * (i + 1)); [copy[i], copy[j]] = [copy[j], copy[i]]; }
    return copy;
  }
}

// RFC 5737 documentation addresses: never routable, never real hosts.
const ADDRESS_POOL = Object.freeze([
  ...Array.from({ length: 40 }, (_, i) => `203.0.113.${10 + i * 5}`),
  ...Array.from({ length: 40 }, (_, i) => `198.51.100.${12 + i * 6}`),
]);
