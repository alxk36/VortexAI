import test from 'node:test';
import assert from 'node:assert/strict';
import { Runtime } from '../src/runtime.mjs';
import { DEFAULT_MODEL } from '../ai/agents.mjs';

/** No containers, target listeners or paid models run here. This transport is a
 * strict in-process fixture for the controller's fixed internal HTTP boundary.
 */
function fixture({ verified = true, aiResult, failPolicy = false } = {}) {
  const calls = [];
  let generation = 1, sequence = 0, disconnected = false;
  const initial = () => ({
    generation: `generation-${generation}`, tick: 0, events: [],
    policies: { storagePrivate: false, requireMfa: false, databaseLeastPrivilege: false },
    running: true, activeScenario: null, containmentVerified: verified,
    metrics: { totalEvents: 0, attackEvents: 0, blockedEvents: 0 },
  });
  let remote = initial();
  function emit(fields) {
    remote.tick++;
    const event = {
      id: `remote-${++sequence}`, tick: remote.tick, time: '00:00:01',
      source: 'attacker', target: 'storage', protocol: 'HTTP', kind: 'attack',
      action: 'read-object', outcome: 'allowed', principal: 'anonymous', authenticated: false,
      bytes: 64, httpStatus: 200, detail: 'Observed fixture service response.',
      ...fields,
    };
    remote.events.unshift(event); remote.events = remote.events.slice(0,160);
    remote.metrics.totalEvents++;
    if(event.kind === 'attack') remote.metrics.attackEvents++;
    if(event.kind === 'blocked') remote.metrics.blockedEvents++;
    return event;
  }
  const fetchImpl = async (url, options) => {
    calls.push({ url, options, body: options.body === undefined ? undefined : JSON.parse(options.body) });
    assert.equal(options.redirect, 'error');
    assert.ok(options.headers.Authorization.startsWith('Bearer '));
    if (disconnected) throw new Error('Fixture disconnected.');
    const parsed = new URL(url), body = options.body ? JSON.parse(options.body) : undefined;
    if (parsed.hostname === 'executor') {
      if (parsed.pathname === '/scenario') {
        assert.ok(['exposed-storage','credential-abuse','lateral-movement'].includes(body.id));
        if (body.id === 'exposed-storage') emit({
          outcome: remote.policies.storagePrivate ? 'denied' : 'allowed',
          kind: remote.policies.storagePrivate ? 'blocked' : 'attack',
          httpStatus: remote.policies.storagePrivate ? 403 : 200, control: 'storagePrivate',
        });
      } else if (parsed.pathname === '/policy') {
        if (failPolicy) return Response.json({ error: 'Policy was not acknowledged.' }, { status:503 });
        assert.ok(Object.hasOwn(remote.policies, body.key)); remote.policies[body.key] = true;
      } else if (parsed.pathname === '/running') remote.running = body.running;
      else if (parsed.pathname === '/reset') { generation++; sequence=0; remote=initial(); }
      else assert.equal(parsed.pathname, '/state');
      return Response.json(remote);
    }
    assert.ok(['attacker','searcher','builder'].includes(parsed.hostname));
    assert.equal(parsed.pathname, '/run');
    const result = typeof aiResult === 'function' ? await aiResult(parsed.hostname, body.context) : aiResult;
    if (!result) throw new Error('No worker is available.');
    return Response.json(result);
  };
  const runtime = new Runtime({container:true,executorToken:'executor-token-test',agentToken:'agent-token-test',fetchImpl});
  return { runtime, calls, emit, remote:()=>remote, disconnect:()=>{disconnected=true;}, reconnect:()=>{disconnected=false;} };
}

const modelResult = (agent, fields={}) => ({
  agent, mode:'model', provider:'anthropic', model:DEFAULT_MODEL,
  summary:'Bounded model analysis for this lab.', scenarioId:null, evidenceIds:[], recommendationIds:[], labels:[],suspects:[],plan:[], ...fields,
});

test('real mode requires a container and successful containment attestation', async()=>{
  let calls=0;
  const host=new Runtime({container:false,fetchImpl:async()=>{calls++;throw new Error('Must not call');}});
  await assert.rejects(()=>host.setMode('lab'),/Docker|verified/);
  assert.equal(calls,0); assert.equal(host.snapshot().runtime.mode,'simulation');
  const unverified=fixture({verified:false});
  await assert.rejects(()=>unverified.runtime.setMode('lab'),/verify|locked/);
  assert.equal(unverified.runtime.snapshot().runtime.mode,'simulation');
  await assert.rejects(()=>host.setMode('production'),/Unknown/);
  await assert.rejects(()=>host.runAI('executor'),/Unknown/);
});

test('local explicit fallback works without a network call and is labeled honestly',async()=>{
  let calls=0;
  const runtime=new Runtime({container:false,fetchImpl:async()=>{calls++;throw new Error('No network allowed');}});
  await runtime.runAI('searcher');
  assert.equal(runtime.snapshot().ai.runs[0].mode,'fallback');
  assert.match(runtime.snapshot().ai.detail,/fallback/i);
  await runtime.runAI('attacker');
  assert.equal(runtime.snapshot().activeScenario.id,'exposed-storage');
  assert.equal(calls,0);
});

test('lab ticks use observed HTTP events only; disconnect never substitutes synthetic traffic',async()=>{
  const f=fixture(); f.emit({source:'app',target:'db',principal:'app-service',authenticated:true,kind:'normal',action:'read'});
  await f.runtime.setMode('lab');
  const before=f.runtime.snapshot();
  await f.runtime.tick();await f.runtime.tick();
  assert.deepEqual(f.runtime.snapshot().events,before.events);
  assert.equal(f.runtime.snapshot().metrics.totalEvents,1);
  assert.equal(f.runtime.simulation.snapshot().tick,0);
  assert.equal(f.runtime.real.snapshot().findings.length,0);
  f.disconnect();await f.runtime.tick();
  assert.deepEqual(f.runtime.snapshot().events,before.events);
  assert.match(f.runtime.snapshot().runtime.detail,/disconnected|retained/i);
});

test('observed storage access produces evidence; remote policy acknowledgment precedes blocked replay',async()=>{
  const f=fixture();await f.runtime.setMode('lab');
  await f.runtime.runScenario('exposed-storage');
  let state=f.runtime.snapshot();
  assert.equal(state.findings.length,1);
  assert.equal(state.findings[0].evidence[0],state.events[0].id);
  const recommendation=state.recommendations[0];
  assert.equal(recommendation.applied,false);
  await f.runtime.applyRecommendation(recommendation.id);
  state=f.runtime.snapshot();
  assert.equal(state.policies.storagePrivate,true);
  assert.equal(state.recommendations[0].applied,true);
  assert.equal(state.recommendations[0].validation,'pending');
  assert.deepEqual(f.calls.find(call=>call.url.endsWith('/policy')).body,{key:'storagePrivate'});
  await f.runtime.runScenario('exposed-storage');
  state=f.runtime.snapshot();
  assert.equal(state.recommendations[0].validation,'blocked-replay');
  assert.equal(state.findings.length,1);assert.equal(state.events[0].httpStatus,403);
  assert.equal(state.metrics.openFindings,0);
});

test('failed remote policy changes cannot mark the local recommendation applied',async()=>{
  const f=fixture({failPolicy:true});await f.runtime.setMode('lab');await f.runtime.runScenario('exposed-storage');
  const id=f.runtime.snapshot().recommendations[0].id;
  await assert.rejects(()=>f.runtime.applyRecommendation(id),/acknowledged/);
  assert.equal(f.runtime.snapshot().recommendations[0].applied,false);
  assert.equal(f.runtime.snapshot().policies.storagePrivate,false);
});

test('a later allowed violation reopens a resolved finding and invalidates stale replay proof',async()=>{
  const f=fixture();await f.runtime.setMode('lab');await f.runtime.runScenario('exposed-storage');
  const id=f.runtime.snapshot().recommendations[0].id;
  await f.runtime.applyRecommendation(id);await f.runtime.runScenario('exposed-storage');
  assert.equal(f.runtime.snapshot().recommendations[0].validation,'blocked-replay');
  // A target may restart with a weak policy while the executor's cached policy
  // still says true. The real allowed outcome must override that old assurance.
  const regression=f.emit({outcome:'allowed',kind:'attack',control:'storagePrivate'});
  await f.runtime.tick();
  let state=f.runtime.snapshot();
  assert.equal(state.policies.storagePrivate,true,'retain the reported config; do not invent a configuration change');
  assert.equal(state.findings[0].status,'open');assert.equal(state.findings[0].resolvedTick,undefined);
  assert.ok(state.findings[0].evidence.includes(regression.id));
  assert.equal(state.recommendations[0].applied,false);
  assert.equal(state.recommendations[0].validation,'pending');
  assert.equal(state.recommendations[0].validationEvent,undefined);
  assert.equal(state.recommendations[0].appliedTick,undefined);
  assert.match(state.agents.searcher.detail,/previously mitigated path succeeded again/i);
  assert.match(state.agents.builder.detail,/Re-approval/);
  await f.runtime.applyRecommendation(id);await f.runtime.runScenario('exposed-storage');
  state=f.runtime.snapshot();
  assert.equal(state.findings[0].status,'resolved');
  assert.equal(state.recommendations[0].validation,'blocked-replay');
  assert.notEqual(state.recommendations[0].validationEvent.id,regression.id);
});

test('detectors derive independent evidence from observations, not simulator attack labels',async()=>{
  const f=fixture();
  // Deliberately label the observed violation "normal"; behavior must still win.
  f.emit({kind:'normal',action:'list-objects'});
  for(let i=0;i<3;i++)f.emit({source:'attacker',target:'iam',action:'sign-in',outcome:'denied',principal:'lab-admin',authentication:'password',kind:'normal'});
  f.emit({source:'attacker',target:'iam',action:'sign-in',outcome:'allowed',principal:'lab-admin',authentication:'password',authenticated:true,kind:'normal'});
  f.emit({source:'app',target:'db',action:'admin-export',principal:'app-service',authenticated:true,kind:'normal'});
  await f.runtime.setMode('lab');
  let state=f.runtime.snapshot();
  assert.deepEqual(new Set(state.findings.map(item=>item.policyKey)),new Set(['storagePrivate','requireMfa','databaseLeastPrivilege']));
  const originalEvidence=structuredClone(state.findings.map(item=>item.evidenceDetails));
  for(let i=0;i<170;i++)f.emit({source:'app',target:'db',action:'read',principal:'app-service',authenticated:true,kind:'normal'});
  await f.runtime.tick();state=f.runtime.snapshot();
  assert.equal(state.events.length,160);
  assert.deepEqual(state.findings.map(item=>item.evidenceDetails),originalEvidence);
  await f.runtime.tick();assert.equal(f.runtime.real.snapshot().metrics.totalEvents,166,'repeated snapshots do not double-count');
});

test('a new executor generation clears stale findings and safely reuses event sequence IDs',async()=>{
  const f=fixture();await f.runtime.setMode('lab');await f.runtime.runScenario('exposed-storage');
  assert.equal(f.runtime.snapshot().findings.length,1);
  await f.runtime.reset();
  assert.equal(f.runtime.snapshot().findings.length,0);assert.equal(f.runtime.snapshot().events.length,0);
  await f.runtime.runScenario('exposed-storage');
  assert.equal(f.runtime.snapshot().findings.length,1);assert.equal(f.runtime.snapshot().events[0].id,'remote-1');
  assert.equal(f.runtime.snapshot().metrics.totalEvents,1);
});

test('validated model attacker choice uses only the catalog and receives a restricted view',async()=>{
  let received;
  const f=fixture({aiResult:(agent,context)=>{received=context;return modelResult(agent,{scenarioId:'exposed-storage'});}});
  await f.runtime.setMode('lab');await f.runtime.runAI('attacker');
  assert.equal(f.runtime.snapshot().ai.runs[0].mode,'model');
  assert.equal(received.policies,undefined);assert.equal(received.events,undefined);assert.equal(received.findings,undefined);
  assert.deepEqual(f.calls.find(call=>call.url.endsWith('/scenario')).body,{id:'exposed-storage'});
  assert.ok(f.calls.every(call=>['executor','attacker'].includes(new URL(call.url).hostname)));
});

test('Builder model analysis never applies its offered recommendation automatically',async()=>{
  const f=fixture({aiResult:(agent,context)=>modelResult(agent,{recommendationIds:context.recommendations.map(item=>item.id)})});
  await f.runtime.setMode('lab');await f.runtime.runScenario('exposed-storage');
  await f.runtime.runAI('builder');
  assert.equal(f.runtime.snapshot().ai.runs[0].mode,'model');
  assert.equal(f.runtime.snapshot().recommendations[0].applied,false);
  assert.equal(f.calls.some(call=>call.url.endsWith('/policy')),false);
});

test('unavailable agent workers retain an explicit fallback result',async()=>{
  const f=fixture();await f.runtime.runAI('searcher');
  assert.equal(f.runtime.snapshot().ai.runs[0].mode,'fallback');
  assert.match(f.runtime.snapshot().ai.detail,/fallback/i);
});

test('controller revalidates remote role metadata and rejects invented action IDs',async()=>{
  for(const result of [modelResult('builder'),modelResult('attacker',{scenarioId:'outside-url'}),modelResult('attacker',{provider:'unknown'})]){
    const f=fixture({aiResult:result});await f.runtime.runAI('attacker');
    const state=f.runtime.snapshot();
    assert.equal(state.ai.runs[0].mode,'fallback');
    assert.equal(state.activeScenario.id,'exposed-storage');
  }
});

test('a pending telemetry read is shared and completes before any state mutation',async()=>{
  const f=fixture();await f.runtime.setMode('lab');
  const transport=f.runtime.fetch;
  const oldState=structuredClone(f.remote());
  let releaseRead, delayedReads=0;
  f.runtime.fetch=async(url,options)=>{
    if(url.endsWith('/state')){
      delayedReads++;
      return new Promise(resolve=>{releaseRead=()=>resolve(Response.json(oldState));});
    }
    return transport(url,options);
  };
  const firstRead=f.runtime.tick();
  const sharedRead=f.runtime.sync();
  const operation=f.runtime.runScenario('exposed-storage');
  await f.runtime.tick(); // Busy state must suppress another periodic read.
  assert.equal(delayedReads,1,'both observers reuse one pending read');
  assert.equal(f.calls.some(call=>call.url.endsWith('/scenario')),false,'mutation must wait for the older read');
  releaseRead();
  const [, , completed]=await Promise.all([firstRead,sharedRead,operation]);
  assert.equal(completed.activeScenario,null,'completed action must not expose phantom busy state');
  assert.equal(completed.metrics.totalEvents,1);
  assert.equal(completed.findings.length,1);
  assert.equal(f.runtime.snapshot().events.length,1,'older telemetry cannot overwrite the mutation result');
  assert.equal(f.runtime.busy,false);
});

test('mode transitions own the operation lock while checking containment',async()=>{
  const f=fixture();
  let releaseRead;
  f.runtime.fetch=async()=>new Promise(resolve=>{releaseRead=()=>resolve(Response.json(f.remote()));});
  const transition=f.runtime.setMode('lab');
  await assert.rejects(()=>f.runtime.runScenario('exposed-storage'),/operation|progress/i);
  await assert.rejects(()=>f.runtime.setMode('simulation'),/operation|finish/i);
  releaseRead();
  const state=await transition;
  assert.equal(state.runtime.mode,'lab');assert.equal(state.activeScenario,null);assert.equal(f.runtime.busy,false);
});

test('ingested telemetry and returned active scenarios are defensively copied',async()=>{
  const f=fixture();await f.runtime.setMode('lab');
  f.remote().activeScenario={id:'exposed-storage',name:'Storage',step:1,total:2};
  f.emit({});f.runtime.ingest(f.remote());
  const state=f.runtime.snapshot();
  state.activeScenario.step=999;state.events[0].detail='changed';state.metrics.totalEvents=999;
  f.remote().activeScenario.step=88;
  f.remote().events[0].detail='original object changed after ingestion';
  const actual=f.runtime.snapshot();
  assert.equal(actual.activeScenario.step,1);assert.equal(actual.metrics.totalEvents,1);
  assert.equal(actual.events[0].detail,'Observed fixture service response.');
});
