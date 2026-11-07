// Run only via `docker compose exec -T dashboard node lab/smoke.mjs`.
// Uses the real services and their fixed scenario catalog, never host targets.
import assert from 'node:assert/strict';
import {Runtime} from '../src/runtime.mjs';
if(process.env.VORTEX_CONTAINER!=='1') throw new Error('Run this check inside the verified Docker dashboard.');
const runtime=new Runtime();
await runtime.setMode('lab');
const policyFor={'exposed-storage':'storagePrivate','credential-abuse':'requireMfa','lateral-movement':'databaseLeastPrivilege'};
for(const [scenario,key] of Object.entries(policyFor)) {
  await runtime.reset();
  await runtime.runScenario(scenario);
  let state=runtime.snapshot();
  const finding=state.findings.find(f=>f.policyKey===key);
  assert.ok(finding,`${scenario}: observed evidence must create a finding`);
  assert.ok(finding.evidenceDetails.every(e=>Number.isInteger(e.httpStatus)),'Only real HTTP observations are accepted');
  await runtime.applyRecommendation(finding.recommendationId);
  await runtime.runScenario(scenario);
  state=runtime.snapshot();
  assert.equal(state.recommendations.find(r=>r.id===finding.recommendationId).validation,'blocked-replay');
  assert.equal(state.metrics.openFindings,0);
  console.log(`${scenario}: real HTTP evidence, acknowledged fix, blocked replay PASS`);
}
// Worker/broker wiring is exercised without pretending fallback is paid inference.
for(const role of ['searcher','builder','attacker']) {
  await runtime.runAI(role);
  const result=runtime.snapshot().ai.runs[0];
  assert.equal(result.agent,role);assert.ok(['model','fallback'].includes(result.mode));
  assert.equal(result.model,'claude-opus-5-5');
  console.log(`${role}: independent worker result=${result.mode}`);
}
await runtime.reset();
await runtime.updateNode('storage','paused','observe');
assert.equal(runtime.snapshot().nodes.find(n=>n.id==='storage').status,'paused');
await runtime.runScenario('exposed-storage');
assert.ok(runtime.snapshot().events.some(e=>e.target==='storage'&&e.outcome==='denied'));
assert.equal(runtime.snapshot().findings.length,0,'Paused service is not an exploitable storage policy finding');
await runtime.updateNode('storage','active','normal');
await runtime.runScenario('exposed-storage');
assert.ok(runtime.snapshot().findings.some(f=>f.nodeId==='storage'));
console.log('Real node admission controls: pause, observe, restore PASS');
await runtime.reset();
await runtime.setRunning(false);
console.log('Real-service smoke check passed; lab reset and paused.');
