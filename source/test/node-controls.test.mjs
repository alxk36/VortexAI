import test from 'node:test';
import assert from 'node:assert/strict';
import {Simulation} from '../src/simulation.mjs';
import {sharedFindings} from '../src/findings.mjs';
test('paused and quarantined nodes stop downstream work and reject affected scenarios',()=>{
  for(const settings of [['paused','normal'],['active','quarantine']]) {
    const sim=new Simulation();sim.updateNode('app',...settings);sim.tick();
    const state=sim.snapshot();assert.equal(state.events[0].target,'app');assert.equal(state.events[0].outcome,'denied');
    assert.ok(!state.events.some(e=>['db','storage'].includes(e.target)));
    assert.throws(()=>sim.runScenario('lateral-movement'),/Restore/);
    sim.updateNode('app','active','normal');sim.runScenario('lateral-movement');
    assert.throws(()=>sim.updateNode('app','paused','normal'),/Finish/);
  }
});
test('node observation and reset are explicit and bounded',()=>{
  const sim=new Simulation();sim.updateNode('gateway','active','observe');sim.tick();
  assert.ok(sim.snapshot().events.some(e=>e.detail.includes('Enhanced observation')));
  assert.throws(()=>sim.updateNode('__proto__','active','normal'),/Unknown/);
  assert.throws(()=>sim.updateNode('app','active','execute'),/Invalid/);
  sim.reset();assert.ok(sim.snapshot().nodes.every(n=>n.status==='active'&&n.action==='normal'));
});
test('shared finding export keeps observed and attacker evidence separate',()=>{
  const sim=new Simulation();sim.runScenario('exposed-storage');for(let i=0;i<3;i++)sim.tick();
  const records=sharedFindings(sim.snapshot(),'test-env');
  assert.ok(records.some(f=>f.source==='searcher'&&f.exploited===null));
  assert.ok(records.some(f=>f.source==='attacker'&&f.exploited===true));
  assert.ok(records.every(f=>f.technique==='public_bucket'&&f.resource_id==='storage'&&f.env_id==='test-env'));
});
