import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createService, DEMO_PASSWORD } from '../lab/services.mjs';
import { LabExecutor } from '../lab/executor.mjs';
import { createLabTransport } from '../lab/http.mjs';

const controlToken='test-control-0123456789-abcdef';
const executorToken='test-executor-0123456789-abcdef';
const appToken='test-application-0123456789-abcdef';
function lab(t,{contained=true}={}) {
  const services={};
  // In-process dispatch exercises real SQLite/service handlers without exposing
  // a vulnerable target listener on the host computer during tests.
  const call=async(role,request)=>services[role].handle(request);
  for(const role of ['gateway','lb','app','storage','iam','db']) services[role]=createService({role,controlToken,appToken,call});
  t.after(()=>Object.values(services).forEach(s=>s.close()));
  return {services,executor:new LabExecutor({call,controlToken,executorToken,isContained:()=>contained})};
}
test('real handlers complete the gateway/application/SQLite path without host sockets',async t=>{
  const {executor}=lab(t);await executor.normalTick();await executor.normalTick();
  const state=executor.snapshot();
  assert.equal(state.metrics.attackEvents,0);
  assert.equal(state.metrics.blockedEvents,0);
  assert.deepEqual(new Set(state.events.map(e=>e.target)),new Set(['gateway','lb','app','db','storage']));
  assert.ok(state.events.every(e=>e.httpStatus===200&&e.protocol==='HTTP'));
});
for(const [id,key,target,action] of [
  ['exposed-storage','storagePrivate','storage','read-object'],
  ['credential-abuse','requireMfa','iam','sign-in'],
  ['lateral-movement','databaseLeastPrivilege','db','admin-export']
]) test(`${id}: real handler permission changes block the same request`,async t=>{
  const {executor}=lab(t);
  await executor.runScenario(id);
  assert.ok(executor.snapshot().events.some(e=>e.target===target&&e.action===action&&e.outcome==='allowed'));
  await executor.applyPolicy(key);
  const sequence=executor.sequence;
  await executor.runScenario(id);
  const newer=executor.snapshot().events.filter(e=>Number(e.id.split('-').at(-1))>sequence);
  assert.ok(newer.some(e=>e.target===target&&e.action===action&&e.outcome==='denied'&&e.control===key));
  assert.ok(!newer.some(e=>e.target===target&&e.action===action&&e.outcome==='allowed'));
  await executor.normalTick();
  assert.equal(executor.snapshot().events[0].outcome,'allowed');
});
test('MFA demo creates actual expiring sessions and does not revoke existing ones',async t=>{
  const {services}=lab(t);
  const login=await services.iam.handle({method:'POST',path:'/login',body:{username:'lab-admin',password:DEMO_PASSWORD}});
  assert.equal(login.status,200);assert.equal(typeof login.body.session,'string');
  await services.iam.handle({method:'POST',path:'/control/policy',headers:{authorization:`Bearer ${controlToken}`},body:{key:'requireMfa',value:true}});
  const replay=await services.iam.handle({method:'POST',path:'/login',body:{username:'lab-admin',password:DEMO_PASSWORD}});
  assert.equal(replay.status,401);
  const session=await services.iam.handle({path:'/session',headers:{authorization:`Bearer ${login.body.session}`}});
  assert.equal(session.status,200);
  const secondFactor=await services.iam.handle({method:'POST',path:'/login',body:{username:'lab-admin',password:DEMO_PASSWORD,secondFactor:'246810'}});
  assert.equal(secondFactor.status,200);
});
test('no traffic or policy operation starts before containment verification',async t=>{
  const {executor}=lab(t,{contained:false});
  await executor.normalTick();assert.equal(executor.snapshot().events.length,0);
  await assert.rejects(executor.runScenario('exposed-storage'),/lab:verify/);
  await assert.rejects(executor.applyPolicy('storagePrivate'),/lab:verify/);
  assert.equal(executor.snapshot().containmentVerified,false);
});
test('executor and service management tokens are distinct and all commands are allowlisted',async t=>{
  const {executor,services}=lab(t);
  assert.equal((await executor.handle({path:'/state',headers:{authorization:`Bearer ${controlToken}`}})).status,403);
  assert.equal((await services.storage.handle({method:'POST',path:'/control/policy',headers:{authorization:`Bearer ${executorToken}`},body:{key:'storagePrivate',value:true}})).status,403);
  assert.equal((await executor.handle({method:'POST',path:'/scenario',headers:{authorization:`Bearer ${executorToken}`},body:{id:'exposed-storage',url:'https://example.com'}})).status,400);
  assert.equal((await services.db.handle({path:'/records?sql=DROP%20TABLE'})).status,404);
  await assert.rejects(executor.runScenario('external-scan'),/Unknown/);
  await assert.rejects(createLabTransport()('example.com',{path:'/objects'}),/outside/);
  await assert.rejects(createLabTransport()('storage',{path:'https://example.com'}),/outside/);
});
test('pause, reset, bounded telemetry and policy state are observable',async t=>{
  const {executor}=lab(t);const headers={authorization:`Bearer ${executorToken}`};
  await executor.runScenario('exposed-storage');await executor.applyPolicy('storagePrivate');
  await executor.handle({method:'POST',path:'/running',headers,body:{running:false}});
  const before=executor.snapshot();await executor.normalTick();assert.deepEqual(executor.snapshot(),before);
  await assert.rejects(executor.runScenario('credential-abuse'),/Resume/);
  await executor.handle({method:'POST',path:'/running',headers,body:{running:true}});
  for(let i=0;i<60;i++)await executor.normalTick();
  assert.equal(executor.snapshot().events.length,160);
  await executor.reset();assert.equal(executor.snapshot().events.length,0);
  assert.notEqual(executor.snapshot().generation,before.generation);
  assert.equal(executor.snapshot().policies.storagePrivate,false);
  assert.equal(executor.snapshot().containmentVerified,true);
});
test('real service pause and quarantine reject traffic while health and controls remain available',async t=>{
  const {executor,services}=lab(t);
  await executor.updateNode({id:'gateway',status:'paused',action:'normal'});
  await executor.normalTick();
  let state=executor.snapshot();
  assert.equal(state.events[0].httpStatus,503);
  assert.equal(state.events[0].action,'blocked-service');
  assert.equal(state.events[0].control,undefined);
  assert.equal(state.events.length,1,'paused gateway must not forward downstream');
  assert.equal((await services.gateway.handle({path:'/health'})).status,200);
  assert.deepEqual(state.nodeSettings.gateway,{status:'paused',action:'normal'});

  await executor.updateNode({id:'gateway',status:'active',action:'normal'});
  await executor.updateNode({id:'app',status:'active',action:'quarantine'});
  const sequence=executor.sequence;
  await executor.normalTick();
  const blocked=executor.snapshot().events.filter(event=>Number(event.id.split('-').at(-1))>sequence);
  assert.ok(blocked.some(event=>event.target==='app'&&event.action==='blocked-service'&&event.httpStatus===403));
  assert.ok(!blocked.some(event=>['storage','db'].includes(event.target)));
  assert.ok(blocked.every(event=>event.control===undefined),'quarantine must not validate a security policy');
  assert.equal((await services.app.handle({path:'/health'})).status,200);

  await executor.updateNode({id:'app',status:'active',action:'observe'});
  await executor.normalTick();
  state=executor.snapshot();
  assert.equal(state.events[0].outcome,'allowed');
  assert.ok(state.events.some(event=>event.target==='app'&&event.detail.includes('Observation mode')));
  assert.deepEqual(state.policies,{storagePrivate:false,requireMfa:false,databaseLeastPrivilege:false});
  await executor.reset();
  assert.deepEqual(executor.snapshot().nodeSettings.app,{status:'active',action:'normal'});
});
test('node control commands reject unknown fields, values, targets and unauthorized requests',async t=>{
  const {executor,services}=lab(t);const headers={authorization:`Bearer ${executorToken}`};
  for(const body of [
    {id:'client',status:'paused',action:'normal'},
    {id:'app',status:'stopped',action:'normal'},
    {id:'app',status:'active',action:'execute'},
    {id:'app',status:'active',action:'normal',command:'shell'}
  ])assert.equal((await executor.handle({method:'POST',path:'/node',headers,body})).status,400);
  assert.equal((await services.app.handle({method:'POST',path:'/control/node',headers,body:{status:'active',action:'normal'}})).status,403);
  assert.equal((await services.app.handle({method:'POST',path:'/control/node',headers:{authorization:`Bearer ${controlToken}`},body:{status:'active',action:'normal',url:'https://example.com'}})).status,400);
  assert.deepEqual(executor.snapshot().nodeSettings.app,{status:'active',action:'normal'});
});
test('node controls cannot interrupt an active scenario',async t=>{
  const {executor}=lab(t);const dispatch=executor.call;
  let release;
  executor.call=async(service,options)=>{
    if(options.path==='/objects')await new Promise(resolve=>{release=resolve;});
    return dispatch(service,options);
  };
  const scenario=executor.runScenario('exposed-storage');
  assert.ok(executor.snapshot().activeScenario);
  await assert.rejects(executor.updateNode({id:'storage',status:'paused',action:'normal'}),/operation is in progress/);
  release();await scenario;
  assert.deepEqual(executor.snapshot().nodeSettings.storage,{status:'active',action:'normal'});
});
