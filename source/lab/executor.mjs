import { existsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { authorized, createJsonServer, createLabTransport, requireContainer, strictObject } from './http.mjs';
import { DEMO_APP_TOKEN, DEMO_PASSWORD } from './services.mjs';

const SCENARIOS=['exposed-storage','credential-abuse','lateral-movement'];
const POLICY_ROLES={storagePrivate:'storage',requireMfa:'iam',databaseLeastPrivilege:'db'};
const ROLES=['gateway','lb','app','storage','iam','db'];

/**
 * A finite action executor. It accepts catalog IDs, never model-written code,
 * hostnames, shell commands, HTTP headers, SQL or URLs. Network containment is
 * verified outside this process; its tmpfs marker gates every traffic action.
 */
export class LabExecutor {
  constructor({call=createLabTransport(),controlToken,executorToken,isContained=()=>false}={}) {
    if (![controlToken,executorToken].every(token=>typeof token==='string' && token.length>=24)) throw new Error('Separate lab control and executor tokens are required.');
    if (controlToken===executorToken) throw new Error('Executor and service-control tokens must differ.');
    this.call=call;this.controlToken=controlToken;this.executorToken=executorToken;this.isContained=isContained;
    this.busy=false;this.generation=randomUUID();this.tickCount=0;this.sequence=0;this.events=[];
    this.policies={storagePrivate:false,requireMfa:false,databaseLeastPrivilege:false};
    this.nodeSettings=Object.fromEntries(ROLES.map(id=>[id,{status:'active',action:'normal'}]));
    this.running=true;this.activeScenario=null;
    this.metrics={totalEvents:0,attackEvents:0,blockedEvents:0,attackAttempts:0};
  }
  snapshot() {
    return structuredClone({generation:this.generation,tick:this.tickCount,events:this.events,policies:this.policies,nodeSettings:this.nodeSettings,running:this.running,activeScenario:this.activeScenario,metrics:this.metrics,containmentVerified:this.isContained()});
  }
  checkContainment() { if (!this.isContained()) throw new Error('Run npm run lab:verify before starting lab traffic.'); }
  // Serialize scenarios, policy changes, and baseline traffic to preserve which
  // configuration produced each observation; always release the lock on failure.
  async exclusive(action) {
    if(this.busy) throw new Error('A lab operation is in progress. Wait for it to finish.');
    this.busy=true;
    try{return await action();}finally{this.busy=false;}
  }
  // Export bounded scalar telemetry only, never target response bodies or tokens.
  // Generation-prefixed IDs prevent resets from colliding with earlier evidence.
  record(result,kind) {
    const observed=result.body?.events;
    if(!Array.isArray(observed) || observed.length>24) throw new Error('Invalid telemetry response from lab service.');
    this.tickCount++;
    for(const raw of observed) {
      // Allow only resource IDs and short scalar metadata out of the target lab.
      if (!['client','attacker',...ROLES].includes(raw.source) || !ROLES.includes(raw.target)) continue;
      const status=Number(raw.httpStatus),outcome=status>=200&&status<400?'allowed':'denied';
      const event={id:`lab-${this.generation}-${++this.sequence}`,tick:this.tickCount,time:new Date().toISOString(),source:raw.source,target:raw.target,protocol:'HTTP',action:String(raw.action||'request').slice(0,50),outcome,httpStatus:status,bytes:Number.isFinite(raw.bytes)?Math.max(0,Math.min(raw.bytes,256*1024)):0,detail:String(raw.detail||'').slice(0,400),principal:String(raw.principal||'anonymous').slice(0,50),authenticated:raw.authenticated===true,kind:outcome==='denied'?'blocked':kind};
      if (['password','password+demo-factor'].includes(raw.authentication)) event.authentication=raw.authentication;
      if(Object.hasOwn(POLICY_ROLES,raw.control)) event.control=raw.control;
      this.events.unshift(event);this.metrics.totalEvents++;
      if(event.kind==='attack')this.metrics.attackEvents++;
      if(event.kind==='blocked')this.metrics.blockedEvents++;
    }
    this.events.length=Math.min(this.events.length,160);
  }
  async request(service,options,kind='attack') {
    this.checkContainment();
    const result=await this.call(service,options);
    this.record(result,kind);return result;
  }
  // Ordinary app traffic is separate from scenario traffic and requires the
  // same live containment gate. It is skipped while a scenario owns the lock.
  async normalTick() {
    if(!this.running || this.busy || !this.isContained())return this.snapshot();
    return this.exclusive(async()=>{
      await this.request('gateway',{path:this.tickCount%2?'/data/db':'/data/storage',headers:{'x-lab-source':'client'}},'normal');
      return this.snapshot();
    });
  }
  async runScenario(id) {
    if(!SCENARIOS.includes(id))throw new Error('Unknown lab scenario.');
    if(!this.running)throw new Error('Resume the lab before running a scenario.');
    this.checkContainment();
    return this.exclusive(async()=>{
      this.metrics.attackAttempts++;
      this.activeScenario={id,step:0,total:id==='credential-abuse'?5:id==='exposed-storage'?2:1};
      // A deadline bounds the entire chain, not just each individual HTTP call.
      const signal=AbortSignal.timeout(4500);
      const step=async(service,options)=>{
        this.activeScenario.step++;
        return this.request(service,{...options,signal,headers:{'x-lab-source':'attacker',...options.headers}});
      };
      try {
        if(id==='exposed-storage') {
          await step('storage',{path:'/objects'});
          await step('storage',{path:'/objects/demo-customers'});
        } else if(id==='credential-abuse') {
          for(const password of ['incorrect-demo-1','incorrect-demo-2','incorrect-demo-3']) await step('iam',{method:'POST',path:'/login',body:{username:'lab-admin',password}});
          const login=await step('iam',{method:'POST',path:'/login',body:{username:'lab-admin',password:DEMO_PASSWORD}});
          await step('app',{path:'/admin',headers:{authorization:`Bearer ${login.status===200?login.body.session:'no-session'}`}});
        } else {
          await step('gateway',{path:'/export',headers:{authorization:`Bearer ${DEMO_APP_TOKEN}`}});
        }
      } finally {this.activeScenario=null;}
      return this.snapshot();
    });
  }
  // Update the local policy mirror only after the target acknowledges success.
  async applyPolicy(key) {
    if(!Object.hasOwn(POLICY_ROLES,key))throw new Error('Unsupported policy.');
    this.checkContainment();
    return this.exclusive(async()=>{
      const result=await this.call(POLICY_ROLES[key],{method:'POST',path:'/control/policy',headers:{authorization:`Bearer ${this.controlToken}`},body:{key,value:true}});
      if(result.status!==200 || result.body.value!==true)throw new Error('The real service did not confirm the policy update.');
      this.policies[key]=true;return this.snapshot();
    });
  }
  async updateNode({id,status,action}) {
    if(!ROLES.includes(id) || !['active','paused'].includes(status) || !['normal','observe','quarantine'].includes(action))throw new Error('Unsupported target or node admission setting.');
    this.checkContainment();
    return this.exclusive(async()=>{
      const result=await this.call(id,{method:'POST',path:'/control/node',headers:{authorization:`Bearer ${this.controlToken}`},body:{status,action}});
      if(result.status!==200 || result.body.id!==id || result.body.status!==status || result.body.action!==action)throw new Error('The real service did not confirm the admission setting.');
      this.nodeSettings[id]={status,action};return this.snapshot();
    });
  }
  // Reset all targets before discarding telemetry. A partial failure is reported
  // rather than claiming the whole lab returned to its initial configuration.
  async reset() {
    this.checkContainment();
    return this.exclusive(async()=>{
      for(const role of ROLES) {
        const result=await this.call(role,{method:'POST',path:'/control/reset',headers:{authorization:`Bearer ${this.controlToken}`},body:{}});
        if(result.status!==200)throw new Error('A lab service failed to reset. Restart the lab before continuing.');
      }
      this.policies={storagePrivate:false,requireMfa:false,databaseLeastPrivilege:false};
      this.nodeSettings=Object.fromEntries(ROLES.map(id=>[id,{status:'active',action:'normal'}]));
      this.generation=randomUUID();this.tickCount=0;this.sequence=0;this.events=[];this.running=true;this.activeScenario=null;
      this.metrics={totalEvents:0,attackEvents:0,blockedEvents:0,attackAttempts:0};return this.snapshot();
    });
  }
  async handle({method='GET',path,headers={},body={}}) {
    if(method==='GET' && path==='/health')return {status:200,body:{ready:true,containmentVerified:this.isContained()}};
    if(!authorized(headers,this.executorToken))return {status:403,body:{error:'Executor authorization required.'}};
    if(method==='GET' && path==='/state')return {status:200,body:this.snapshot()};
    if(method!=='POST')return {status:405,body:{error:'POST required.'}};
    try {
      if(path==='/scenario' && strictObject(body,['id']) && typeof body.id==='string') await this.runScenario(body.id);
      else if(path==='/policy' && strictObject(body,['key']) && typeof body.key==='string') await this.applyPolicy(body.key);
      else if(path==='/node' && strictObject(body,['id','status','action']))await this.updateNode(body);
      else if(path==='/reset' && strictObject(body,[]))await this.reset();
      else if(path==='/running' && strictObject(body,['running']) && typeof body.running==='boolean') {
        if(this.busy)throw new Error('Wait for the current lab operation to finish.');
        this.running=body.running;
      } else return {status:400,body:{error:'Invalid lab command.'}};
      return {status:200,body:this.snapshot()};
    } catch(error) {return {status:400,body:{error:error.message}};}
  }
}

if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  requireContainer();
  const executor=new LabExecutor({controlToken:process.env.LAB_CONTROL_TOKEN,executorToken:process.env.LAB_EXECUTOR_TOKEN,isContained:()=>existsSync(process.env.CONTAINMENT_MARKER || '/tmp/containment-verified')});
  const server=createJsonServer(input=>executor.handle(input));
  const interval=setInterval(()=>executor.normalTick().catch(()=>{}),1500).unref();
  server.on('close',()=>clearInterval(interval));
  server.listen(8080,process.env.CONTROL_BIND || '0.0.0.0');
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close());
}
