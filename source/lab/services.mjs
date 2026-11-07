import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { authorized, createJsonServer, createLabTransport, requireContainer, strictObject, tokenMatches } from './http.mjs';

export const ROLES = ['gateway','lb','app','storage','iam','db'];
// Public fixture credentials intentionally exercise weak demo paths. Real
// service/control tokens are generated separately and supplied via environment.
export const DEMO_PASSWORD = 'vortex-disposable-demo-password';
export const DEMO_APP_TOKEN = 'vortex-disposable-app-user';
const POLICY_ROLES = {storagePrivate:'storage', requireMfa:'iam', databaseLeastPrivilege:'db'};
const STATUS = (status, data={}) => ({status,body:{...data,events:data.events || []}});

/**
 * Purpose-built toy services, not an exploit runner. SQL executes only fixed,
 * parameterized statements against disposable SQLite data. Every emitted trace
 * corresponds to a handled request and its real authorization/result status.
 * The factory is injectable so tests need neither sockets nor exposed services.
 */
export function createService({role, controlToken, appToken, call=createLabTransport(), databasePath=':memory:'}={}) {
  if (!ROLES.includes(role)) throw new Error('Unknown lab service role.');
  if (typeof controlToken !== 'string' || controlToken.length < 24 || typeof appToken !== 'string' || appToken.length < 24) throw new Error('Lab service tokens must be configured.');
  const db = ['storage','db'].includes(role) ? new DatabaseSync(databasePath) : null;
  const sessions = new Map();
  let hardened = false;
  let nodeSettings = {status:'active',action:'normal'};
  // Reset restores fabricated rows, clears sessions, and removes hardening so
  // the same attack/fix/replay experiment can be repeated from a known baseline.
  const seed = () => {
    if (role === 'db') {
      db.exec('CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, name TEXT, segment TEXT); DELETE FROM customers;');
      const put = db.prepare('INSERT INTO customers (id,name,segment) VALUES (?,?,?)');
      put.run(1,'Demo Customer One','demo'); put.run(2,'Demo Customer Two','demo');
    }
    if (role === 'storage') {
      db.exec('CREATE TABLE IF NOT EXISTS objects (key TEXT PRIMARY KEY, body TEXT); DELETE FROM objects;');
      db.prepare('INSERT INTO objects VALUES (?,?)').run('demo-customers',JSON.stringify([{id:1,name:'Demo Customer One',classification:'fabricated'}]));
    }
    sessions.clear(); hardened=false;nodeSettings={status:'active',action:'normal'};
  };
  seed();
  const serviceAuth = headers => tokenMatches(headers['x-service-token'],appToken);
  const sourceFor = headers => ['client','attacker','gateway','lb','app'].includes(headers['x-lab-source']) ? headers['x-lab-source'] : 'attacker';

  async function handle({method='GET',path,headers={},body={}}) {
    headers = Object.fromEntries(Object.entries(headers).map(([k,v])=>[k.toLowerCase(),v]));
    if (method === 'GET' && path === '/health') return STATUS(200,{role,ready:true,...nodeSettings});
    // Management routes remain reachable when admission is paused/quarantined,
    // but require the separate control token before any state change.
    if (['/control/policy','/control/reset','/control/node'].includes(path)) {
      if (!authorized(headers,controlToken)) return STATUS(403,{error:'Control authorization required.'});
      if (method !== 'POST') return STATUS(405,{error:'POST required.'});
      if (path === '/control/reset') {
        if (!strictObject(body,[]) ) return STATUS(400,{error:'Unexpected reset fields.'});
        seed();return STATUS(200,{reset:true});
      }
      if(path==='/control/node') {
        if(!strictObject(body,['status','action']) || !['active','paused'].includes(body.status) || !['normal','observe','quarantine'].includes(body.action))return STATUS(400,{error:'Unsupported node admission setting.'});
        nodeSettings={status:body.status,action:body.action};
        return STATUS(200,{id:role,...nodeSettings});
      }
      if (!strictObject(body,['key','value']) || POLICY_ROLES[body.key] !== role || body.value !== true) return STATUS(400,{error:'Unsupported policy change.'});
      hardened=true; return STATUS(200,{key:body.key,value:true});
    }
    const source=sourceFor(headers);
    // Preserve downstream traces while adding this service's observed result;
    // the executor later removes bodies and assigns global event identifiers.
    const trace=(status,action,detail,fields={},data={})=>{
      const result=STATUS(status,data);
      const event={source,target:role,protocol:'HTTP',action,outcome:status<400?'allowed':'denied',httpStatus:status,bytes:Buffer.byteLength(JSON.stringify(data)),detail:nodeSettings.action==='observe'?`${detail} Observation mode: request explicitly monitored.`:detail,authenticated:false,principal:'anonymous',...fields};
      result.body.events=[event,...(data.events || [])];
      return result;
    };
    // These are application admission controls, never Docker process controls.
    // The service stays healthy and its authenticated control routes stay usable.
    // No policy key is attached: service interruption is not proof of remediation.
    if(nodeSettings.status==='paused' || nodeSettings.action==='quarantine') {
      const status=nodeSettings.status==='paused'?503:403;
      return trace(status,'blocked-service',nodeSettings.status==='paused'?'Service admission is paused by the administrator.':'Service admission is quarantined by the administrator.',{},{error:'Service admission is disabled.'});
    }
    const forward=async(target,targetPath,{action='request',extraHeaders={},fields={}}={})=>{
      try {
        const result=await call(target,{method,path:targetPath,headers:{...headers,'x-lab-source':role,...extraHeaders},...(method==='POST'?{body}:{})});
        return trace(result.status,action,`${role} forwarded the lab request to ${target}.`,fields,result.body);
      } catch { return trace(503,action,`${target} is unavailable; no successful operation is inferred.`,fields,{error:'Downstream lab service unavailable.'}); }
    };
    if (['gateway','lb'].includes(role) && method==='GET' && ['/data/db','/data/storage','/export','/admin'].includes(path)) {
      return forward(role==='gateway'?'lb':'app',path,{action:path==='/export'?'token-replay':'request'});
    }
    if (role==='app' && method==='GET' && ['/data/db','/data/storage'].includes(path)) {
      return forward(path==='/data/db'?'db':'storage',path==='/data/db'?'/records':'/objects',{
        extraHeaders:{'x-service-token':appToken}, fields:{principal:'application-user',authenticated:true}
      });
    }
    if (role==='app' && method==='GET' && path==='/export') {
      if (headers.authorization!==`Bearer ${DEMO_APP_TOKEN}`) return trace(401,'application-request','A disposable application-user token is required.');
      // Deliberately insecure business-logic endpoint: a low-privilege account
      // can invoke the service's export permission. No code execution is involved.
      return forward('db','/export',{action:'application-request',extraHeaders:{'x-service-token':appToken},fields:{principal:'app-user',authenticated:true}});
    }
    if (role==='app' && method==='GET' && path==='/admin') {
      let checked;
      try { checked=await call('iam',{path:'/session',headers:{authorization:headers.authorization || '', 'x-lab-source':'app'}}); }
      catch { return trace(503,'admin-request','Identity service unavailable.'); }
      return trace(checked.status,'admin-request',checked.status===200?'The issued lab session authorizes this admin page.':'No valid lab administrator session.',{principal:'lab-admin',authenticated:checked.status===200},{admin:checked.status===200,events:checked.body.events});
    }
    if (role==='storage' && method==='GET' && ['/objects','/objects/demo-customers'].includes(path)) {
      const authenticated=serviceAuth(headers), allow=authenticated || !hardened;
      const data=allow ? (path==='/objects' ? {objects:db.prepare('SELECT key FROM objects ORDER BY key').all()} : {object:JSON.parse(db.prepare('SELECT body FROM objects WHERE key=?').get('demo-customers').body)}) : {error:'Anonymous object access denied.'};
      return trace(allow?200:403,path==='/objects'?'list-objects':'read-object',allow?'Object operation completed against the lab SQLite object store.':'Private storage policy rejected anonymous access.',{principal:authenticated?'app-service':'anonymous',authenticated,control:'storagePrivate'},data);
    }
    if (role==='db' && method==='GET' && ['/records','/export'].includes(path)) {
      const authenticated=serviceAuth(headers), allowed=authenticated && (path!=='/export' || !hardened);
      const rows=allowed?db.prepare('SELECT id,name,segment FROM customers ORDER BY id').all():undefined;
      return trace(allowed?200:403,path==='/export'?'admin-export':'read',allowed?'Fixed SQL query returned disposable demo rows.':'Database role rejected the requested operation.',{principal:authenticated?'app-service':'anonymous',authenticated,...(path==='/export'?{control:'databaseLeastPrivilege'}:{})},allowed?{rows}:{error:'Database operation denied.'});
    }
    if (role==='iam' && method==='POST' && path==='/login') {
      if (!strictObject(body,['username','password','secondFactor']) || typeof body.username!=='string' || typeof body.password!=='string') return STATUS(400,{error:'Invalid login fields.'});
      const passwordValid=body.username==='lab-admin' && body.password===DEMO_PASSWORD;
      // A fixed teaching factor gates new sessions only; this is not real MFA
      // enrollment, and enabling it does not revoke already-issued sessions.
      const accepted=passwordValid && (!hardened || body.secondFactor==='246810');
      let session;
      if (accepted) {
        session=randomUUID();sessions.set(session,{principal:'lab-admin',expires:Date.now()+60_000});
        while(sessions.size>32) sessions.delete(sessions.keys().next().value);
      }
      return trace(accepted?200:401,'sign-in',accepted?'The identity service issued a disposable administrator session.':passwordValid?'The configured demonstration second factor is required.':'The identity service rejected the credentials.',{principal:'lab-admin',authentication:body.secondFactor?'password+demo-factor':'password',authenticated:accepted,...(passwordValid?{control:'requireMfa'}:{})},accepted?{session}:{error:'Sign-in denied.'});
    }
    if (role==='iam' && method==='GET' && path==='/session') {
      const session=sessions.get((headers.authorization || '').replace(/^Bearer /,''));
      const accepted=Boolean(session && session.expires>Date.now());
      return trace(accepted?200:401,'validate-session','The identity service checked a short-lived lab session.',{principal:'lab-admin',authenticated:accepted},{valid:accepted});
    }
    return STATUS(404,{error:'Operation is not in this service catalog.'});
  }
  return {handle,close:()=>db?.close(),getPolicy:()=>hardened};
}

if (process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  requireContainer();
  const service=createService({role:process.env.SERVICE_ROLE, controlToken:process.env.LAB_CONTROL_TOKEN,appToken:process.env.LAB_APP_TOKEN,databasePath:['db','storage'].includes(process.env.SERVICE_ROLE)?'/tmp/lab.sqlite':':memory:'});
  const server=createJsonServer(service.handle);
  server.listen(8080,'0.0.0.0');
  for(const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>server.close(()=>service.close()));
}
