import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const PROJECT='vortexai';
export const EXPECTED={
  dashboard:['frontend','control'],executor:['control','targets'],
  gateway:['targets'],lb:['targets'],app:['targets'],storage:['targets'],iam:['targets'],db:['targets'],
  attacker:['control','inference'],searcher:['control','inference'],builder:['control','inference'],
  'model-broker':['inference','model_egress']
};
const COMMANDS={dashboard:['node','server.mjs'],executor:['node','lab/executor.mjs'],'model-broker':['node','ai/broker.mjs']};
const ISOLATED={control:'172.30.40.0/24',targets:'172.30.41.0/24',inference:'172.30.42.0/24'};
const assert=(condition,message)=>{if(!condition)throw new Error(message);};
const same=(a,b)=>JSON.stringify([...a].sort())===JSON.stringify([...b].sort());

/** Validate actual Docker inspect objects, never a declarative Compose file.
 * Error messages name only the failing field, never environment values. */
export function validateInspection(container,networks) {
  const labels=container.Config?.Labels || {},role=labels['com.docker.compose.service'];
  assert(Object.hasOwn(EXPECTED,role),'Unexpected service in the lab project.');
  assert(labels['com.docker.compose.project']===PROJECT,`${role}: wrong Compose project.`);
  assert(container.State?.Running===true && container.State?.Health?.Status==='healthy',`${role}: service must be running and healthy.`);
  assert(container.Config.User==='1000:1000',`${role}: expected the unprivileged 1000:1000 identity.`);
  const host=container.HostConfig || {};
  assert(host.ReadonlyRootfs===true && host.Privileged===false,`${role}: read-only and unprivileged execution is required.`);
  assert((host.CapDrop || []).includes('ALL') && !(host.CapAdd || []).length,`${role}: all Linux capabilities must be dropped.`);
  assert((host.SecurityOpt || []).some(value=>value==='no-new-privileges' || value==='no-new-privileges:true'),`${role}: privilege escalation must be disabled.`);
  assert(!['host'].includes(host.NetworkMode) && !String(host.NetworkMode).startsWith('container:'),`${role}: host/shared networking is forbidden.`);
  assert(!['host'].includes(host.PidMode) && !['host'].includes(host.IpcMode),`${role}: host PID/IPC namespaces are forbidden.`);
  assert(!(host.Binds || []).length && !(container.Mounts || []).some(mount=>mount.Type!=='tmpfs'),`${role}: host folders, sockets and persistent mounts are forbidden.`);
  assert(!(host.Devices || []).length && !(host.DeviceRequests || []).length,`${role}: host devices are forbidden.`);
  assert(Number(host.PidsLimit)>0 && Number(host.PidsLimit)<=100,`${role}: PID limit is missing or excessive.`);
  assert(Number(host.Memory)>0 && Number(host.Memory)<=512*1024*1024,`${role}: memory limit is missing or excessive.`);
  assert(Number(host.NanoCpus)>0 && Number(host.NanoCpus)<=1e9,`${role}: CPU limit is missing or excessive.`);
  assert(host.Sysctls?.['net.ipv4.ip_forward']==='0' && host.Sysctls?.['net.ipv6.conf.all.disable_ipv6']==='1',`${role}: forwarding or IPv6 settings are unsafe.`);
  const tmp=host.Tmpfs?.['/tmp'] || '';
  assert(tmp.includes('noexec') && tmp.includes('nosuid'),`${role}: ephemeral storage must disable execution and setuid.`);
  const command=COMMANDS[role] || ['node',['attacker','searcher','builder'].includes(role)?'ai/agent-service.mjs':'lab/services.mjs'];
  assert(JSON.stringify(container.Config.Cmd)===JSON.stringify(command),`${role}: unexpected process command.`);
  const env=Object.fromEntries((container.Config.Env || []).map(value=>{const at=value.indexOf('=');return [value.slice(0,at),value.slice(at+1)];}));
  assert(env.VORTEX_CONTAINER==='1',`${role}: container execution guard missing.`);
  if(role==='executor')assert(env.CONTROL_BIND==='172.30.40.3' && env.CONTAINMENT_MARKER==='/tmp/containment-verified',`${role}: control listener or verification marker changed.`);
  if(role!=='model-broker')assert(!env.ANTHROPIC_API_KEY,`${role}: model API credential must exist only in the broker.`);
  if(['gateway','lb','app','storage','iam','db'].includes(role))assert(!env.LAB_EXECUTOR_TOKEN&&!env.AGENT_CONTROL_TOKEN&&!env.AGENT_BROKER_TOKEN,`${role}: target contains a control-plane credential.`);

  const bindings=host.PortBindings || {},published=container.NetworkSettings?.Ports || {};
  if(role==='dashboard') {
    assert(same(Object.keys(bindings),['4173/tcp']),`${role}: unexpected published ports.`);
    const ports=bindings['4173/tcp'];
    assert(ports?.length===1 && ports[0].HostIp==='127.0.0.1' && ports[0].HostPort==='4173',`${role}: dashboard must bind only to loopback port 4173.`);
    assert(Object.values(published).flat().filter(Boolean).every(port=>port.HostIp==='127.0.0.1'&&port.HostPort==='4173'),`${role}: unexpected live published port.`);
  } else assert(!Object.keys(bindings).length && !Object.values(published).flat().some(Boolean),`${role}: service ports must not be published.`);
  const attached=Object.keys(container.NetworkSettings?.Networks || {});
  assert(same(attached,EXPECTED[role].map(name=>`${PROJECT}_${name}`)),`${role}: network attachments differ from the approved topology.`);
  for(const name of EXPECTED[role]) {
    const network=networks.find(item=>item.Name===`${PROJECT}_${name}`);
    assert(network && network.Driver==='bridge' && network.EnableIPv6===false,`${role}: invalid bridge or IPv6 setting.`);
    assert(network.Labels?.['com.docker.compose.project']===PROJECT && network.Labels?.['com.docker.compose.network']===name,`${role}: network ownership mismatch.`);
    assert(network.Internal===(!['model_egress','frontend'].includes(name)),`${role}: unexpected external network access.`);
    if(Object.hasOwn(ISOLATED,name)) {
      assert(network.Options?.['com.docker.network.bridge.gateway_mode_ipv4']==='isolated',`${role}: host bridge gateway is not isolated.`);
      assert(network.IPAM?.Config?.length===1 && network.IPAM.Config[0].Subnet===ISOLATED[name],`${role}: isolated subnet changed.`);
    }
  }
  return role;
}

/** An extra peer could act as an internet relay even if all approved services
 * look correct. Reject unapproved containers attached to any lab bridge. */
export function validateNetworkMembers(containers,networks) {
  for(const network of networks) {
    const expected=containers.filter(container=>Object.hasOwn(container.NetworkSettings?.Networks || {},network.Name)).map(container=>container.Id);
    assert(same(Object.keys(network.Containers || {}),expected),`${network.Name}: unexpected or missing network peer.`);
  }
}

function docker(args) {
  const executable=process.env.DOCKER_BIN || 'docker';
  const result=spawnSync(executable,args,{cwd:ROOT,encoding:'utf8',timeout:45_000,windowsHide:true,maxBuffer:4*1024*1024});
  // CLI output can contain interpolated credentials; never forward it on error.
  if(result.error || result.status!==0)throw new Error('Docker command failed. Check Docker Desktop and the lab service health.');
  return result.stdout;
}
const compose=(...args)=>docker(['compose','--project-name',PROJECT,'-f','compose.yaml',...args]);
const removeMarker=()=>compose('exec','-T','executor','node','-e',"require('node:fs').rmSync('/tmp/containment-verified',{force:true})");

export function verifyLab() {
  // Re-verification invalidates earlier approval before examining live state.
  try{removeMarker();}catch{throw new Error('Could not revoke the previous verification marker. Stop the lab, restore Docker access, and retry.');}
  try {
    const version=docker(['version','--format','{{.Server.Version}}']).trim();
    assert(Number(version.split('.')[0])>=28,'Docker Engine 28 or newer is required for isolated bridge gateways.');
    const ids=compose('ps','--all','--quiet').trim().split(/\s+/).filter(Boolean);
    assert(ids.length===Object.keys(EXPECTED).length,'Start exactly the approved lab services before verification.');
    const containers=JSON.parse(docker(['inspect',...ids]));
    const networkNames=[...new Set(Object.values(EXPECTED).flat())].map(name=>`${PROJECT}_${name}`);
    const networks=JSON.parse(docker(['network','inspect',...networkNames]));
    const roles=containers.map(container=>validateInspection(container,networks));
    assert(same(roles,Object.keys(EXPECTED)),'Lab services are missing or duplicated.');
    validateNetworkMembers(containers,networks);
    for(const role of roles.filter(role=>!['dashboard','model-broker'].includes(role))) {
      const result=JSON.parse(compose('exec','-T',role,'node','lab/network-probe.mjs',role));
      assert(result.passed===true && result.role===role,`${role}: namespace probe did not pass.`);
      console.log(`Verified confined network: ${role}`);
    }
    compose('exec','-T','executor','node','-e',"require('node:fs').writeFileSync('/tmp/containment-verified','verified',{mode:0o600})");
    console.log('Containment verified. Real lab traffic is enabled until the executor container is recreated.');
    return true;
  } catch(error) {
    try{removeMarker();}catch{throw new Error('Verification failed and marker revocation could not be confirmed. Stop the lab before proceeding.');}
    throw error;
  }
}

if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  try{verifyLab();}catch(error){console.error(`Containment was not approved: ${error.message}`);process.exitCode=1;}
}
