import { readFile } from 'node:fs/promises';
import net from 'node:net';
import dns from 'node:dns/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const TARGETS=['gateway','lb','app','storage','iam','db'];
const AGENTS=['attacker','searcher','builder'];

/** A refused TCP connection alone is not proof of isolation. The host verifier
 * also inspects bridge mode/attachments, while this probe requires absent
 * default routes, disabled IPv6, and successful communication within the lab. */
export function checkRoutes(ipv4,ipv6,disableIpv6) {
  for(const row of ipv4.trim().split('\n').slice(1)) {
    const fields=row.trim().split(/\s+/);
    if(fields[1]==='00000000' && fields[7]==='00000000' && (parseInt(fields[3],16)&1)) throw new Error('An IPv4 default route is present.');
  }
  for(const row of ipv6.trim().split('\n')) {
    const fields=row.trim().split(/\s+/), flags=parseInt(fields[8],16);
    if(fields[0]==='0'.repeat(32) && fields[1]==='00' && (flags&1) && !(flags&0x200)) throw new Error('An active IPv6 default route is present.');
  }
  if(disableIpv6.trim()!=='1')throw new Error('IPv6 must be disabled in the confined namespace.');
}

function canConnect(host,port) {
  return new Promise(resolveConnection=>{
    const socket=net.createConnection({host,port});
    let settled=false;
    const finish=value=>{if(!settled){settled=true;socket.destroy();resolveConnection(value);}};
    socket.setTimeout(700,()=>finish(false));
    socket.once('connect',()=>finish(true));socket.once('error',()=>finish(false));
  });
}

export async function probeNamespace(role) {
  if(![...TARGETS,...AGENTS,'executor'].includes(role))throw new Error('Unknown confined role.');
  const [ipv4,ipv6,disabled]=await Promise.all([
    readFile('/proc/net/route','utf8'),readFile('/proc/net/ipv6_route','utf8'),readFile('/proc/sys/net/ipv6/conf/all/disable_ipv6','utf8')
  ]);
  checkRoutes(ipv4,ipv6,disabled);
  const positive=AGENTS.includes(role)?'http://model-broker:8080/health':'http://storage:8080/health';
  const response=await fetch(positive,{redirect:'error',signal:AbortSignal.timeout(2000)});
  if(!response.ok)throw new Error('The positive internal-network check failed.');
  await response.body?.cancel();

  // Only fixed representative egress destinations are attempted; this is not a
  // host or network scan. Every socket is closed within 700 ms.
  const checks=[['1.1.1.1',443],['169.254.169.254',80]];
  for(const host of ['172.30.40.1','172.30.41.1','172.30.42.1'])for(const port of [80,443,2375])checks.push([host,port]);
  let hostAddresses=[];
  try{hostAddresses=(await dns.lookup('host.docker.internal',{all:true})).map(item=>item.address);}catch{}
  for(const host of [...new Set(hostAddresses)].slice(0,4))for(const port of [80,443,2375])checks.push([host,port]);
  const reachable=await Promise.all(checks.map(async([host,port])=>({host,port,reachable:await canConnect(host,port)})));
  if(reachable.some(check=>check.reachable))throw new Error('A forbidden external, metadata, or host endpoint is reachable.');
  return {role,internalReachability:true,defaultRoutes:false,ipv6Disabled:true,forbiddenConnections:reachable.length,passed:true};
}

if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  try{console.log(JSON.stringify(await probeNamespace(process.argv[2])));}
  catch(error){console.error(`Containment probe failed: ${error.message}`);process.exitCode=1;}
}
