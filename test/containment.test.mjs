import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EXPECTED,validateInspection,validateNetworkMembers } from '../scripts/lab-verify.mjs';
import { checkRoutes } from '../lab/network-probe.mjs';

const isolated={control:'172.30.40.0/24',targets:'172.30.41.0/24',inference:'172.30.42.0/24'};
function fixtures(role='storage') {
  const names=[...new Set(Object.values(EXPECTED).flat())];
  const networks=names.map(name=>({Name:`vortexai_${name}`,Driver:'bridge',EnableIPv6:false,Internal:!['model_egress','frontend'].includes(name),Labels:{'com.docker.compose.project':'vortexai','com.docker.compose.network':name},Options:isolated[name]?{'com.docker.network.bridge.gateway_mode_ipv4':'isolated'}:{},IPAM:{Config:isolated[name]?[{Subnet:isolated[name]}]:[]}}));
  const commands={dashboard:['node','server.mjs'],executor:['node','lab/executor.mjs'],'model-broker':['node','ai/broker.mjs']};
  const container={
    Config:{User:'1000:1000',Labels:{'com.docker.compose.project':'vortexai','com.docker.compose.service':role},Cmd:commands[role]||['node',['attacker','searcher','builder'].includes(role)?'ai/agent-service.mjs':'lab/services.mjs'],Env:['VORTEX_CONTAINER=1',...(role==='executor'?['CONTROL_BIND=172.30.40.3','CONTAINMENT_MARKER=/tmp/containment-verified']:[])]},
    State:{Running:true,Health:{Status:'healthy'}},
    HostConfig:{ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],CapAdd:null,SecurityOpt:['no-new-privileges:true'],NetworkMode:'vortexai_targets',PidMode:'',IpcMode:'private',Binds:null,Devices:[],DeviceRequests:null,PidsLimit:80,Memory:256*1024*1024,NanoCpus:500000000,Sysctls:{'net.ipv4.ip_forward':'0','net.ipv6.conf.all.disable_ipv6':'1'},Tmpfs:{'/tmp':'rw,noexec,nosuid,size=32m'},PortBindings:role==='dashboard'?{'4173/tcp':[{HostIp:'127.0.0.1',HostPort:'4173'}]}:{}},
    Mounts:[],NetworkSettings:{Ports:role==='dashboard'?{'4173/tcp':[{HostIp:'127.0.0.1',HostPort:'4173'}]}:{},Networks:Object.fromEntries(EXPECTED[role].map(name=>[`vortexai_${name}`,{}]))}
  };
  return {container,networks};
}
test('approved inspection topology accepts every exact service role',()=>{
  for(const role of Object.keys(EXPECTED)){const {container,networks}=fixtures(role);assert.equal(validateInspection(container,networks),role);}
});
test('frontend ingress is permitted only for the trusted dashboard',()=>{
  const dashboard=fixtures('dashboard');
  assert.equal(dashboard.networks.find(network=>network.Name==='vortexai_frontend').Internal,false);
  assert.equal(validateInspection(dashboard.container,dashboard.networks),'dashboard');
  for(const role of Object.keys(EXPECTED).filter(role=>role!=='dashboard')) {
    const {container,networks}=fixtures(role);
    container.NetworkSettings.Networks.vortexai_frontend={};
    assert.throws(()=>validateInspection(container,networks),/network attachments/);
  }
});
const mutations=[
  ['extra internet attachment',c=>c.NetworkSettings.Networks.bridge={}],
  ['root execution',c=>c.Config.User='0:0'],
  ['privileged mode',c=>c.HostConfig.Privileged=true],
  ['capability re-addition',c=>c.HostConfig.CapAdd=['NET_ADMIN']],
  ['host filesystem',c=>c.Mounts=[{Type:'bind',Source:'/',Destination:'/host'}]],
  ['Docker socket',c=>c.HostConfig.Binds=['/var/run/docker.sock:/var/run/docker.sock']],
  ['published target',c=>c.HostConfig.PortBindings={'8080/tcp':[{HostIp:'127.0.0.1',HostPort:'8080'}]}],
  ['actual published target',c=>c.NetworkSettings.Ports={'8080/tcp':[{HostIp:'0.0.0.0',HostPort:'8080'}]}],
  ['forwarding',c=>c.HostConfig.Sysctls['net.ipv4.ip_forward']='1'],
  ['IPv6 enabled',c=>c.HostConfig.Sysctls['net.ipv6.conf.all.disable_ipv6']='0'],
  ['unhealthy service',c=>c.State.Health.Status='unhealthy'],
  ['unlimited memory',c=>c.HostConfig.Memory=0],
  ['changed process',c=>c.Config.Cmd=['sh']],
  ['model key in target',c=>c.Config.Env.push('ANTHROPIC_API_KEY=never-print-this')],
  ['executor token in target',c=>c.Config.Env.push('LAB_EXECUTOR_TOKEN=never-print-this')]
];
for(const [name,mutate] of mutations)test(`inspection rejects ${name}`,()=>{
  const {container,networks}=fixtures();mutate(container);
  assert.throws(()=>validateInspection(container,networks),error=>!error.message.includes('never-print-this'));
});
test('isolated network settings and subnet must match actual bridge state',()=>{
  for(const mutate of [n=>n.Internal=false,n=>n.EnableIPv6=true,n=>n.Options={},n=>n.IPAM.Config[0].Subnet='172.17.0.0/16']) {
    const {container,networks}=fixtures();mutate(networks.find(n=>n.Name==='vortexai_targets'));
    assert.throws(()=>validateInspection(container,networks));
  }
});
test('dashboard host publishing and executor control binding are narrowly pinned',()=>{
  let {container,networks}=fixtures('dashboard');container.HostConfig.PortBindings['4173/tcp'][0].HostIp='0.0.0.0';
  assert.throws(()=>validateInspection(container,networks),/loopback/);
  ({container,networks}=fixtures('executor'));container.Config.Env=container.Config.Env.map(item=>item.startsWith('CONTROL_BIND=')?'CONTROL_BIND=0.0.0.0':item);
  assert.throws(()=>validateInspection(container,networks),/listener/);
});
test('namespace route checks distinguish connected lab networks from usable default routes',()=>{
  const header='Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT';
  const connected=`${header}\neth0 00291EAC 00000000 0001 0 0 0 00FFFFFF 0 0 0`;
  const rejectV6=`${'0'.repeat(32)} 00 ${'0'.repeat(32)} 00 ${'0'.repeat(32)} ffffffff 00000001 00000000 00200200 lo`;
  assert.doesNotThrow(()=>checkRoutes(connected,rejectV6,'1'));
  assert.throws(()=>checkRoutes(`${connected}\neth0 00000000 01291EAC 0003 0 0 0 00000000 0 0 0`,rejectV6,'1'),/IPv4 default/);
  assert.throws(()=>checkRoutes(connected,rejectV6.replace('00200200','00000003'),'1'),/IPv6 default/);
  assert.throws(()=>checkRoutes(connected,rejectV6,'0'),/disabled/);
});
test('an unapproved network peer cannot provide a hidden external relay',()=>{
  const {container,networks}=fixtures('storage');container.Id='container-storage';
  for(const network of networks)network.Containers=network.Name==='vortexai_targets'?{'container-storage':{Name:'vortexai-storage-1'}}:{};
  assert.doesNotThrow(()=>validateNetworkMembers([container],networks));
  networks.find(network=>network.Name==='vortexai_targets').Containers['rogue-container']={Name:'unapproved-relay'};
  assert.throws(()=>validateNetworkMembers([container],networks),/unexpected or missing network peer/);
});
