import {existsSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join,dirname,delimiter,isAbsolute} from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url));
const command=process.argv[2];
const candidates=[process.env.DOCKER_BIN,...(process.platform==='win32'?[
  join(process.env.LOCALAPPDATA || '', 'Programs','DockerDesktop','resources','bin','docker.exe'),
  'C:/Program Files/Docker/Docker/resources/bin/docker.exe',
]:[])].filter(Boolean);
const docker=candidates.find(existsSync)||'docker';
process.env.DOCKER_BIN=docker;
// A just-installed Desktop may not be on this terminal's PATH yet. Its registry
// credential helper must be discoverable alongside the absolute CLI executable.
if(isAbsolute(docker)) {
  const pathKey=Object.keys(process.env).find(key=>key.toLowerCase()==='path') || 'PATH';
  process.env[pathKey]=dirname(docker)+delimiter+(process.env[pathKey] || '');
}
function run(bin,args) {
  const result=spawnSync(bin,args,{cwd:root,env:process.env,stdio:'inherit',shell:false});
  if(result.error || result.status!==0) {
    console.error(result.error?'Docker is unavailable. Install/start Docker Desktop, then retry.':'The operation failed; lab traffic remains gated by containment verification.');
    process.exit(result.status || 1);
  }
}
if(command==='up') {
  run(process.execPath,['scripts/lab-setup.mjs']);
  run(docker,['version','--format','{{.Server.Version}}']);
  run(docker,['compose','config','--quiet']);
  run(docker,['compose','build','dashboard']);
  run(docker,['compose','up','-d','--no-build','--wait','--wait-timeout','120']);
  run(process.execPath,['scripts/lab-verify.mjs']);
  console.log('Open http://127.0.0.1:4173 and select Real services.');
} else if(command==='verify')run(process.execPath,['scripts/lab-verify.mjs']);
else if(command==='down')run(docker,['compose','down']);
else if(command==='status')run(docker,['compose','ps']);
else {console.error('Choose up, verify, down, or status.');process.exitCode=1;}
