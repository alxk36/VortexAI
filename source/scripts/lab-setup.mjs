// Prepare source/.env relative to this script, not the caller's working folder.
// Existing nonempty values stay intact; missing control tokens get independent
// random values. Provider keys are never generated or printed by this script.
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const path=fileURLToPath(new URL('../.env',import.meta.url));
// Preserve an existing provider key; generate independent control-plane secrets.
let content=existsSync(path)?readFileSync(path,'utf8'):readFileSync(new URL('../.env.example',import.meta.url),'utf8');
for(const key of ['LAB_CONTROL_TOKEN','LAB_EXECUTOR_TOKEN','LAB_APP_TOKEN','AGENT_CONTROL_TOKEN','AGENT_BROKER_TOKEN']) {
  const pattern=new RegExp(`^${key}=([^\\r\\n]*)$`,'m');
  const match=content.match(pattern);
  if(!match || !match[1].trim()) {
    const line=`${key}=${randomBytes(32).toString('hex')}`;
    content=match?content.replace(pattern,line):content+'\n'+line+'\n';
  }
}
writeFileSync(path,content,{mode:0o600});
console.log('Local .env is ready. Add your key after ANTHROPIC_API_KEY= in that file.');
console.log('The key is optional for fallback mode; never paste it into chat or commit it.');
