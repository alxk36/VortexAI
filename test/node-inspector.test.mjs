import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Exercise the actual browser handlers with a small DOM boundary. Rendering and
// canvas gestures are separate; these checks cover data-changing group actions.
const app=readFileSync(new URL('../public/app.mjs',import.meta.url),'utf8');
const source=app.slice(app.indexOf('// Resource inspector:'),app.indexOf('// A dependency-free perspective renderer'));
class Element {
  constructor(){this.listeners={};this.options=[{}];this.value='';this.textContent='';this.disabled=false;this.hidden=false;this.open=false;this.children=[];}
  addEventListener(type,listener){this.listeners[type]=listener;}
  dispatch(type,event={}){return this.listeners[type]?.({preventDefault(){},target:this,...event});}
  replaceChildren(){this.children=[];}
  append(...children){this.children.push(...children);}
  showModal(){this.open=true;}
  close(){this.open=false;}
  getBoundingClientRect(){return {left:0,right:100,top:0,bottom:100};}
  set innerHTML(value){throw new Error('Inspector must not insert HTML');}
}
function fixture({mode='simulation',nodes,selected=['gateway','app'],onRequest}={}){
  const elements=new Map(),$=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  const resources=nodes||[
    {id:'gateway',label:'Gateway',status:'active',action:'normal'},
    {id:'app',label:'Application',status:'paused',action:'normal'},
    {id:'logs',label:'Audit view',status:'active',action:'normal'}
  ];
  const backend={runtime:{mode},nodes:resources.map(n=>({x:1,y:0,z:2,type:'service',zone:'private',description:'Resource details',...n})),findings:[]};
  const calls=[];
  const ctx={$,document:{createElement:()=>new Element()},state:structuredClone(backend),selected:selected[0],selectedNodes:new Set(selected),dialogNode:'',busy:false,commandVersion:0,layout:{},saveCount:0};
  Object.assign(ctx,{
    mode:()=>ctx.state.runtime.mode,
    canEditControls:id=>ctx.state.runtime.mode==='simulation'||['gateway','lb','app','storage','iam','db'].includes(id),
    visualNode:node=>({...node,...ctx.layout[node.id]}),
    inspectResource(){},renderControls(){},saveLayout(){ctx.saveCount++;},
    update:next=>{ctx.state=next;},
    request:async(path,body)=>{
      calls.push({path,body:body&&structuredClone(body),busy:ctx.busy,version:ctx.commandVersion});
      await onRequest?.(path,body,backend,calls);
      if(path==='node')Object.assign(backend.nodes.find(n=>n.id===body.id),body);
      return structuredClone(backend);
    }
  });
  vm.createContext(ctx);vm.runInContext(source,ctx);
  return {$,ctx,calls,backend,open:id=>ctx.openNode(id),change:(field,value)=>{$(`node-${field}`).value=value;$(`node-${field}`).dispatch('change');},save:()=>$('node-form').dispatch('submit')};
}

test('inspector retains a selected group, shows mixed values, and resets for an outside node',()=>{
  const f=fixture();f.open('app');
  assert.equal(f.$('node-dialog-title').textContent,'2 selected resources');
  assert.equal(f.$('node-status').value,'');
  assert.equal(f.$('node-status').options[0].textContent,'Mixed — keep unchanged');
  assert.equal(f.$('node-action').value,'normal');
  assert.match(f.$('node-members').textContent,/Gateway.*Application/);
  assert.equal(f.$('node-position-fields').hidden,true);
  assert.equal(f.$('node-x').disabled,true);
  f.open('logs');
  assert.deepEqual([...f.ctx.selectedNodes],['logs']);
  assert.equal(f.$('node-dialog-title').textContent,'Audit view');
  assert.equal(f.$('node-position-fields').hidden,false);
  assert.equal(f.$('node-x').disabled,false);
});

test('shared action updates preserve mixed and newly changed statuses under one busy span',async()=>{
  const f=fixture({onRequest(path,body,backend,calls){
    // Another viewer changes the second resource after the inspector opened.
    if(path==='state'&&calls.filter(c=>c.path==='state').length===2)backend.nodes[1].status='active';
  }});
  f.open('app');f.change('action','observe');await f.save();
  assert.deepEqual(f.calls.filter(c=>c.path==='node').map(c=>c.body),[
    {id:'gateway',status:'active',action:'observe'},
    {id:'app',status:'active',action:'observe'}
  ]);
  assert.ok(f.calls.every(call=>call.busy&&call.version===1));
  assert.equal(f.ctx.busy,false);assert.equal(f.ctx.saveCount,0);
  assert.equal(f.$('node-dialog').open,false);
});

test('unchosen and keep-unchanged fields do not submit operational changes',async()=>{
  const f=fixture();f.open('gateway');f.change('action','quarantine');f.change('action','');await f.save();
  assert.deepEqual(f.calls,[]);
  assert.equal(f.backend.nodes[0].action,'normal');
  assert.equal(f.backend.nodes[1].status,'paused');
});

test('changing a shared status preserves different actions and skips an already-matching node',async()=>{
  const f=fixture({nodes:[
    {id:'gateway',label:'Gateway',status:'active',action:'normal'},
    {id:'app',label:'Application',status:'paused',action:'quarantine'}
  ]});
  f.open('app');f.change('status','active');await f.save();
  assert.deepEqual(f.calls.filter(c=>c.path==='node').map(c=>c.body),[{id:'app',status:'active',action:'quarantine'}]);
  assert.equal(f.backend.nodes[0].action,'normal');assert.equal(f.backend.nodes[1].action,'quarantine');
  assert.match(f.$('message').textContent,/1 already had the requested values/);
});

test('a real-lab group containing a conceptual node has no shared operational controls',async()=>{
  const f=fixture({mode:'lab',selected:['gateway','logs']});f.open('gateway');
  assert.equal(f.$('node-status').disabled,true);assert.equal(f.$('node-action').disabled,true);
  assert.equal(f.$('save-node').disabled,true);assert.match(f.$('node-edit-note').textContent,/conceptual/);
  f.change('status','paused');await f.save();assert.deepEqual(f.calls,[]);
});

test('partial failure retains successful changes and explains uncertainty without rolling back',async()=>{
  const f=fixture({onRequest(path,body){if(path==='node'&&body.id==='app')throw new Error('Connection interrupted');}});
  f.open('app');f.change('action','quarantine');await f.save();
  assert.equal(f.backend.nodes[0].action,'quarantine');assert.equal(f.backend.nodes[1].action,'normal');
  assert.equal(f.$('node-dialog').open,true);
  assert.match(f.$('node-error').textContent,/1 of 2 updates confirmed/);
  assert.match(f.$('node-error').textContent,/may have reached the server/);
  assert.match(f.$('node-error').textContent,/Earlier successful changes remain/);
  assert.equal(f.ctx.busy,false);assert.equal(f.$('close-node').disabled,false);
});

test('saving prevents retargeting and dismissal while preserving captured membership',async()=>{
  let release,started;
  const requestStarted=new Promise(resolve=>{started=resolve;});
  const blocked=new Promise(resolve=>{release=resolve;});
  const f=fixture({onRequest:async(path)=>{if(path==='node'){started();await blocked;}}});
  f.open('gateway');f.change('action','observe');const saving=f.save();await requestStarted;
  f.open('logs');f.$('close-node').dispatch('click');
  let cancelled=false;f.$('node-dialog').dispatch('cancel',{preventDefault(){cancelled=true;}});
  assert.equal(cancelled,true);assert.equal(f.$('node-dialog').open,true);
  assert.equal(f.$('node-dialog-title').textContent,'2 selected resources');
  release();await saving;
  assert.deepEqual(f.calls.filter(c=>c.path==='node').map(c=>c.body.id),['gateway','app']);
});

test('single-node layout editing stays local and retains untouched live settings',async()=>{
  const f=fixture({selected:['app']});f.open('app');f.$('node-x').value='-3.25';f.$('node-z').value='4';await f.save();
  assert.deepEqual(f.calls,[]);assert.equal(f.ctx.layout.app.x,-3.25);assert.equal(f.ctx.layout.app.z,4);
  assert.equal(f.backend.nodes[1].status,'paused');assert.equal(f.ctx.saveCount,1);
});
