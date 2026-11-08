import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';
import * as gridMath from '../public/grid-math.mjs';

// Run the real browser module and its registered event handlers. The small DOM
// double provides only browser primitives; it does not reproduce gesture logic.
// No server, network request, browser process, package, or UI automation is used.
const appSource=readFileSync(new URL('../public/app.mjs',import.meta.url),'utf8');
const importLine="import {projectPoint, screenToPlane, clampTranslation, sanitizeLayout, orbitCamera, nodesInRect} from './grid-math.mjs';";

class Element {
  constructor(id,context) {
    this.id=id;this.context=context;this.listeners=new Map();this.value='';this.open=false;
    this.textContent='';this.innerHTML='';this.children=[];this.options=[{textContent:''}];this.captures=new Set();
    this.classList={toggle(){},add(){},remove(){}};
    this.dataset={};
  }
  addEventListener(name,listener){const list=this.listeners.get(name)||[];list.push(listener);this.listeners.set(name,list);}
  dispatch(name,event={}){
    const input={target:this,button:0,pointerId:1,clientX:0,clientY:0,ctrlKey:false,altKey:false,shiftKey:false,preventDefault(){this.defaultPrevented=true;},...event};
    for(const listener of this.listeners.get(name)||[])listener(input);
    return input;
  }
  getContext(){return this.context;}
  getBoundingClientRect(){return {left:0,top:0,width:600,height:400,right:600,bottom:400};}
  setPointerCapture(id){this.captures.add(id);}
  hasPointerCapture(id){return this.captures.has(id);}
  releasePointerCapture(id){this.captures.delete(id);}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
  showModal(){this.open=true;}
  close(){this.open=false;}
}

function harness() {
  const ctx=new Proxy({measureText:text=>({width:String(text).length*6})},{get:(target,key)=>target[key]||(()=>{}),set:(target,key,value)=>(target[key]=value,true)});
  const elements=new Map(),storage=new Map();
  const element=id=>{if(!elements.has(id))elements.set(id,new Element(id,ctx));return elements.get(id);};
  const window=new Element('window',ctx);
  const sandbox={...gridMath,console,document:{getElementById:element,querySelectorAll:()=>[],createElement:tag=>new Element(tag,ctx)},window,matchMedia:()=>({matches:true}),devicePixelRatio:1,performance:{now:()=>0},localStorage:{getItem:key=>storage.get(key)??null,setItem:(key,value)=>storage.set(key,value)},requestAnimationFrame:()=>0,setTimeout:()=>0,fetch:()=>new Promise(()=>{}),ResizeObserver:class{constructor(callback){this.callback=callback;}observe(){this.callback([{contentRect:{width:600,height:400}}]);}}};
  const context=vm.createContext(sandbox);
  // Replace the ES module import with the same imported functions supplied above.
  // All runtime and event-registration code stays unchanged.
  const executable=appSource.replace(importLine,'');
  new vm.Script(executable+`\n globalThis.testGrid={
    initialize:next=>{update(next);render(0);}, frame:()=>render(0),
    inspect:()=>({selected:[...selectedNodes],primary:selected,layout:structuredClone(layout),camera:camera(),dialog:nodeEditor?{ids:[...nodeEditor.ids],group:nodeEditor.group}:null}),
    point:id=>{const n=visualNode(state.nodes.find(n=>n.id===id));return project(n.x,n.y,n.z);},
    nodes:()=>state.nodes.map(visualNode)
  };`,{filename:'public/app.mjs'}).runInContext(context);
  const state={running:true,tick:0,events:[],edges:[],findings:[],recommendations:[],scenarios:[],metrics:{totalEvents:0,attackEvents:0,blockedEvents:0,openFindings:0},agents:Object.fromEntries(['attacker','searcher','builder'].map(id=>[id,{status:'Ready',detail:''}])),runtime:{mode:'simulation'},nodes:[
    {id:'app',label:'Application',type:'compute',zone:'private',x:-2,y:.4,z:-1,description:'Application'},
    {id:'db',label:'Database',type:'database',zone:'private',x:.4,y:.9,z:.8,description:'Database'},
    {id:'storage',label:'Storage',type:'storage',zone:'private',x:4,y:.4,z:-3,description:'Storage'}
  ]};
  // Node's VM realms need an explicit clone primitive; production uses the browser's.
  context.structuredClone=structuredClone;
  context.testGrid.initialize(state);
  const read=()=>JSON.parse(JSON.stringify(context.testGrid.inspect()));
  const nodes=()=>JSON.parse(JSON.stringify(context.testGrid.nodes()));
  const point=id=>context.testGrid.point(id);
  const emit=(type,point,options={})=>element('topology').dispatch(type,{clientX:point.x,clientY:point.y,...options});
  const click=(id,options={})=>{const p=point(id);emit('pointerdown',p,options);emit('pointerup',p,options);context.testGrid.frame();};
  const drag=(id,dx,dy,options={})=>{const p=point(id),end={x:p.x+dx,y:p.y+dy};emit('pointerdown',p,options);emit('pointermove',end,options);emit('pointerup',end,options);context.testGrid.frame();};
  return {read,nodes,point,emit,click,drag,element,window,storage,frame:context.testGrid.frame};
}
const close=(actual,expected,tolerance=1e-8)=>assert.ok(Math.abs(actual-expected)<tolerance,`${actual} should equal ${expected}`);

test('Ctrl-click toggles membership without moving the clicked resource',()=>{
  const h=harness(),before=h.nodes();
  h.click('app',{ctrlKey:true});assert.deepEqual(h.read().selected,['app']);
  h.click('db',{ctrlKey:true});assert.deepEqual(h.read().selected,['app','db']);
  h.click('app',{ctrlKey:true});assert.deepEqual(h.read().selected,['db']);
  assert.equal(h.read().primary,'db');assert.deepEqual(h.nodes(),before);
});

test('Ctrl-left drag moves a selected group together without toggling membership or changing heights',()=>{
  const h=harness();h.click('app',{ctrlKey:true});h.click('db',{ctrlKey:true});
  const before=h.nodes();h.drag('app',55,30,{ctrlKey:true});
  const after=h.nodes();assert.deepEqual(h.read().selected,['app','db']);
  assert.notEqual(after[0].x,before[0].x);
  close(after[1].x-after[0].x,before[1].x-before[0].x);
  close(after[1].z-after[0].z,before[1].z-before[0].z);
  assert.deepEqual(after.map(n=>n.y),before.map(n=>n.y));
  assert.deepEqual(after[2],before[2]);
  assert.ok(h.storage.has('vortexai.node-layout.v2.simulation'));
});

test('Ctrl-left drag on an unselected node moves that node and replaces the previous group',()=>{
  const h=harness();h.click('app',{ctrlKey:true});h.click('db',{ctrlKey:true});
  const before=h.nodes();h.drag('storage',-45,20,{ctrlKey:true});
  const after=h.nodes();assert.deepEqual(h.read().selected,['storage']);
  assert.deepEqual(after.slice(0,2),before.slice(0,2));assert.notEqual(after[2].x,before[2].x);
});

for(const reverseX of [false,true])for(const reverseY of [false,true])test(`Alt-left box selects in ${reverseX?'right-to-left':'left-to-right'} / ${reverseY?'bottom-to-top':'top-to-bottom'} direction`,()=>{
  const h=harness(),a=h.point('app'),b=h.point('db'),outside=h.point('storage');
  const left=Math.min(a.x,b.x)-6,right=Math.max(a.x,b.x)+6,top=Math.min(a.y,b.y)-6,bottom=Math.max(a.y,b.y)+6;
  assert.ok(outside.x>right || outside.x<left || outside.y>bottom || outside.y<top);
  const start={x:reverseX?right:left,y:reverseY?bottom:top},end={x:reverseX?left:right,y:reverseY?top:bottom};
  h.emit('pointerdown',start,{altKey:true});h.emit('pointermove',end,{altKey:true});h.emit('pointerup',end,{altKey:true});
  assert.deepEqual(h.read().selected.sort(),['app','db']);
});

test('Ctrl-right stationary click opens selected-group options; a drag moves instead',()=>{
  const h=harness();h.click('app',{ctrlKey:true});h.click('db',{ctrlKey:true});
  h.click('app',{button:2,ctrlKey:true});
  assert.equal(h.element('node-dialog').open,true);assert.equal(h.read().dialog.group,true);
  assert.deepEqual(h.read().dialog.ids,['app','db']);
  h.element('node-dialog').close();
  const before=h.nodes();h.drag('app',35,25,{button:2,ctrlKey:true});
  assert.equal(h.element('node-dialog').open,false);
  assert.deepEqual(h.read().selected,['app','db']);assert.notEqual(h.nodes()[0].x,before[0].x);
  const menu=h.element('topology').dispatch('contextmenu');assert.equal(menu.defaultPrevented,true);
});

test('pointer cancellation restores original group layout and pre-drag selection',()=>{
  const h=harness();h.click('app',{ctrlKey:true});h.click('db',{ctrlKey:true});
  const before=h.nodes(),selection=h.read().selected,p=h.point('storage');
  h.emit('pointerdown',p,{ctrlKey:true});h.emit('pointermove',{x:p.x-50,y:p.y+20},{ctrlKey:true});
  assert.deepEqual(h.read().selected,['storage']);assert.notEqual(h.nodes()[2].x,before[2].x);
  h.emit('pointercancel',p,{ctrlKey:true});
  assert.deepEqual(h.read().selected,selection);assert.deepEqual(h.nodes(),before);
  assert.equal(h.storage.size,0,'cancelled layout changes must not be persisted');
});

test('Escape cancels a marquee and restores its previous selection',()=>{
  const h=harness();h.click('storage',{ctrlKey:true});const before=h.read().selected;
  h.emit('pointerdown',{x:0,y:0},{altKey:true});h.emit('pointermove',{x:600,y:400},{altKey:true});
  assert.equal(h.read().selected.length,3);
  h.window.dispatch('keydown',{key:'Escape'});assert.deepEqual(h.read().selected,before);
});

test('orbit reverses vertical mouse motion and crosses both former pitch limits',()=>{
  const h=harness(),start={x:25,y:25};const initial=h.read().camera;
  h.emit('pointerdown',start);
  h.emit('pointermove',{x:25,y:65});assert.ok(h.read().camera.pitch<initial.pitch);
  h.emit('pointermove',{x:25,y:425});assert.ok(h.read().camera.pitch<-.5,'orbit must pass below the horizontal plane');
  h.emit('pointermove',{x:625,y:825});assert.ok(h.read().camera.pitch>Math.PI/2,'orbit must continue beyond a pole rather than clamp');
  assert.notEqual(h.read().camera.yaw,initial.yaw);
  h.emit('pointerup',{x:625,y:825});
});
