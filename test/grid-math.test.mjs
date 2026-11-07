import test from 'node:test';
import assert from 'node:assert/strict';
import {projectPoint, screenToPlane, clampTranslation, sanitizeLayout, orbitCamera, nodesInRect} from '../public/grid-math.mjs';

test('screen rays recover horizontal positions across orbital angles, pan and zoom', () => {
  for (const yaw of [-Math.PI,-2.1, -.42, 0, 1.9,Math.PI]) for (const pitch of [-2.8,-Math.PI/2,-.56,.15,.56,Math.PI/2,2.8]) for (const zoom of [.65, 1, 1.65]) {
    const camera = {width:720,height:420,yaw,pitch,zoom,panX:83,panY:-34};
    for (const point of [{x:-4,y:0,z:2},{x:3.1,y:.4,z:-1.5},{x:2,y:2.8,z:3.5}]) {
      const result=screenToPlane(projectPoint(point,camera),point.y,camera);
      assert.ok(result);
      assert.ok(Math.abs(result.x-point.x)<1e-9);
      assert.ok(Math.abs(result.z-point.z)<1e-9);
      assert.equal(result.y,point.y);
    }
  }
});

test('orbit is unrestricted in yaw and pitch with reversed vertical mouse direction',()=>{
  const base={yaw:0,pitch:0};
  const moved=orbitCamera(base,20,20);
  assert.ok(Math.abs(moved.yaw-.12)<1e-12);
  assert.ok(Math.abs(moved.pitch+.1)<1e-12);
  const overPole=orbitCamera({yaw:0,pitch:1.5},0,-100);
  assert.ok(overPole.pitch>Math.PI/2,'pitch must cross overhead without a clamp');
  const underPole=orbitCamera({yaw:0,pitch:-1.5},0,100);
  assert.ok(underPole.pitch<-Math.PI/2,'pitch must cross underneath without a clamp');
  assert.deepEqual(base,{yaw:0,pitch:0},'camera input is not mutated');
});

test('complete orbit turns preserve the projected scene and keep angles wrapped',()=>{
  const base={width:720,height:420,yaw:.72,pitch:-.91,zoom:1.2,panX:12,panY:-18};
  const point={x:2,y:.4,z:-3};
  const expected=projectPoint(point,base);
  for(const turns of [-12,-2,-1,1,2,12]){
    const angles=orbitCamera(base,turns*2*Math.PI/.006,turns*2*Math.PI/.005);
    assert.ok(angles.yaw>=-Math.PI&&angles.yaw<Math.PI);
    assert.ok(angles.pitch>=-Math.PI&&angles.pitch<Math.PI);
    const camera={...base,...angles},screen=projectPoint(point,camera);
    assert.ok(Math.abs(screen.x-expected.x)<1e-9);
    assert.ok(Math.abs(screen.y-expected.y)<1e-9);
    const recovered=screenToPlane(screen,point.y,camera);
    assert.ok(Math.abs(recovered.x-point.x)<1e-9);
    assert.ok(Math.abs(recovered.z-point.z)<1e-9);
    assert.equal(recovered.y,point.y);
  }
});

test('marquee selection is inclusive, direction-independent and based on centers',()=>{
  const nodes=[{id:'left-top',x:10,y:20},{id:'middle',x:20,y:30},{id:'right-bottom',x:30,y:40},
    {id:'outside',x:31,y:30,r:20},{id:'invalid',x:NaN,y:30},{id:'middle',x:20,y:30}];
  for(const [start,end] of [[{x:10,y:20},{x:30,y:40}],[{x:30,y:40},{x:10,y:20}],
    [{x:30,y:20},{x:10,y:40}],[{x:10,y:40},{x:30,y:20}]]){
    assert.deepEqual(nodesInRect(nodes,start,end),['left-top','middle','right-bottom']);
  }
  assert.deepEqual(nodesInRect(nodes,{x:20,y:30},{x:20,y:30}),['middle']);
  assert.deepEqual(nodesInRect(nodes,{x:Infinity,y:0},{x:30,y:40}),[]);
});

test('marquee selection works on projections from inverted camera orientations',()=>{
  const points=[{id:'a',x:-2,y:.4,z:1},{id:'b',x:3,y:1,z:-2}];
  for(const pitch of [-2.4,-Math.PI/2,Math.PI/2,2.4]){
    const camera={width:720,height:420,yaw:1.8,pitch,zoom:1};
    const nodes=points.map(point=>({id:point.id,...projectPoint(point,camera)}));
    const start={x:Math.min(...nodes.map(n=>n.x))-1,y:Math.min(...nodes.map(n=>n.y))-1};
    const end={x:Math.max(...nodes.map(n=>n.x))+1,y:Math.max(...nodes.map(n=>n.y))+1};
    assert.deepEqual(nodesInRect(nodes,start,end),['a','b']);
  }
});

test('horizontal drag follows screen ray and preserves node height', () => {
  const camera={width:640,height:400,yaw:.7,pitch:.6,zoom:1.2};
  const start={x:1,y:1.8,z:-1}, screen=projectPoint(start,camera);
  const moved=screenToPlane({x:screen.x+32,y:screen.y+18},start.y,camera);
  const final=projectPoint(moved,camera);
  assert.equal(moved.y,1.8);
  assert.ok(Math.abs(final.x-screen.x-32)<1e-9);
  assert.ok(Math.abs(final.y-screen.y-18)<1e-9);
});

test('group movement clamps the whole translation without changing spacing', () => {
  assert.deepEqual(clampTranslation([{x:5,z:-5},{x:2,z:1}],4,-3),{dx:1,dz:-1});
  assert.deepEqual(clampTranslation([],4,-3),{dx:0,dz:0});
  assert.deepEqual(clampTranslation([{x:0,z:0}],Infinity,1),{dx:0,dz:0});
});

test('invalid layout and camera-horizon input cannot corrupt coordinates', () => {
  assert.deepEqual(sanitizeLayout({app:{x:2,z:-3},bad:{x:0,z:0},db:{x:99,z:1},iam:{x:'2',z:1}},['app','db','iam']),{app:{x:2,z:-3}});
  assert.deepEqual(sanitizeLayout(null,['app']),{});
  assert.equal(screenToPlane({x:320,y:204},0,{width:640,height:400,yaw:0,pitch:0,zoom:1}),null);
});
