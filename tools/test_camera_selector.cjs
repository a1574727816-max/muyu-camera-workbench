// Frontend-only contract/race fixture. Run: node tools/test_camera_selector.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const source = fs.readFileSync(require('node:path').join(__dirname, '../server/camera_web.py'), 'utf8');
const html = source.split("HTML = r'''")[1].split("'''")[0];
const script = html.split('<script>')[1].split('</script>')[0];
new vm.Script(script); // Parse the actual shipped script, never a copied implementation.
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return {promise, resolve}; };
const response = value => ({ok:true, status:200, json:async()=>value});
const flush = async () => { for(let i=0;i<30;i++) await Promise.resolve(); };
const cameras = ['cam1','cam2'].map((id,i)=>({id,name:`Camera ${i+1}`,capabilities:{ptz:!i,wifi:!i,ssh_recovery:!i}}));
function fixture(saved='cam1',mse=false) {
  const elements = new Map(), timers = new Map(), requests = [], overrides = [];
  const media=[],readers=[];
  class FakeMediaSource extends EventTarget {
    static isTypeSupported(){return true}
    constructor(){super();media.push(this);this.readyState='open'}
    addSourceBuffer(){const buffer=new EventTarget();buffer.buffered={length:0};buffer.appendBuffer=buffer.remove=()=>queueMicrotask(()=>buffer.dispatchEvent(new Event('updateend')));return buffer}
    endOfStream(){}
  }
  let timerId=0;
  function element(id) {
    if(elements.has(id))return elements.get(id);
    const classes=new Set();
    const e={id,children:[],style:{},value:'',textContent:'',disabled:false,muted:true,paused:true,currentTime:0,
      buffered:{length:0},classList:{add:c=>classes.add(c),remove:c=>classes.delete(c),contains:c=>classes.has(c),toggle(c,on){if(on)classes.add(c);else classes.delete(c)}},
      append(...children){this.children.push(...children)},replaceChildren(...children){this.children=children},
      pause(){this.paused=true},play(){this.paused=false;return Promise.resolve()},load(){},removeAttribute(key){delete this[key]},
      setPointerCapture(){},getBoundingClientRect(){return {left:0,top:0,width:178,height:178}}};
    elements.set(id,e);return e;
  }
  const storage=new Map([['cameraId',saved]]);
  function state(id){return {camera_id:id,camera_name:id==='cam1'?'Camera 1':'Camera 2',capabilities:cameras.find(c=>c.id===id).capabilities,
    online:true,ip:id==='cam1'?'192.168.1.10':'192.168.1.11',manual_ip:'',csrf:'token',mode:'auto',recording:true,recording_enabled:true,
    storage_bytes:100,storage_limit_bytes:1000,total_recordings:1,recordings_has_more:true,
    recordings:[{name:'same name.mkv',mtime:1,bytes:500,active:false}],logs:[],candidates:[],video_codec:id==='cam1'?'H.265':'H.264',video_resolution:'1920×1080'};}
  const sandbox={console,crypto:webcrypto,AbortController,DOMException,Uint8Array,URL,
    document:{getElementById:element,querySelector:element,createElement:tag=>element(`node-${elements.size}-${tag}`),addEventListener(){}},
    window:{addEventListener(){},MediaSource:mse?FakeMediaSource:undefined},MediaSource:FakeMediaSource,
    URL:{createObjectURL:()=>`blob:fixture-${media.length}`,revokeObjectURL(){}},
    sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)},
    location:{reload(){}},prompt:()=>null,
    setTimeout:(fn,ms)=>{const id=++timerId;timers.set(id,{fn,ms});return id},clearTimeout:id=>timers.delete(id),
    setInterval:(fn,ms)=>{const id=++timerId;timers.set(id,{fn,ms,interval:true});return id},clearInterval:id=>timers.delete(id),
    fetch:async(url,options={})=>{
      const u=new URL(url,'http://fixture'), req={url,u,options};requests.push(req);
      if(!['/api/cameras','/api/login','/api/logout'].includes(u.pathname)&&!u.pathname.startsWith('/api/auth/')){
        assert(['cam1','cam2'].includes(u.searchParams.get('camera_id')),url);
        assert.equal(u.searchParams.getAll('camera_id').length,1);
      }
      if((options.method||'GET')==='GET'){assert.equal(options.body,undefined);assert(!options.headers?.['X-CSRF-Token']);}
      const override=overrides.findIndex(o=>o.match(req));if(override>=0)return overrides.splice(override,1)[0].result;
      if(u.pathname==='/api/cameras')return response({cameras:structuredClone(cameras),csrf:'token'});
      if(u.pathname==='/api/state')return response(state(u.searchParams.get('camera_id')));
      if(u.pathname==='/api/live'||u.pathname.startsWith('/api/play/')){
        const pending=deferred(),reader={cancelled:false,read:()=>pending.promise,cancel(){this.cancelled=true;pending.resolve({done:true});return Promise.resolve()}};readers.push(reader);
        return {ok:true,body:{getReader:()=>reader}};
      }
      if(u.pathname.endsWith('/prepare'))return response({duration:600});
      if(u.pathname.endsWith('/status'))return response({state:'ready'});
      return response({});
    }};
  const ctx=vm.createContext(sandbox);vm.runInContext(script,ctx);
  return {element,requests,timers,overrides,storage,ctx,state,media,readers,run:code=>vm.runInContext(code,ctx),
    switch:id=>vm.runInContext(`selectCamera('${id}')`,ctx)};
}
async function main(){
  const f=fixture();await flush();
  assert.equal(f.element('manualIp').value,'192.168.1.10');
  assert.match(f.element('codecLabel').textContent,/H.265/);
  assert.match(f.element('live').src,/camera_id=cam1/);
  const oldClip=f.element('clips').children[0].children[1].children[0];
  assert.match(f.element('clips').children[0].children[1].children[1].href,/camera_id=cam1/);
  // An old refresh can finish after switching, even when fetch ignores abort.
  const stale=deferred();f.overrides.push({match:r=>r.u.pathname==='/api/state',result:stale.promise});
  const refreshing=f.run('refresh()');await flush();
  const staleRequest=f.requests.at(-1);
  await f.switch('cam2');assert(staleRequest.options.signal.aborted);
  stale.resolve(response({...f.state('cam1'),camera_name:'STALE'}));await refreshing;
  assert.equal(f.element('cameraTitle').textContent,'Camera 2');
  assert.equal(f.element('manualIp').value,'192.168.1.11');
  assert(f.element('.ptz-card').classList.contains('hidden'));
  assert(f.element('.wifi-card').classList.contains('hidden'));
  assert(f.element('.grid').classList.contains('no-ptz'));
  assert(f.element('.grid').classList.contains('no-wifi'));
  assert.match(f.element('codecLabel').textContent,/H.264/);
  assert.equal(f.storage.get('cameraId'),'cam2');
  let count=f.requests.length;oldClip.onclick();await f.element('panLeft').onclick();
  f.element('stick').onkeydown({key:'ArrowLeft',preventDefault(){}});
  f.element('wifiForm').onsubmit({preventDefault(){}});await flush();assert.equal(f.requests.length,count);
  // Recording remains an explicit per-camera action; selecting alone sent no recording POST.
  assert(!f.requests.some(r=>r.u.pathname==='/api/recording'));
  f.element('olderClips').onclick();await flush();
  const page=f.requests.filter(r=>r.u.pathname==='/api/state').at(-1);
  assert.equal(page.u.searchParams.get('offset'),'100');assert.equal(page.u.searchParams.get('camera_id'),'cam2');
  await f.element('discover').onclick();await f.element('saveDevice').onclick();await f.element('toggleRec').onclick();await flush();
  for(const path of ['/api/discover','/api/device','/api/recording'])assert(f.requests.some(r=>r.u.pathname===path&&r.u.searchParams.get('camera_id')==='cam2'));
  // A stale prepare response cannot open a video on the next camera.
  const prep=deferred();f.overrides.push({match:r=>r.u.pathname.endsWith('/prepare'),result:prep.promise});
  const playing=f.run("play('same name.mkv')");await flush();await f.switch('cam1');
  prep.resolve(response({duration:600}));await playing;assert.equal(f.element('playvideo').src,undefined);
  assert(f.element('playmodal').classList.contains('hidden'));
  await f.run("play('same name.mkv')");assert.match(f.element('playvideo').src,/start=0&camera_id=cam1/);
  f.element('forward30').onclick();assert.match(f.element('playvideo').src,/start=30&camera_id=cam1/);
  // Held PTZ + a late response: every stop still targets the old camera.
  const motor=deferred();f.overrides.push({match:r=>r.u.pathname==='/api/ptz'&&JSON.parse(r.options.body).x!==0,result:motor.promise});
  f.element('stick').onkeydown({key:'ArrowLeft',preventDefault(){}});await flush();
  const marker=f.requests.length;await f.switch('cam2');motor.resolve(response({message:'old PTZ'}));await flush();
  const stops=f.requests.slice(marker).filter(r=>r.u.pathname==='/api/ptz');assert(stops.length>=1);
  for(const req of stops){assert.equal(req.u.searchParams.get('camera_id'),'cam1');assert.equal(JSON.parse(req.options.body).x,0);}
  assert.notEqual(f.element('ptzFeedback').textContent,'old PTZ');
  // Native live backoff is invalidated on a switch (including queued callbacks).
  const oldError=f.element('live').onerror;oldError();
  const retry=[...f.timers.values()].find(t=>t.ms===2000);assert(retry);
  await f.switch('cam1');const liveSrc=f.element('live').src;retry.fn();oldError();await flush();assert.equal(f.element('live').src,liveSrc);
  // Same-camera concurrent refreshes also obey latest-request-wins.
  const a=deferred(),b=deferred();f.overrides.push({match:r=>r.u.pathname==='/api/state',result:a.promise},{match:r=>r.u.pathname==='/api/state',result:b.promise});
  const ra=f.run('refresh()'),rb=f.run('refresh()');b.resolve(response({...f.state('cam1'),camera_name:'Newest'}));await rb;
  a.resolve(response({...f.state('cam1'),camera_name:'Older'}));await ra;assert.equal(f.element('cameraTitle').textContent,'Newest');
  const independent=fixture('cam2');await flush();assert.equal(independent.element('cameraSelect').value,'cam2');
  assert.equal(f.element('cameraSelect').value,'cam1');
  const m=fixture('cam1',true);await flush();
  m.media[0].dispatchEvent(new Event('sourceopen'));await flush();
  const oldReader=m.readers[0],oldLiveRequest=m.requests.find(r=>r.u.pathname==='/api/live');
  await m.switch('cam2');await flush();assert(oldReader.cancelled);assert(oldLiveRequest.options.signal.aborted);
  m.media.at(-1).dispatchEvent(new Event('sourceopen'));await flush();
  const newLiveRequest=m.requests.filter(r=>r.u.pathname==='/api/live').at(-1);
  assert.equal(newLiveRequest.u.searchParams.get('camera_id'),'cam2');assert(!newLiveRequest.options.signal.aborted);
  // Aborted sourceopen must not initiate an old fetch or kill the new stream.
  await m.switch('cam1');const unopened=m.media.at(-1);await m.switch('cam2');
  const beforeOpen=m.requests.length;unopened.dispatchEvent(new Event('sourceopen'));await flush();assert.equal(m.requests.length,beforeOpen);
  // Playback sourceopen and reader cleanup use the same selection fence.
  await m.run("play('same name.mkv')");m.media.at(-1).dispatchEvent(new Event('sourceopen'));await flush();
  const playReader=m.readers.at(-1);await m.switch('cam1');assert(playReader.cancelled);
  // A late step completion cannot arm a stop against the selected camera.
  const step=deferred();m.overrides.push({match:r=>r.u.pathname==='/api/ptz'&&JSON.parse(r.options.body).mode==='step',result:step.promise});
  const stepping=m.element('panLeft').onclick();await flush();await m.switch('cam2');const afterSwitch=m.requests.length;
  step.resolve(response({}));await stepping;await flush();assert.equal(m.requests.length,afterSwitch);
  assert(html.includes('.grid.no-ptz.no-wifi{grid-template-areas:"live" "metrics" "recordings" "status" "device"}'));
  console.log('PASS: scoped URLs, capabilities, tab selection, pagination, recording independence, stale refresh/prepare/PTZ, native playback/live retries, MediaSource reader/sourceopen cleanup');
}
main().catch(e=>{console.error(e);process.exitCode=1});
