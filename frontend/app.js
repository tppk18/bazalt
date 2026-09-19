const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => [...r.querySelectorAll(s)];

const settings = {
  pageSize: Number(localStorage.getItem('bazalt.pageSize') || localStorage.getItem('packmate.pageSize') || 100),
  hexBlock: Number(localStorage.getItem('bazalt.hexBlock') || localStorage.getItem('packmate.hexBlock') || 16),
  lineBase: Number(localStorage.getItem('bazalt.lineBase') || localStorage.getItem('packmate.lineBase') || 10),
  resourcesExpanded: localStorage.getItem('bazalt.resourcesExpanded') === '1',
};

const state = {
  services: [], patterns: [], flows: [], offset: 0,
  selectedService: '', selectedPattern: '', selectedFlow: '',
  favoritesOnly: false, hexdump: false, paused: false,
  ua: {mode:'contains', value:''},
  serviceEdit: null, patternEdit: null,
  lastCounters: null, lastResourceSample: null, status: null, resourceStatus: null, ws: null,
  management: null, managementOpen: false, topology: null, topologyOpen: false, topologyLoading: false,
};

function esc(v){return String(v ?? '').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}

function viewLabel(view){
  return ({
    tcp_raw:'RAW',
    http_request_headers:'HDR',
    http_request_body:'BODY',
    http_request_decoded_body:'DEC',
    http_response_headers:'HDR',
    http_response_body:'BODY',
    http_response_decoded_body:'DEC',
  })[view] || String(view || '').toUpperCase();
}
function toast(message, kind='error'){const t=$('#toast');t.textContent=message;t.className=`toast show ${kind}`;clearTimeout(t._timer);t._timer=setTimeout(()=>t.className='toast',4200);}
async function api(path, options={}){
  const opts={...options,headers:{...(options.body?{'Content-Type':'application/json'}:{}),...(options.headers||{})}};
  const response=await fetch(path,opts);
  if(response.status===403&&path!=='/auth/login'){showLogin();throw new Error('authentication required');}
  if(!response.ok){let detail='';try{const b=await response.json();detail=b.error||JSON.stringify(b);}catch{detail=await response.text();}throw new Error(detail||`${response.status} ${response.statusText}`);}
  if(response.status===204)return null;
  const ct=response.headers.get('content-type')||'';
  return ct.includes('json')?response.json():response.text();
}

function showModal(id){$(`#${id}`).classList.remove('hidden');}
function hideModal(id){$(`#${id}`).classList.add('hidden');}
function showLogin(){
  $('#login-screen').classList.remove('hidden');
  $('#login-error').classList.add('hidden');
  if(state.ws){try{state.ws.close();}catch{}state.ws=null;}
  setTimeout(()=>$('#login-username')?.focus(),0);
}
function hideLogin(){
  $('#login-screen').classList.add('hidden');
  $('#login-error').classList.add('hidden');
}
$$('[data-close]').forEach(b=>b.addEventListener('click',()=>hideModal(b.dataset.close)));
$$('.modal-backdrop').forEach(m=>m.addEventListener('mousedown',e=>{if(e.target===m)hideModal(m.id);}));

function fmtTime(v){const d=new Date(v);const now=new Date();const same=d.toDateString()===now.toDateString();return same?d.toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit'}):d.toLocaleDateString('ru-RU',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function fmtPacketTime(ns){const ms=Number(BigInt(ns||0)/1000000n);return new Date(ms).toLocaleDateString('ru-RU',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function bytesInFlow(f){return Number(f.bytes_c2s||0)+Number(f.bytes_s2c||0)}
function packetsInFlow(f){return Number(f.packets_c2s||0)+Number(f.packets_s2c||0)}
function currentService(){return state.services.find(s=>s.name===state.selectedService)||null;}
function patternById(id){return state.patterns.find(p=>p.id===id);}

function fmtBytes(value){
  const n=Math.max(0,Number(value)||0);const units=['B','KiB','MiB','GiB','TiB'];let v=n,i=0;
  while(v>=1024&&i<units.length-1){v/=1024;i++;}
  const digits=v>=100||i===0?0:v>=10?1:2;return `${v.toFixed(digits)} ${units[i]}`;
}
function fmtCount(value){const n=Math.max(0,Number(value)||0);if(n>=1e9)return `${(n/1e9).toFixed(1)}G`;if(n>=1e6)return `${(n/1e6).toFixed(1)}M`;if(n>=1e3)return `${(n/1e3).toFixed(1)}K`;return String(Math.round(n));}
function fmtBitRate(value){const n=Math.max(0,Number(value)||0);const units=['bit/s','Kbit/s','Mbit/s','Gbit/s','Tbit/s'];let v=n,i=0;while(v>=1000&&i<units.length-1){v/=1000;i++;}const digits=v>=100||i===0?0:v>=10?1:2;return `${v.toFixed(digits)} ${units[i]}`;}
function fmtDuration(seconds){let s=Math.max(0,Math.floor(Number(seconds)||0));const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);s%=3600;const m=Math.floor(s/60);if(d)return `${d}d ${h}h`;if(h)return `${h}h ${m}m`;if(m)return `${m}m ${s%60}s`;return `${s}s`;}
function pct(value,total){return total>0?Math.max(0,(Number(value)||0)*100/Number(total)):0;}
function severity(value,warn,danger){return value>=danger?'danger':value>=warn?'warn':'';}
function setCardSeverity(id,level){const el=$(id);if(el)el.classList.remove('warn','danger');if(el&&level)el.classList.add(level);}
function setBar(id,value){const el=$(id);if(el)el.style.width=`${Math.max(0,Math.min(100,Number(value)||0))}%`;}
function counterRate(current,previous,elapsed){if(previous===null||previous===undefined||!elapsed)return null;return Math.max(0,(Number(current)||0)-(Number(previous)||0))/elapsed;}

function setResourceExpanded(expanded){
  settings.resourcesExpanded=!!expanded;localStorage.setItem('bazalt.resourcesExpanded',expanded?'1':'0');
  $('#resource-panel').classList.toggle('hidden',!expanded);$('#resource-toggle').setAttribute('aria-expanded',expanded?'true':'false');
}
$('#resource-toggle').addEventListener('click',()=>setResourceExpanded(!settings.resourcesExpanded));
$('#resource-minimize').addEventListener('click',()=>setResourceExpanded(false));
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&settings.resourcesExpanded)setResourceExpanded(false);});
setResourceExpanded(settings.resourcesExpanded);

function renderResources(snapshot,now=Date.now()){
  const m=snapshot?.metrics||{};const r=snapshot?.resources||{};const prev=state.lastResourceSample;
  const elapsed=prev?Math.max((now-prev.time)/1000,0.001):0;
  const rate=key=>counterRate(m[key],prev?.metrics?.[key],elapsed);
  const cpuSeconds=Number(r.process_cpu_seconds)||0;
  const cpuCores=prev&&elapsed?Math.max(0,cpuSeconds-(Number(prev.cpuSeconds)||0))/elapsed:null;
  const cpuBudget=Math.max(1,Number(m.cpu_budget)||Number(r.logical_cpus)||1);
  const cpuPct=cpuCores===null?null:(cpuCores*100/cpuBudget);
  const memoryPct=pct(r.memory_scope_used_bytes,r.memory_scope_limit_bytes);
  const rssPct=pct(r.process_rss_bytes,r.memory_scope_limit_bytes);
  const pressure=Number(snapshot?.live_pressure_pct)||0;
  const capturePps=rate('capture_frames');
  const captureByteRate=rate('capture_frame_bytes');
  const pipelineDropRate=prev?(rate('capture_backend_drops')||0)+(rate('capture_drops')||0):null;
  const parseErrorRate=rate('packet_parse_errors');
  const truncatedRate=rate('capture_truncated_packets');
  const fragmentLossRate=prev?(rate('ip_fragment_overlap_drops')||0)+(rate('ip_fragment_expired')||0)+(rate('ip_fragment_evicted')||0):null;
  const tcpGapRate=rate('tcp_gap_events');

  $('#resource-cpu-compact').textContent=cpuPct===null?'--':`${Math.round(cpuPct)}%`;
  $('#resource-rss-compact').textContent=fmtBytes(r.process_rss_bytes).replace(' ','');
  $('#resource-queue-compact').textContent=`${Math.round(pressure)}%`;
  $('#resource-drop-compact').textContent=pipelineDropRate===null?'--':`${pipelineDropRate<10?pipelineDropRate.toFixed(1):Math.round(pipelineDropRate)}/s`;

  $('#resource-cpu').textContent=cpuPct===null?'sampling…':`${cpuPct.toFixed(cpuPct>=10?0:1)}%`;
  $('#resource-cpu-meta').textContent=cpuCores===null?`${cpuBudget} CPU budget`: `${cpuCores.toFixed(2)} cores / ${cpuBudget} budget · ${Number(m.cpu_available)||Number(r.logical_cpus)||0} available`;
  setBar('#resource-cpu-bar',cpuPct===null?0:cpuPct);setCardSeverity('#resource-cpu-card',cpuPct===null?'':severity(cpuPct,80,95));

  $('#resource-memory-scope').textContent=String(r.memory_scope||'host').toUpperCase();
  $('#resource-memory').textContent=r.memory_scope_limit_bytes?`${memoryPct.toFixed(memoryPct>=10?0:1)}%`:fmtBytes(r.process_rss_bytes);
  $('#resource-memory-meta').textContent=r.memory_scope_limit_bytes?`RSS ${fmtBytes(r.process_rss_bytes)} (${rssPct.toFixed(1)}%) · ${fmtBytes(r.memory_scope_used_bytes)} / ${fmtBytes(r.memory_scope_limit_bytes)}`:`RSS ${fmtBytes(r.process_rss_bytes)}`;
  setBar('#resource-memory-bar',memoryPct);setCardSeverity('#resource-memory-card',severity(memoryPct,80,93));

  $('#resource-pressure').textContent=`${Math.round(pressure)}%`;setBar('#resource-pressure-bar',pressure);setCardSeverity('#resource-queue-card',severity(pressure,70,90));

  $('#resource-ingress').textContent=capturePps===null?'sampling…':`${fmtCount(capturePps)} pps`;
  $('#resource-ingress-meta').textContent=captureByteRate===null?`${fmtCount(m.capture_frames)} frames total`:`${(captureByteRate*8/1e6).toFixed(captureByteRate*8/1e6>=10?1:2)} Mbit/s · ${fmtBytes(captureByteRate)}/s`;

  $('#resource-load').textContent=`${Number(r.load_1m||0).toFixed(2)} / ${Number(r.load_5m||0).toFixed(2)} / ${Number(r.load_15m||0).toFixed(2)}`;
  $('#resource-threads').textContent=fmtCount(r.process_threads);
  $('#resource-fds').textContent=fmtCount(r.open_fds);
  $('#resource-uptime').textContent=fmtDuration(r.process_uptime_seconds);
  $('#resource-vmem').textContent=fmtBytes(r.process_virtual_bytes);
  $('#resource-workers').textContent=`Tokio ${m.tokio_workers||0} · Flow ${m.flow_workers||0} · L7 ${m.l7_workers||0} · Matcher ${m.matcher_workers||0} · Replay ${m.replay_workers||0}`;

  const queueDefs=[['PACKET → FLOW','flow'],['FLOW → L7','l7'],['L7 → MATCHER','match'],['METADATA → DB','storage']];
  let hottest=null;
  $('#resource-queues').innerHTML=queueDefs.map(([label,key])=>{
    const depth=Number(m[`${key}_queue_depth`]||0),cap=Number(m[`${key}_queue_capacity`]||0),hwm=Number(m[`${key}_queue_high_watermark`]||0);const qPct=pct(depth,cap);if(!hottest||qPct>hottest.pct)hottest={label,pct:qPct,depth,cap};const level=severity(qPct,70,90);
    return `<div class="resource-queue-row ${level}"><span class="resource-queue-name">${label}</span><div class="resource-queue-track"><span style="width:${Math.min(100,qPct).toFixed(1)}%"></span></div><span class="resource-queue-values">${fmtCount(depth)}/${fmtCount(cap)} · PEAK ${fmtCount(hwm)}</span></div>`;
  }).join('');
  $('#resource-pressure-meta').textContent=hottest&&hottest.cap?`${hottest.label} ${fmtCount(hottest.depth)} / ${fmtCount(hottest.cap)}`:'all queues idle';

  const lossDefs=[
    ['NIC / KERNEL DROPPED PACKETS','capture_backend_drops',true],['BAZALT INPUT QUEUE DROPS','capture_drops',true],
    ['CAPTURE-TRUNCATED PACKETS','capture_truncated_packets',true],['INVALID AF_XDP DESCRIPTORS','capture_backend_invalid_descs',true],
    ['RAW PCAP ARCHIVE DROPS','raw_capture_drops',false],['PACKET PARSER ERRORS','packet_parse_errors',true],
    ['IP FRAGMENTS RECEIVED','ip_fragments_received',false],['IP DATAGRAMS REASSEMBLED','ip_fragments_reassembled',false],
    ['IP FRAGMENT OVERLAP DROPS','ip_fragment_overlap_drops',true],['IP FRAGMENT TIMEOUTS','ip_fragment_expired',true],
    ['IP FRAGMENT CACHE EVICTIONS','ip_fragment_evicted',true],['TCP ACK-INFERRED / FORCED GAPS','tcp_gap_events',true],
    ['TCP MISSING STREAM BYTES','tcp_gap_bytes',true],['REJECTED OFF-SEQUENCE TCP RST','tcp_rejected_resets',false],
    ['UNSUPPORTED PACKETS','packets_ignored',false],['PORT-FILTERED PACKETS','packets_filtered',false],
    ['TCP RETRANSMISSIONS','tcp_retransmits',false],['TCP OUT-OF-ORDER SEGMENTS','tcp_out_of_order',false],
  ];
  $('#resource-loss').innerHTML=lossDefs.map(([label,key,isError])=>{const value=Number(m[key]||0);const itemRate=rate(key);const hot=!!(isError&&itemRate!==null&&itemRate>0);return `<div class="resource-loss-item ${hot?'hot':''}"><span>${label}</span><strong>${fmtCount(value)}</strong><span class="resource-loss-rate">${itemRate===null?'sampling':`${itemRate<10?itemRate.toFixed(2):Math.round(itemRate)}/s`}</span></div>`;}).join('');

  let health='ok';
  if((pipelineDropRate!==null&&pipelineDropRate>0)||(parseErrorRate!==null&&parseErrorRate>0)||(truncatedRate!==null&&truncatedRate>0)||(fragmentLossRate!==null&&fragmentLossRate>0)||(tcpGapRate!==null&&tcpGapRate>0)||pressure>=90||(cpuPct!==null&&cpuPct>=95)||memoryPct>=93)health='danger';
  else if(pressure>=70||(cpuPct!==null&&cpuPct>=80)||memoryPct>=80)health='warn';
  const dot=$('#resource-health-dot');dot.className=`resource-health-dot ${r.supported===false?'unknown':health}`;
  $('#resource-updated').textContent=`${new Date(now).toLocaleTimeString('ru-RU')} · ${String(r.memory_scope||'host')}`;

  state.lastResourceSample={time:now,cpuSeconds,metrics:{...m}};
}

async function loadResources(){
  try{const s=await api('/api/resources');state.resourceStatus=s;renderResources(s);}
  catch(e){const dot=$('#resource-health-dot');dot.className='resource-health-dot unknown';$('#resource-cpu-compact').textContent='!';$('#resource-queue-compact').textContent='!';$('#resource-updated').textContent='telemetry unavailable';}
}

async function loadServices(){
  try{
    state.services=await api('/api/services');
    if(!state.services.some(s=>s.name===state.selectedService))state.selectedService=state.services[0]?.name||'';
    renderServiceTabs();renderPatternServiceOptions();
  }
  catch(e){toast(`Failed to load services: ${e.message}`);}
}
function renderServiceTabs(){
  const root=$('#service-tabs');
  root.innerHTML=state.services.map(s=>`<div class="service-tab"><button class="nav-link ${state.selectedService===s.name?'active':''}" data-service="${esc(s.name)}">${esc(s.name)} #${s.port} (<span data-spm-port="${s.port}">0</span> <u title="Streams per minute">SPM</u>)</button><button class="edit-service" data-edit-service="${s.port}" title="Edit service">✎</button></div>`).join('');
  $$('[data-service]',root).forEach(b=>b.addEventListener('click',()=>{state.selectedService=b.dataset.service||'';state.selectedFlow='';state.offset=0;state.flows=[];renderServiceTabs();loadFlows(true);}));
  $$('[data-edit-service]',root).forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();openServiceModal(state.services.find(s=>s.port===Number(b.dataset.editService)));}));
}
function renderPatternServiceOptions(){const sel=$('#pattern-service');const prev=sel.value;sel.innerHTML='<option value="">Any service</option>'+state.services.map(s=>`<option value="${esc(s.name)}">${esc(s.name)} #${s.port}</option>`).join('');sel.value=prev;}

function openServiceModal(service=null){
  state.serviceEdit=service;
  $('#service-modal-title').textContent=service?'EDIT SERVICE':'NEW SERVICE';
  $('#service-port-row').classList.toggle('hidden',!!service);$('#delete-service').classList.toggle('hidden',!service);
  $('#service-name').value=service?.name||'';$('#service-port').value=service?.port||'';
  $('#service-is-http').checked=service?.http ?? true;
  $('#service-urldecode').checked=service?.urldecode_http_requests ?? false;
  $('#service-merge').checked=service?.merge_adjacent_packets ?? false;
  $('#service-ws').checked=service?.parse_websockets ?? false;
  showModal('service-modal');setTimeout(()=>$('#service-name').focus(),0);
}
$('#add-service').addEventListener('click',()=>openServiceModal());
$('#service-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const payload={name:$('#service-name').value.trim(),http:$('#service-is-http').checked,urldecode_http_requests:$('#service-urldecode').checked,merge_adjacent_packets:$('#service-merge').checked,parse_websockets:$('#service-ws').checked};
  if(!payload.name)return toast('Service name is required.');
  try{
    let saved;
    if(state.serviceEdit){saved=await api(`/api/services/${state.serviceEdit.port}`,{method:'PUT',body:JSON.stringify(payload)});}
    else{const port=Number($('#service-port').value);if(!Number.isInteger(port)||port<1||port>65535)return toast('Port must be between 1 and 65535.');saved=await api('/api/services',{method:'POST',body:JSON.stringify({port,...payload})});}
    hideModal('service-modal');state.selectedService=saved.name;await loadServices();await loadFlows(true);toast(`Service ${saved.name} #${saved.port} saved.`,'success');
  }catch(err){toast(`Failed to ${state.serviceEdit?'edit':'create'} service: ${err.message}`);}
});
$('#delete-service').addEventListener('click',async()=>{if(!state.serviceEdit)return;if(!confirm(`Delete ${state.serviceEdit.name} #${state.serviceEdit.port}?`))return;try{await api(`/api/services/${state.serviceEdit.port}`,{method:'DELETE'});if(state.selectedService===state.serviceEdit.name)state.selectedService='';hideModal('service-modal');await loadServices();await loadFlows(true);toast('Service deleted.','success');}catch(e){toast(`Failed to delete service: ${e.message}`);}});

async function loadPatterns(){try{state.patterns=await api('/api/patterns');renderPatternsMenu();}catch(e){toast(`Failed to load patterns: ${e.message}`);}}
function patternValue(p){if(p.kind==='regex')return `/${p.expression}/`;if(p.kind==='binary')return `0x${p.expression}`;return `'${p.expression}'`;}
function directionText(p){return p.direction_type==='input'?'in request':p.direction_type==='output'?'in response':'anywhere';}
function renderPatternsMenu(){
  $('#patterns-menu-items').innerHTML=state.patterns.map(p=>`<div class="dropdown-item ${p.action==='ignore'?'ignore-pattern':''}"><div class="pattern-menu-item"><div class="pattern-description" data-select-pattern="${p.id}">${p.enabled?`<strong style="color:${p.action==='find'?esc(p.color):'inherit'}">${esc(p.name)}</strong>`:`<s style="color:${esc(p.color)}">${esc(p.name)}</s>`}: <code>${esc(patternValue(p))}</code>; ${p.action==='find'?'search':'ignore'} ${directionText(p)} ${p.service?`of service ${esc(p.service)}`:'of any service'}</div><div class="pattern-actions"><button class="btn btn-outline-info btn-sm" data-edit-pattern="${p.id}" title="Edit pattern">✎</button>${p.action==='find'?`<button class="btn btn-outline-warning btn-sm" data-lookback="${p.id}" title="Apply pattern to older streams">↶</button>`:''}<button class="btn ${p.enabled?'btn-outline-danger':'btn-outline-success'} btn-sm" data-toggle-pattern="${p.id}" title="${p.enabled?'Stop matching streams with this pattern':'Start matching streams with this pattern again'}">${p.enabled?'Ⅱ':'▶'}</button><button class="btn btn-outline-danger btn-sm" data-delete-pattern="${p.id}" title="Permanently delete this pattern">⌫</button></div></div></div>`).join('');
  $$('[data-select-pattern]').forEach(el=>el.addEventListener('click',()=>{state.selectedPattern=el.dataset.selectPattern;$('#patterns-dropdown').classList.remove('open');renderSelectedPattern();loadFlows(true);}));
  $$('[data-edit-pattern]').forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();openPatternModal(patternById(b.dataset.editPattern));}));
  $$('[data-lookback]').forEach(b=>b.addEventListener('click',async e=>{e.stopPropagation();try{await api(`/api/patterns/${b.dataset.lookback}/lookback`,{method:'POST'});toast('Lookback queued.','success');}catch(err){toast(`Failed to queue lookback: ${err.message}`);}}));
  $$('[data-toggle-pattern]').forEach(b=>b.addEventListener('click',async e=>{e.stopPropagation();const p=patternById(b.dataset.togglePattern);try{await api(`/api/patterns/${p.id}/enabled`,{method:'PATCH',body:JSON.stringify({enabled:!p.enabled})});await loadPatterns();}catch(err){toast(err.message);}}));
  $$('[data-delete-pattern]').forEach(b=>b.addEventListener('click',async e=>{e.stopPropagation();const p=patternById(b.dataset.deletePattern);if(!confirm(`Permanently delete pattern "${p.name}"?`))return;try{await api(`/api/patterns/${p.id}`,{method:'DELETE'});if(state.selectedPattern===p.id)state.selectedPattern='';await loadPatterns();renderSelectedPattern();loadFlows(true);}catch(err){toast(err.message);}}));
}
function renderSelectedPattern(){const p=patternById(state.selectedPattern);$('#selected-pattern').textContent=state.selectedPattern?(p?`[Selected: ${p.name}]`:'[Invalid pattern]'):'';}
$('#patterns-toggle').addEventListener('click',e=>{e.stopPropagation();$('#patterns-dropdown').classList.toggle('open');});
document.addEventListener('click',e=>{if(!$('#patterns-dropdown').contains(e.target))$('#patterns-dropdown').classList.remove('open');});
$('#all-patterns').addEventListener('click',()=>{state.selectedPattern='';renderSelectedPattern();$('#patterns-dropdown').classList.remove('open');loadFlows(true);});
$('#add-pattern').addEventListener('click',e=>{e.stopPropagation();openPatternModal();});
$('#pattern-action').addEventListener('change',()=>$('#pattern-color-row').classList.toggle('hidden',$('#pattern-action').value==='ignore'));

function openPatternModal(pattern=null){
  state.patternEdit=pattern;$('#pattern-modal-title').textContent=pattern?'EDIT PATTERN':'NEW PATTERN';$$('.create-only',$('#pattern-modal')).forEach(e=>e.classList.toggle('hidden',!!pattern));
  $('#pattern-name').value=pattern?.name||'';$('#pattern-value').value=pattern?.expression||'';$('#pattern-action').value=pattern?.action||'find';$('#pattern-color').value=pattern?.color||'#ff7474';$('#pattern-kind').value=pattern?.kind||'text';$('#pattern-direction').value=pattern?.direction_type||'both';$('#pattern-service').value=pattern?.service||'';$('#pattern-color-row').classList.toggle('hidden',(pattern?.action||'find')==='ignore');
  $('#patterns-dropdown').classList.remove('open');showModal('pattern-modal');setTimeout(()=>$('#pattern-name').focus(),0);
}
$('#pattern-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const existing=state.patternEdit;
  const payload={name:$('#pattern-name').value.trim(),expression:existing?.expression||$('#pattern-value').value,kind:existing?.kind||$('#pattern-kind').value,action:existing?.action||$('#pattern-action').value,color:$('#pattern-color').value,direction_type:existing?.direction_type||$('#pattern-direction').value,service:existing?.service??($('#pattern-service').value||null),view:existing?.view||null};
  if(!payload.name||!payload.expression)return toast('Name and pattern are required.');
  try{if(existing)await api(`/api/patterns/${existing.id}`,{method:'PUT',body:JSON.stringify({...payload,enabled:existing.enabled})});else await api('/api/patterns',{method:'POST',body:JSON.stringify(payload)});hideModal('pattern-modal');await loadPatterns();toast(existing?'Pattern updated.':'Pattern created; historical lookback queued.','success');}catch(err){toast(`Failed to save pattern: ${err.message}`);}
});

function flowParams(){const p=new URLSearchParams({limit:String(settings.pageSize),offset:String(state.offset),service:state.selectedService});if(state.selectedPattern)p.set('pattern_id',state.selectedPattern);if(state.favoritesOnly)p.set('favorite','true');if(state.ua.value){const key={contains:'user_agent',equals:'user_agent_equals',not_contains:'user_agent_not_contains',regex:'user_agent_regex'}[state.ua.mode];p.set(key,state.ua.value);}return p;}
async function loadFlows(reset=false){if(reset){state.offset=0;state.flows=[];}if(!state.selectedService){renderFlows();return;}try{const data=await api(`/api/flows?${flowParams()}`);if(reset)state.flows=data.items;else state.flows.push(...data.items.filter(x=>!state.flows.some(y=>y.flow_id===x.flow_id)));state.offset=state.flows.length;renderFlows();}catch(e){toast(`Failed to load streams: ${e.message}`);}}
function renderFlows(){
  $('#stream-list').innerHTML=state.flows.map(f=>{const pats=(f.pattern_ids||[]).map(id=>patternById(id)).filter(Boolean);return `<li class="stream-item ${f.favorite?'favorite':''} ${state.selectedFlow===f.flow_id?'active':''}" id="stream-${f.flow_id}"><a href="#" data-flow="${f.flow_id}"><button class="stream-star" data-favorite="${f.flow_id}" title="Favorite">${f.favorite?'★':'☆'}</button>${esc(f.flow_id)} ${String(f.protocol||'').toUpperCase()}<br>${fmtTime(f.started_at)}${f.ended_at&&f.ended_at!==f.started_at?` - ${fmtTime(f.ended_at)}`:''}${f.user_agent?`<br>UA ${esc(f.user_agent)}`:''}<br>${bytesInFlow(f)} B / ${packetsInFlow(f)} PKT<br>${pats.map(p=>`<span class="stream-pattern" style="color:${esc(p.color)}">${esc(p.name)}</span>`).join('')}</a></li>`;}).join('');
  $$('[data-flow]').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();openFlow(a.dataset.flow);}));
  $$('[data-favorite]').forEach(b=>b.addEventListener('click',async e=>{e.stopPropagation();e.preventDefault();const f=state.flows.find(x=>x.flow_id===b.dataset.favorite);try{await api(`/api/flows/${f.flow_id}/favorite`,{method:'POST',body:JSON.stringify({favorite:!f.favorite})});f.favorite=!f.favorite;if(state.favoritesOnly&&!f.favorite)state.flows=state.flows.filter(x=>x.flow_id!==f.flow_id);renderFlows();}catch(err){toast(`Failed to fav stream: ${err.message}`);}}));
}
$('#load-more').addEventListener('click',()=>loadFlows(false));
$('#pause-btn').addEventListener('click',()=>{state.paused=!state.paused;$('#pause-btn').textContent=state.paused?'▶':'Ⅱ';$('#pause-btn').className=`btn btn-sm ${state.paused?'btn-danger':'btn-outline-success'}`;$('#pause-btn').title=state.paused?'Continue':'Pause new streams';});
$('#favorites-btn').addEventListener('click',()=>{state.favoritesOnly=!state.favoritesOnly;$('#favorites-btn').className=`btn btn-sm ${state.favoritesOnly?'btn-danger':'btn-outline-danger'}`;loadFlows(true);});
$('#hexdump-btn').addEventListener('click',()=>{state.hexdump=!state.hexdump;$('#hexdump-btn').title=state.hexdump?'Switch to text view':'Switch to hexdump view';if(state.selectedFlow)openFlow(state.selectedFlow);});
$('#scroll-top-btn').addEventListener('click',()=>$('.sidebar-sticky').scrollTo({top:0,behavior:'smooth'}));

function hexdump(text){const bytes=new TextEncoder().encode(text);const width=settings.hexBlock;const base=settings.lineBase;const lines=[];for(let i=0;i<bytes.length;i+=width){const block=bytes.slice(i,i+width);const addr=i.toString(base).toUpperCase().padStart(10,'0');const hex=[...block].map(b=>b.toString(16).toUpperCase().padStart(2,'0')).join(' ').padEnd(width*3-1,' ');const chars=[...block].map(b=>b>=32&&b<127?String.fromCharCode(b):'.').join('').padEnd(width,' ');lines.push(`${addr}: ${hex} |${chars}|`);}return lines.join('\n');}
function highlightedPreview(item){if(state.hexdump)return esc(hexdump(item.preview||''));const hits=(item.matches||[]).map(h=>({...h,p:patternById(h.pattern_id)})).filter(h=>h.p).sort((a,b)=>a.offset_start-b.offset_start);if(!hits.length)return esc(item.preview||'');let out='',pos=0;const text=item.preview||'';for(const h of hits){let a=Math.max(0,Number(h.offset_start)-Number(item.offset));let b=Math.max(a,Number(h.offset_end)-Number(item.offset));if(a>=text.length)continue;b=Math.min(b,text.length);if(a<pos)a=pos;if(b<=a)continue;out+=esc(text.slice(pos,a));out+=`<span class="pattern-hit" style="background-color:${esc(h.p.color)}" title="${esc(h.p.name)}">${esc(text.slice(a,b))}</span>`;pos=b;}return out+esc(text.slice(pos));}
async function openFlow(id){
  state.selectedFlow=id;renderFlows();
  try{const [detail,content]=await Promise.all([api(`/api/flows/${id}`),api(`/api/flows/${id}/content`)]);const f=detail.flow;$('#empty-content').classList.add('hidden');$('#stream-content').classList.remove('hidden');$('#stream-heading').innerHTML=`<strong>${esc(f.service||'-')}</strong><span class="heading-sep">|</span>${esc(f.src_ip)}:${f.src_port} <span class="flow-arrow">&gt;</span> ${esc(f.dst_ip)}:${f.dst_port}<span class="heading-sep">|</span>${String(f.protocol||'').toUpperCase()}<span class="heading-sep">|</span>${packetsInFlow(f)} PKT / ${bytesInFlow(f)} B${detail.favorite?' <span class="favorite-mark">★</span>':''}`;
    $('#packet-list').innerHTML=content.items.map((item,i)=>`<div class="packet ${item.request?'request':'response'}"><div class="packet-head"><span class="packet-side">${item.request?'REQ':'RES'}</span><span class="packet-seq">#${i+1}</span><span class="packet-time">${fmtPacketTime(item.timestamp_ns)}</span><span class="view-tag">${esc(viewLabel(item.view))}</span><span class="packet-actions"><button class="btn btn-link" data-copy-hex="${item.id}">HEX</button><button class="btn btn-link" data-copy-text="${item.id}">TEXT</button><button class="btn btn-link" data-copy-python="${item.id}">PY</button></span></div><pre class="packet-content ${state.hexdump?'hex':''}">${highlightedPreview(item)}</pre></div>`).join('');
    bindCopyButtons();
  }catch(e){toast(`Failed to load stream: ${e.message}`);}
}
async function copyContent(id,format){const data=await api(`/api/content/${id}?format=${format}`);if(format==='hex')return data.data;if(format==='text')return data.data;return data.data;}
function bindCopyButtons(){
  $$('[data-copy-hex]').forEach(b=>b.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(await copyContent(b.dataset.copyHex,'hex'));toast('HEX copied.','success');}catch(e){toast(e.message);}}));
  $$('[data-copy-text]').forEach(b=>b.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(await copyContent(b.dataset.copyText,'text'));toast('Text copied.','success');}catch(e){toast(e.message);}}));
  $$('[data-copy-python]').forEach(b=>b.addEventListener('click',async()=>{try{const h=await copyContent(b.dataset.copyPython,'hex');await navigator.clipboard.writeText(`bytes.fromhex('${h}')`);toast('Python bytes copied.','success');}catch(e){toast(e.message);}}));
}

document.addEventListener('keydown',e=>{if(!e.ctrlKey||!state.flows.length)return;const i=state.flows.findIndex(f=>f.flow_id===state.selectedFlow);let ni=i;if(e.key==='ArrowUp')ni=Math.max(0,i-1);else if(e.key==='ArrowDown')ni=Math.min(state.flows.length-1,i+1);else if(e.key==='Home')ni=0;else if(e.key==='End')ni=state.flows.length-1;else return;e.preventDefault();const f=state.flows[ni];if(f){openFlow(f.flow_id);document.getElementById(`stream-${f.flow_id}`)?.scrollIntoView({behavior:'smooth',block:'center'});}});

$('#ua-filter-btn').addEventListener('click',()=>{$('#ua-form [name=mode]').value=state.ua.mode;$('#ua-form [name=value]').value=state.ua.value;showModal('ua-modal');});
$('#ua-form').addEventListener('submit',e=>{e.preventDefault();state.ua={mode:$('#ua-form [name=mode]').value,value:$('#ua-form [name=value]').value.trim()};hideModal('ua-modal');$('#ua-filter-btn').className=`btn btn-sm ${state.ua.value?'btn-primary':'btn-outline-secondary'}`;loadFlows(true);});
$('#clear-ua').addEventListener('click',()=>{state.ua={mode:'contains',value:''};hideModal('ua-modal');$('#ua-filter-btn').className='btn btn-sm btn-outline-secondary';loadFlows(true);});


function ipv4ToInt(ip){const parts=String(ip||'').split('.').map(Number);if(parts.length!==4||parts.some(x=>!Number.isInteger(x)||x<0||x>255))return null;return (((parts[0]<<24)>>>0)|((parts[1]<<16)>>>0)|((parts[2]<<8)>>>0)|parts[3])>>>0;}
function parseRuleTarget(target){const [raw,prefixRaw]=String(target||'').split('/');const value=ipv4ToInt(raw);if(value===null)return null;const prefix=prefixRaw===undefined?32:Number(prefixRaw);if(!Number.isInteger(prefix)||prefix<0||prefix>32)return null;const mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0;return {target:String(target),network:(value&mask)>>>0,prefix};}
function effectiveTopologyRule(ip,rules){const value=ipv4ToInt(ip);if(value===null)return null;let best=null;for(const rule of rules||[]){const parsed=parseRuleTarget(rule.target);if(!parsed)continue;const mask=parsed.prefix===0?0:(0xffffffff<<(32-parsed.prefix))>>>0;if(((value&mask)>>>0)!==parsed.network)continue;if(!best||parsed.prefix>best.prefix)best={...parsed,rule};}return best?.rule||null;}
function exactTopologyRule(target){return state.topology?.enforcement?.rules?.find(rule=>rule.target===target)||null;}
function renderTopologyAudit(entries){const body=$('#topology-audit-body');if(!body)return;const rows=entries||[];body.innerHTML=rows.length?rows.map(entry=>`<tr><td>${esc(fmtTime(entry.at))}</td><td>${esc(String(entry.action||'').toUpperCase())}</td><td>${esc(entry.target||'-')}</td><td>${entry.drop_percent?`${esc(entry.drop_percent)}%`:'-'}</td><td>${entry.action==='set'?(entry.ttl_seconds?esc(fmtDuration(entry.ttl_seconds)):'UNTIL DISABLED'):'-'}</td></tr>`).join(''):'<tr><td colspan="5">No throttle actions yet.</td></tr>';}
function ruleMeta(rule,sourceTarget=''){if(!rule)return '';const inherited=sourceTarget&&rule.target!==sourceTarget?` via ${rule.target}`:'';const expiry=rule.expires_at?` · until ${fmtTime(rule.expires_at)}`:' · until disabled';const dropped=Number(rule.dropped_packets||0)?` · ${fmtCount(rule.dropped_packets)} dropped`:'';return `${inherited}${expiry}${dropped}`;}
function renderTopology(data){
  state.topology=data;const t=data?.traffic||{};const e=data?.enforcement||{};const groups=t.groups||[];const rules=e.rules||[];
  $('#topology-group-count').textContent=fmtCount(t.group_count||0);$('#topology-prefix').textContent=`automatic IPv4 /${t.group_prefix_v4??24} source groups`;
  $('#topology-source-count').textContent=fmtCount(t.source_count||0);$('#topology-source-ttl').textContent=`hide after ${fmtDuration(t.source_ttl_seconds||0)} idle · cap ${fmtCount(t.source_capacity||0)}`;
  const capacityNote=$('#topology-capacity-note');const saturated=Boolean(t.source_capacity_saturated);capacityNote.classList.toggle('hidden',!saturated);capacityNote.textContent=saturated?`Source tracking cap reached (${fmtCount(t.source_capacity||0)}). Overflow traffic is still counted in observed totals but cannot be grouped per source: ${fmtBitRate(t.untracked_bits_per_second||0)}, ${fmtCount(t.untracked_packets_per_second||0)} pkt/s.`:'';
  const viewNote=$('#topology-view-note');const viewTruncated=Boolean(t.view_truncated);viewNote.classList.toggle('hidden',!viewTruncated);viewNote.textContent=viewTruncated?`Large topology: showing the busiest ${fmtCount(t.returned_group_count||0)} of ${fmtCount(t.group_count||0)} groups and ${fmtCount(t.returned_source_count||0)} of ${fmtCount(t.source_count||0)} tracked sources. Aggregate rates and totals still include all tracked traffic.`:'';
  $('#topology-ingress-rate').textContent=fmtBitRate(t.bits_per_second||0);$('#topology-ingress-pps').textContent=`${fmtCount(t.packets_per_second||0)} packets/s · ${t.rate_window_seconds||5}s window`;
  $('#topology-enforcement').textContent=e.available?'READY':'OFF';$('#topology-enforcement-meta').textContent=e.available?`${e.interface||'-'} · ${rules.length} active rule${rules.length===1?'':'s'}`:'set BAZALT_THROTTLE_INTERFACE';
  const note=$('#topology-enforcement-note');note.className=`topology-enforcement-note ${e.available?'ok':'warn'}`;note.textContent=e.available?`Real XDP packet drop is armed on ${e.interface}. Throttle can be applied to a whole auto-discovered group or to one source IP.`:'Topology is active. Enforcement is intentionally disabled until BAZALT_THROTTLE_INTERFACE points at the real ingress/forwarding interface.';
  renderTopologyAudit(e.audit||[]);
  if(!groups.length){$('#topology-groups').innerHTML='<div class="topology-empty">Waiting for IPv4 source traffic…</div>';return;}
  const totalBps=Math.max(1,Number(t.bits_per_second)||0);
  $('#topology-groups').innerHTML=groups.map(group=>{
    const groupShare=Math.min(100,Math.max(0,Number(group.bits_per_second||0)*100/totalBps));const groupRule=rules.find(rule=>rule.target===group.cidr);const groupMax=Math.max(1,Number(group.bits_per_second)||0);
    const rows=(group.sources||[]).map(src=>{const rule=effectiveTopologyRule(src.ip,rules);const share=Math.min(100,Math.max(0,Number(src.bits_per_second||0)*100/groupMax));return `<tr><td><span class="topology-source-ip">${esc(src.ip)}</span></td><td class="topology-source-rate"><strong>${fmtBitRate(src.bits_per_second||0)}</strong><small>${fmtCount(src.packets_per_second||0)} pkt/s</small></td><td><div class="topology-source-bar" title="${share.toFixed(1)}% of group"><span style="width:${share}%"></span></div></td><td>${fmtBytes(src.bytes_total||0)}<br><small>${fmtCount(src.packets_total||0)} packets</small></td><td>${rule?`<span class="topology-throttle-state">DROP ${rule.drop_percent}%</span><span class="topology-rule-meta">${esc(ruleMeta(rule,src.ip))}</span>`:'<span class="topology-throttle-state off">NO THROTTLE</span>'}</td><td><button class="btn btn-sm ${rule?'btn-outline-warning':'btn-secondary'}" data-throttle-target="${esc(src.ip)}">THROTTLE</button></td></tr>`;}).join('');
    const visibleSources=group.sources?.length||0;const totalSources=group.source_count??visibleSources;const sourceLabel=group.sources_truncated?`${fmtCount(totalSources)} sources · showing top ${fmtCount(visibleSources)}`:`${fmtCount(totalSources)} source${totalSources===1?'':'s'}`;
    return `<section class="topology-group"><div class="topology-group-head"><div class="topology-group-title"><strong>${esc(group.cidr)}</strong><span>${sourceLabel} · ${groupShare.toFixed(1)}% of observed traffic</span></div><div class="topology-group-rate"><strong>${fmtBitRate(group.bits_per_second||0)}</strong><small>${fmtCount(group.packets_per_second||0)} pkt/s · ${fmtBytes(group.bytes_total||0)} total</small>${groupRule?`<span class="topology-rule-meta">DROP ${groupRule.drop_percent}%${esc(ruleMeta(groupRule))}</span>`:''}</div><button class="btn btn-sm ${groupRule?'btn-outline-warning':'btn-secondary'}" data-throttle-target="${esc(group.cidr)}">GROUP THROTTLE</button></div><div class="topology-share"><span style="width:${groupShare}%"></span></div><table class="topology-source-table"><thead><tr><th>SOURCE</th><th>LIVE RATE</th><th>GROUP SHARE</th><th>TOTAL OBSERVED</th><th>ENFORCEMENT</th><th>ACTION</th></tr></thead><tbody>${rows}</tbody></table></section>`;
  }).join('');
  $$('[data-throttle-target]').forEach(button=>button.addEventListener('click',()=>openThrottle(button.dataset.throttleTarget)));
}
async function loadTopology(){if(state.topologyLoading)return;state.topologyLoading=true;try{renderTopology(await api('/api/topology'));}catch(e){if(e.message!=='authentication required')toast(`Failed to load topology: ${e.message}`);}finally{state.topologyLoading=false;}}
function openTopology(){state.topologyOpen=true;if(state.managementOpen)closeManagement();$('#topology-view').classList.remove('hidden');$('#open-topology').classList.add('active');setResourceExpanded(false);loadTopology();}
function closeTopology(){state.topologyOpen=false;$('#topology-view').classList.add('hidden');$('#open-topology').classList.remove('active');}
function openThrottle(target){const enforcement=state.topology?.enforcement;if(!enforcement?.available){toast('XDP enforcement is disabled. Configure BAZALT_THROTTLE_INTERFACE first.');return;}const rule=exactTopologyRule(target);$('#throttle-target').value=target;$('#throttle-target-label').textContent=target;const percent=Number(rule?.drop_percent||25);$('#throttle-percent').value=percent;$('#throttle-percent-range').value=percent;$('#throttle-ttl').value='300';$('#throttle-disable').classList.toggle('hidden',!rule);showModal('throttle-modal');}
$('#open-topology').addEventListener('click',()=>state.topologyOpen?closeTopology():openTopology());
$('#topology-close').addEventListener('click',closeTopology);$('#topology-refresh').addEventListener('click',loadTopology);
$('#throttle-percent-range').addEventListener('input',()=>{$('#throttle-percent').value=$('#throttle-percent-range').value;});$('#throttle-percent').addEventListener('input',()=>{$('#throttle-percent-range').value=Math.max(1,Math.min(100,Number($('#throttle-percent').value)||1));});
$('#throttle-form').addEventListener('submit',async e=>{e.preventDefault();const target=$('#throttle-target').value;const drop_percent=Math.max(1,Math.min(100,Number($('#throttle-percent').value)||25));const ttl_seconds=Math.max(0,Number($('#throttle-ttl').value)||0);try{await api('/api/topology/throttle',{method:'PUT',body:JSON.stringify({target,drop_percent,ttl_seconds})});hideModal('throttle-modal');await loadTopology();toast(`Throttle ${drop_percent}% applied to ${target}.`,'success');}catch(err){toast(`Throttle failed: ${err.message}`);}});
$('#throttle-disable').addEventListener('click',async()=>{const target=$('#throttle-target').value;try{await api('/api/topology/throttle',{method:'DELETE',body:JSON.stringify({target})});hideModal('throttle-modal');await loadTopology();toast(`Throttle disabled for ${target}.`,'success');}catch(err){toast(`Failed to disable throttle: ${err.message}`);}});


function managementTableLabel(name){
  return ({flows:'Flows',http_messages:'HTTP messages',content_index:'Payload index',matches:'Pattern matches'})[name]||name;
}
function renderManagement(data){
  state.management=data;
  $('#mgmt-total-bytes').textContent=fmtBytes(data.total_managed_bytes);
  $('#mgmt-segment-bytes').textContent=fmtBytes(data.segments?.bytes);
  $('#mgmt-segment-files').textContent=`${fmtCount(data.segments?.files)} segment files`;
  $('#mgmt-clickhouse-bytes').textContent=fmtBytes(data.clickhouse?.total_bytes_on_disk);
  $('#mgmt-clickhouse-rows').textContent=`${fmtCount(data.clickhouse?.total_rows)} rows · ${fmtCount(data.clickhouse?.active_parts)} active parts`;
  $('#mgmt-postgres-bytes').textContent=fmtBytes(data.postgres_bytes);
  const rows=data.clickhouse?.tables||[];
  $('#mgmt-table-body').innerHTML=rows.length?rows.map(row=>{
    const avg=Number(row.rows)>0?Number(row.bytes_on_disk)/Number(row.rows):0;
    return `<tr><td>${esc(managementTableLabel(row.table))}<br><small>${esc(row.table)}</small></td><td>${fmtCount(row.rows)}</td><td>${fmtBytes(row.bytes_on_disk)}</td><td>${fmtBytes(avg)}</td><td>${fmtCount(row.active_parts)}</td></tr>`;
  }).join(''):'<tr><td colspan="5">No active ClickHouse parts.</td></tr>';
  $('#mgmt-auth-status').textContent=data.auth_enabled?'Authentication is enabled. API, metrics and WebSocket access require a valid session or HTTP Basic credentials.':'Authentication is disabled by configuration (development mode).';
  $('#logout-btn').classList.toggle('hidden',!data.auth_enabled);
}
async function loadManagement(){
  try{const data=await api('/api/management/storage');renderManagement(data);}
  catch(e){if(e.message!=='authentication required')toast(`Failed to load management data: ${e.message}`);}
}
function openManagement(){state.managementOpen=true;if(state.topologyOpen)closeTopology();$('#management-view').classList.remove('hidden');$('#open-management').classList.add('active');setResourceExpanded(false);loadManagement();updateRetentionPreview();}
function closeManagement(){state.managementOpen=false;$('#management-view').classList.add('hidden');$('#open-management').classList.remove('active');}
function retentionSeconds(){return Math.floor(Math.max(1,Number($('#retention-value').value)||1)*Math.max(1,Number($('#retention-unit').value)||1));}
function updateRetentionPreview(){const cutoff=new Date(Date.now()-retentionSeconds()*1000);$('#retention-preview').textContent=`Cutoff: ${cutoff.toLocaleString('ru-RU')} (${cutoff.toISOString()})`;}
$('#open-management').addEventListener('click',()=>state.managementOpen?closeManagement():openManagement());
$('#management-close').addEventListener('click',closeManagement);
$('#management-refresh').addEventListener('click',loadManagement);
$('#retention-value').addEventListener('input',updateRetentionPreview);
$('#retention-unit').addEventListener('change',updateRetentionPreview);
$('#retention-confirm').addEventListener('input',()=>{$('#retention-submit').disabled=$('#retention-confirm').value.trim()!=='DELETE';});
$('#retention-form').addEventListener('submit',async e=>{
  e.preventDefault();
  if($('#retention-confirm').value.trim()!=='DELETE')return;
  const button=$('#retention-submit');button.disabled=true;button.textContent='DELETING…';
  const result=$('#retention-result');result.className='management-result';result.textContent='Retention cleanup is running. Replay is temporarily paused while immutable storage is mutated.';
  try{
    const out=await api('/api/management/cleanup',{method:'POST',body:JSON.stringify({older_than_seconds:retentionSeconds(),confirm:'DELETE'})});
    result.className='management-result success';result.textContent=`Cleanup complete. Cutoff: ${out.cutoff}\nPayload segments deleted: ${fmtCount(out.segments_deleted)} (${fmtBytes(out.segment_bytes_deleted)})\n${out.note||''}`;
    $('#retention-confirm').value='';await loadManagement();await loadFlows(true);
  }catch(err){result.className='management-result error';result.textContent=`Cleanup failed: ${err.message}`;}
  finally{button.textContent='DELETE OLD TRAFFIC';button.disabled=$('#retention-confirm').value.trim()!=='DELETE';}
});
$('#logout-btn').addEventListener('click',async()=>{try{await api('/auth/logout',{method:'POST'});}catch{}closeManagement();showLogin();});

$('#login-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const button=$('#login-submit'),error=$('#login-error');button.disabled=true;error.classList.add('hidden');
  try{
    const response=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('#login-username').value,password:$('#login-password').value})});
    if(!response.ok){let detail='Authentication failed';try{detail=(await response.json()).error||detail;}catch{}throw new Error(detail);}
    $('#login-password').value='';hideLogin();await bootApp();
  }catch(err){error.textContent=err.message;error.classList.remove('hidden');}
  finally{button.disabled=false;}
});

$('#open-settings').addEventListener('click',()=>{$('#settings-form [name=hex_block]').value=settings.hexBlock;$('#settings-form [name=line_base]').value=settings.lineBase;$('#settings-form [name=page_size]').value=settings.pageSize;showModal('settings-modal');});
$('#settings-form').addEventListener('submit',e=>{e.preventDefault();settings.hexBlock=Math.max(4,Math.min(64,Number($('#settings-form [name=hex_block]').value)||16));settings.lineBase=Number($('#settings-form [name=line_base]').value)===16?16:10;settings.pageSize=Math.max(10,Math.min(500,Number($('#settings-form [name=page_size]').value)||100));localStorage.setItem('bazalt.hexBlock',settings.hexBlock);localStorage.setItem('bazalt.lineBase',settings.lineBase);localStorage.setItem('bazalt.pageSize',settings.pageSize);hideModal('settings-modal');loadFlows(true);});

async function loadStatus(){
  try{
    const s=await api('/api/status');state.status=s;const m=s.metrics;const now=Date.now();
    if(state.lastCounters){
      const elapsedMs=Math.max(now-state.lastCounters.time,1);
      const streams=Math.max(0,m.flows_completed-state.lastCounters.flows);
      $('#spm').textContent=Math.round(streams*60000/elapsedMs);
      $('#pps').textContent=m.flows_completed?Math.round((m.packets_received/m.flows_completed)*10)/10:0;
    }
    for(const svc of state.services){
      const el=document.querySelector(`[data-spm-port="${svc.port}"]`);
      if(el)el.textContent=Number(s.service_spm?.[svc.name]||0);
    }
    state.lastCounters={time:now,flows:m.flows_completed,packets:m.packets_received};
  }catch(e){$('#spm').textContent='!';$('#pps').textContent='!';}
}
let liveRefreshTimer=null;
let selectedFlowDirty=false;
function scheduleLiveRefresh(event){
  if(state.paused)return;
  let msg=null;
  try{msg=JSON.parse(event?.data||'null');}catch{}
  if(msg?.event==='new_match'&&msg.pattern_id){
    const flow=state.flows.find(f=>f.flow_id===msg.flow_id);
    if(flow){flow.pattern_ids=flow.pattern_ids||[];if(!flow.pattern_ids.includes(msg.pattern_id)){flow.pattern_ids.push(msg.pattern_id);renderFlows();}}
  }
  if(msg?.flow_id&&msg.flow_id===state.selectedFlow)selectedFlowDirty=true;
  // Throttle rather than debounce: under continuous traffic we still refresh,
  // but never turn every metadata event into a multi-query ClickHouse burst.
  if(liveRefreshTimer)return;
  liveRefreshTimer=setTimeout(async()=>{
    liveRefreshTimer=null;
    const refreshSelected=selectedFlowDirty;
    selectedFlowDirty=false;
    await loadFlows(true);
    if(refreshSelected&&state.selectedFlow)await openFlow(state.selectedFlow);
  },500);
}
function connectLive(){if(!$('#login-screen').classList.contains('hidden'))return;if(state.ws)try{state.ws.close()}catch{}const proto=location.protocol==='https:'?'wss':'ws';const ws=new WebSocket(`${proto}://${location.host}/api/live`);state.ws=ws;ws.onmessage=scheduleLiveRefresh;ws.onclose=()=>{if($('#login-screen').classList.contains('hidden'))setTimeout(connectLive,3000);};}

let intervalsStarted=false;
async function bootApp(){
  hideLogin();
  await Promise.all([loadServices(),loadPatterns(),loadResources()]);
  renderSelectedPattern();await loadFlows(true);await loadStatus();connectLive();
  if(!intervalsStarted){
    intervalsStarted=true;
    setInterval(()=>{if($('#login-screen').classList.contains('hidden'))loadResources();},2000);
    setInterval(()=>{if($('#login-screen').classList.contains('hidden'))loadStatus();},5000);
    setInterval(()=>{if($('#login-screen').classList.contains('hidden')&&state.topologyOpen)loadTopology();},1000);
    setInterval(async()=>{if($('#login-screen').classList.contains('hidden')&&!state.paused){await loadFlows(true);if(state.selectedFlow)await openFlow(state.selectedFlow);}},30000);
  }
}
async function boot(){
  try{
    const probe=await fetch('/api/status');
    if(probe.status===403){showLogin();return;}
    if(!probe.ok)throw new Error(`${probe.status} ${probe.statusText}`);
    await bootApp();
  }catch(err){toast(`Failed to initialize BAZALT: ${err.message}`);}
}
boot();
