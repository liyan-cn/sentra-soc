'use strict';
const $=s=>document.querySelector(s);
function setListTab(name){document.querySelectorAll('.list-tab').forEach(tab=>{const selected=tab.dataset.listTab===name;tab.classList.toggle('active',selected);tab.classList.toggle('secondary',!selected);tab.setAttribute('aria-pressed',String(selected))});$('#blackPanel').classList.toggle('hidden',name!=='black');$('#whitePanel').classList.toggle('hidden',name!=='white')}
const state={token:sessionStorage.getItem('monitor3_token')||'',view:'overview',refreshId:0,overviewController:null};
const viewText={
  overview:['数智中心','统一感知、关联研判与闭环处置'],
  events:['事件中心','查询标准化后的多源安全事件'],
  reviews:['研判中心','对高风险事件进行人工确认与审计'],
  lists:['黑白名单','管理联动封禁与可信网络例外'],
  operations:['设备与运行','监控采集节点、Worker 与异常任务']
};
const metricLabels={
  events_24h:['24H 安全事件','EVENTS'],
  unique_sources_24h:['风险源 IP','UNIQUE SOURCES'],
  open_reviews:['待人工研判','OPEN REVIEWS'],
  active_blacklist:['联动封禁','ACTIVE BLOCKS'],
  services_healthy:['健康服务','HEALTHY'],
  services_total:['服务总数','SERVICES']
};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=v=>v?new Date(v).toLocaleString('zh-CN',{hour12:false,timeZone:'Asia/Shanghai'}):'--';
const shortService=v=>String(v||'').replace('collector:','').replace('-192-168',' · 192.168').replace('-172-16',' · 172.16');
async function apiPayload(path,options={}){
  const headers={...(options.headers||{})};
  if(state.token)headers.Authorization=`Bearer ${state.token}`;
  if(options.body)headers['Content-Type']='application/json';
  let response;
  const attempts=String(options.method||'GET').toUpperCase()==='GET'?2:1;
  for(let attempt=0;attempt<attempts;attempt++){
    try{response=await fetch(path,{...options,headers,cache:'no-store'});break}
    catch(error){if(error.name==='AbortError')throw error;if(attempt+1>=attempts)throw new Error('连接服务失败，请稍后重试');await new Promise(resolve=>setTimeout(resolve,250))}
  }
  const payload=await response.json().catch(()=>({}));
  if(!response.ok){const e=new Error(payload.error?.message||`${response.status} request failed`);e.status=response.status;throw e}
  return payload;
}
async function api(path,options={}){return (await apiPayload(path,options)).data}
function badge(v){const value=String(v||'--');const ok=['ok','ready','running','online','blocked','succeeded'].includes(value);const bad=['dead','error','offline','degraded'].includes(value);return `<span class="badge ${ok?'ok':bad?'bad':''}">${esc(value)}</span>`}
const empty=(cols,msg='暂无数据')=>`<tr><td colspan="${cols}" class="empty">${msg}</td></tr>`;
function show(message,error=false){const n=$('#notice');n.textContent=message;n.classList.toggle('error',error);n.classList.remove('hidden');setTimeout(()=>n.classList.add('hidden'),5000)}
const listState={};
function listInfo(key){return listState[key]||(listState[key]={page:1,pageSize:25,filters:{}})}
const optionHtml=items=>items.map(([value,label])=>`<option value="${esc(value)}">${esc(label)}</option>`).join('');
function filterField(field){
  if(field.type==='select')return `<label>${esc(field.label)}<select name="${esc(field.name)}"><option value="">全部</option>${optionHtml(field.options||[])}</select></label>`;
  return `<label>${esc(field.label)}<input name="${esc(field.name)}" type="${field.type||'text'}" placeholder="${esc(field.placeholder||'')}"></label>`;
}
function ensureListControls(key, tbodySelector, filters=[]){
  if(document.querySelector(`[data-list-controls="${key}"]`))return;
  const tbody=$(tbodySelector), wrap=tbody?.closest('.table-wrap');
  if(!wrap)return;
  wrap.insertAdjacentHTML('beforebegin',`<form class="list-controls" data-list-controls="${key}"><div class="filter-grid">${filters.map(filterField).join('')}</div><div class="list-actions"><button type="submit">筛选</button><button type="button" class="secondary" data-list-reset="${key}">重置</button></div></form>`);
  wrap.insertAdjacentHTML('afterend',`<div class="pager" data-list-pager="${key}"><button type="button" class="secondary" data-list-page="${key}" data-dir="-1">上一页</button><span id="pager-${key}">第 1 页</span><select data-list-size="${key}"><option>10</option><option selected>25</option><option>50</option><option>100</option></select><button type="button" class="secondary" data-list-page="${key}" data-dir="1">下一页</button></div>`);
  const form=document.querySelector(`[data-list-controls="${key}"]`);
  form.addEventListener('submit',event=>{event.preventDefault();const info=listInfo(key);info.page=1;info.filters=Object.fromEntries(new FormData(form).entries());refresh().catch(error=>show(error.message,true))});
}
function queryForList(key, extra={}){
  const info=listInfo(key), params=new URLSearchParams({page:String(info.page),page_size:String(info.pageSize),...extra});
  for(const [name,value] of Object.entries(info.filters||{}))if(String(value||'').trim())params.set(name,String(value).trim());
  return params.toString();
}
async function listApi(key, endpoint, options={}, extra={}){
  const path=`${endpoint}${endpoint.includes('?')?'&':'?'}${queryForList(key,extra)}`;
  const payload=await apiPayload(path,options);
  const meta=payload.meta||{}, info=listInfo(key);
  const pager=$(`#pager-${key}`); if(pager)pager.textContent=`第 ${meta.page||info.page} 页 · 每页 ${meta.page_size||info.pageSize} 条${meta.has_more?' · 还有下一页':' · 已到末页'}`;
  const next=document.querySelector(`[data-list-page="${key}"][data-dir="1"]`); if(next)next.disabled=!meta.has_more;
  const prev=document.querySelector(`[data-list-page="${key}"][data-dir="-1"]`); if(prev)prev.disabled=(meta.page||info.page)<=1;
  return payload.data||[];
}
document.addEventListener('click',event=>{
  const page=event.target.closest('[data-list-page]');
  if(page){const info=listInfo(page.dataset.listPage);info.page=Math.max(1,info.page+Number(page.dataset.dir));refresh().catch(error=>show(error.message,true))}
  const reset=event.target.closest('[data-list-reset]');
  if(reset){const key=reset.dataset.listReset,form=document.querySelector(`[data-list-controls="${key}"]`);if(form)form.reset();listState[key]={page:1,pageSize:listInfo(key).pageSize,filters:{}};refresh().catch(error=>show(error.message,true))}
});
document.addEventListener('change',event=>{
  const size=event.target.closest('[data-list-size]');
  if(size){const info=listInfo(size.dataset.listSize);info.page=1;info.pageSize=Number(size.value);refresh().catch(error=>show(error.message,true))}
});
const eventFilters=[{name:'q',label:'关键字',placeholder:'IP / 来源 / 类型 / 设备'},{name:'src_ip',label:'源 IP'},{name:'dst_ip',label:'目的 IP'},{name:'source',label:'数据源'},{name:'category',label:'威胁类型'},{name:'severity',label:'等级',type:'select',options:[['low','low'],['medium','medium'],['high','high'],['critical','critical']]},{name:'date_from',label:'开始日期',type:'date'},{name:'date_to',label:'结束日期',type:'date'}];
const reviewFilters=[{name:'q',label:'关键字',placeholder:'IP / 类型 / 原因'},{name:'src_ip',label:'攻击源 IP'},{name:'dst_ip',label:'攻击目标'},{name:'category',label:'类型'},{name:'status',label:'状态',type:'select',options:[['open','open'],['claimed','claimed'],['approved','approved'],['rejected','rejected']]},{name:'date_from',label:'开始日期',type:'date'},{name:'date_to',label:'结束日期',type:'date'}];
const listFilters=[{name:'q',label:'关键字',placeholder:'IP / 备注 / 来源'},{name:'ip',label:'IP / 网段'},{name:'direction',label:'方向',type:'select',options:[['src','源地址'],['dst','目的地址']]},{name:'source',label:'来源'},{name:'status',label:'状态'}];
const serviceFilters=[{name:'q',label:'服务名'},{name:'status',label:'状态'}];
const actionFilters=[{name:'q',label:'关键字',placeholder:'类型 / 错误 / 目标'},{name:'status',label:'状态',type:'select',options:[['dead','dead'],['pending','pending'],['retry','retry'],['running','running']]},{name:'action_type',label:'动作类型'},{name:'date_from',label:'开始日期',type:'date'},{name:'date_to',label:'结束日期',type:'date'}];
async function loadOverview(){
  if(state.overviewController)state.overviewController.abort();
  const controller=new AbortController();state.overviewController=controller;
  const brain=await api('/api/v1/soc/brain',{signal:controller.signal});
  const totals=brain.totals;
  $('#brainMetrics').innerHTML=Object.entries(metricLabels).map(([key,[label,sub]])=>`<div class="metric"><div class="metric-label">${label}</div><div class="metric-value">${esc(totals[key]??0)}</div><div class="metric-sub">${sub}</div></div>`).join('');
  $('#brainCount').textContent=`${totals.events_24h} EVENTS / 24H`;
  $('#sourceList').innerHTML=brain.sources.length?brain.sources.map(x=>`<div class="source-item"><header><span>${esc(x.display_name||x.source)}</span><strong>${esc(x.processed_lines||0)}</strong></header><div class="source-meta"><span>24H 采集处理 ${esc(x.processed_lines||0)} · 安全告警 ${esc(x.events)}</span><span>${x.lifecycle?esc({active:'已启用',observing:'观察中'}[x.lifecycle]||x.lifecycle):''}</span></div><small>${x.last_ingested_at?'最近采集 '+fmt(x.last_ingested_at):'等待新日志采集计数'}${x.sample_events?' · 识别样本 '+esc(x.sample_events):''}</small></div>`).join(''):'<div class="empty">等待数据接入</div>';
  $('#riskFeed').innerHTML=brain.risks.length?brain.risks.map(x=>`<div class="risk-item ${x.severity==='critical'||x.severity==='high'?'high':''}"><div class="risk-top"><span class="risk-ip">${esc(x.src_ip)}</span><span class="risk-action">${esc(x.decision)}</span></div><p>${esc(x.source)} · ${esc(x.category)} · ${fmt(x.occurred_at)}</p></div>`).join(''):'<div class="empty">暂无实时风险</div>';
  const maxCategory=Math.max(1,...brain.categories.map(x=>x.events));
  $('#categoryList').innerHTML=brain.categories.map(x=>`<div class="category-row"><span title="${esc(x.category)}">${esc(x.category)}</span><div class="category-meter"><i style="width:${x.events/maxCategory*100}%"></i></div><b>${esc(x.events)}</b></div>`).join('')||'<div class="empty">暂无威胁分布</div>';
  $('#serviceCards').innerHTML=brain.services.map(x=>`<div class="service-card ${esc(x.health_state||'')}"><i class="service-dot ${x.health_state==='fresh'?'ok':['delayed','degraded'].includes(x.health_state)?'warn':''}"></i><span>${esc(shortService(x.service))}</span><small>${x.health_state==='delayed'?`在线 · 等待下个周期（${x.max_age_seconds}s）`:x.health_state==='degraded'?'在线 · 短暂拥塞':x.health_state==='stale'?`心跳超时（阈值 ${x.max_age_seconds}s）`:'实时在线'} · ${x.age_seconds}s</small></div>`).join('')||'<div class="empty">暂无服务心跳</div>';
  const trendRows=brain.hourly;
  const max=Math.max(1,...trendRows.map(x=>x.events));
  $('#trend').innerHTML=trendRows.length?trendRows.slice(-24).map(x=>`<div class="bar-wrap"><span class="bar-value">${esc(x.events)}</span><div class="bar h${Math.max(1,Math.ceil(x.events/max*10))}"></div><span class="bar-label">${esc(x.hour?new Date(x.hour+':00:00Z').toLocaleTimeString('zh-CN',{timeZone:'Asia/Shanghai',hour:'2-digit',hourCycle:'h23'}):(x.date||'').slice(-2))}</span></div>`).join(''):'<div class="empty">最近 24 小时暂无事件</div>';
  renderGeo(brain.geography);
  renderHosts(brain.hosts);
  renderVpn(brain.vpn_sessions);
  if(!brain.vpn_sessions.length){
    const stale=brain.vpn_status&&!brain.vpn_status.collector_healthy;
    $('#vpnSummary').textContent=stale?'采集状态异常 · 在线数待确认':'最近活动窗口内 0 会话';
    $('#vpnMonitor').innerHTML=`<div class="empty-state"><b>${stale?'VPN 数据暂不可用':'暂未检测到近期 VPN 活动'}</b><span>${stale?'采集心跳超时或未启动，不能据此认定所有用户离线':'采集正常，持续等待会话活动；静默连接不等同于已注销'}</span></div>`;
  }
}
const geoPoints={'北京':[650,210],'上海':[720,330],'广东':[590,470],'四川':[430,350],'新疆':[180,190],'西藏':[230,390],'陕西':[470,300],'山东':[650,280],'江苏':[690,310],'浙江':[700,350],'湖北':[520,350],'湖南':[520,400],'河南':[560,300],'河北':[600,235],'香港':[620,475],'成都':[430,360],'青岛':[680,280],'广州':[585,455]};
function geoPoint(location,index){for(const [name,point] of Object.entries(geoPoints))if(String(location).includes(name))return point;return [100+(index%5)*145,110+Math.floor(index/5)*95]}
function renderGeo(rows){
  const known=rows.filter(x=>x.location&&x.location!=='UNKNOWN');
  const points=known.slice(0,10).map((x,i)=>{const [px,py]=geoPoint(x.location,i);const width=Math.max(1.5,Math.min(6,Math.log10(x.events+1)*1.8));return `<path class="attack-arc" style="stroke-width:${width}" d="M 470 365 Q ${(470+px)/2} ${Math.min(80,py-100)} ${px} ${py}"/><circle class="geo-pulse" cx="${px}" cy="${py}" r="${4+Math.min(8,Math.log10(x.events+1)*2)}"/><text x="${px+10}" y="${py-7}">${esc(x.location)} · ${esc(x.events)}</text>`}).join('');
  $('#geoMap').innerHTML=`<svg viewBox="0 0 820 540" role="img" aria-label="地理攻击感知图"><path class="china-shape" d="M115 155L185 115 270 130 330 90 430 110 505 80 590 125 690 135 735 210 700 265 750 330 675 365 645 445 560 475 500 430 430 485 345 450 285 405 205 390 160 325 100 275Z"/><circle class="soc-center" cx="470" cy="365" r="11"/><text class="soc-label" x="487" y="370">SOC 中心</text>${points}</svg>${known.length?'':`<div class="map-empty">地理缓存尚无可定位数据；事件仍正常入库</div>`}`;
}
function renderHosts(rows){const online=rows.filter(x=>x.status==='online').length;const sites=rows.filter(x=>x.kind==='site');const sitesOnline=sites.filter(x=>x.status==='online').length;const physical=rows.filter(x=>x.kind==='physical').length;const virtual=rows.filter(x=>x.kind==='virtual').length;const labels={physical:'物理机',virtual:'虚拟机',network:'网络设备',site:'机房出口',unknown:'待核实'};$('#hostSummary').textContent=`${online}/${rows.length} 在线 · 物理 ${physical} · 虚拟 ${virtual} · 机房 ${sitesOnline}/${sites.length}`;$('#hostMonitor').innerHTML=rows.length?rows.map(x=>`<div class="monitor-item ${x.kind==='site'?'site-item':''}"><i class="service-dot ${x.status==='online'?'ok':''}"></i><div><strong><em class="asset-kind ${esc(x.kind||'unknown')}">${labels[x.kind]||'其他资产'}</em>${esc(x.name||x.ip)}</strong><small>${esc(x.ip)}${x.site?` · ${esc(x.site)}`:''} · ${fmt(x.last_checked_at)}</small></div>${badge(x.status)}</div>`).join(''):'<div class="empty-state"><b>资产清单待接入</b><span>配置资产后自动展示真实类型、机房与在线状态</span></div>'}
function renderVpn(rows){$('#vpnSummary').textContent=`${rows.length} 近期活跃会话`;$('#vpnMonitor').innerHTML=rows.length?rows.map(x=>`<div class="monitor-item vpn-session"><i class="service-dot ok"></i><div><strong>${esc(x.username)}</strong><div class="vpn-route">${x.client_ip?`<span class="ip-chip public">公网 ${esc(x.client_ip)}</span><b>→</b>`:''}<span class="ip-chip virtual">VPN ${esc(x.virtual_ip||'地址未上报')}</span></div><small>${x.client_ip?(x.location&&!['UNKNOWN','INTERNAL'].includes(x.location)?`归属地 ${esc(x.location)}`:'归属地暂不可用'):'公网地址未上报'} · 最近活动</small></div><span class="session-time">${fmt(x.last_seen_at||x.login_at)}</span></div>`).join(''):'<div class="empty-state"><b>暂无 VPN 近期活跃会话</b><span>仅展示最近活动窗口内的会话，历史日志不会再冒充在线</span></div>'}
async function loadEvents(){ensureListControls('events','#eventRows',eventFilters);const rows=await listApi('events','/api/v1/events');$('#eventRows').innerHTML=rows.length?rows.map(x=>`<tr><td>${fmt(x.occurred_at)}</td><td>${esc(x.src_ip)}</td><td>${esc(x.source_location||'未知')}</td><td>${esc(x.dst_ip||'--')}</td><td>${esc(x.source)}</td><td>${esc(x.category)}</td><td>${badge(x.severity)}</td><td>${esc(x.device_id)}</td></tr>`).join(''):empty(8)}
async function loadReviews(){ensureListControls('reviews','#reviewRows',reviewFilters);const rows=await listApi('reviews','/api/v1/reviews');$('#reviewRows').innerHTML=rows.length?rows.map(x=>`<tr><td>${esc(x.attack_source_ip||x.ip)}</td><td>${esc(x.location||'未知')}</td><td>${esc(x.target_ip||'--')}</td><td>${esc(x.category)}</td><td>${esc(x.count)}</td><td>${esc(x.reason).slice(0,50)}</td><td>${badge(x.status)}</td><td><div class="row-actions"><button data-review="${esc(x.id)}" data-op="approve">批准</button><button class="danger" data-review="${esc(x.id)}" data-op="reject">拒绝</button></div></td></tr>`).join(''):empty(9)}
async function loadBlacklist(){ensureListControls('blacklist','#blacklistRows',listFilters);const rows=await listApi('blacklist','/api/v1/blacklist');$('#blacklistRows').innerHTML=rows.length?rows.map(x=>`<tr><td>${esc(x.ip)}</td><td>${x.direction==='dst'?'目的地址':'源地址'}</td><td>${esc(x.description||x.category||'--')}</td><td>${badge(x.actual_state)}</td><td>${esc(x.age_time||fmt(x.desired_expires_at))}</td><td>${fmt(x.inserted_at||x.first_seen_at)}</td><td>${esc(x.hit_count||0)}</td><td>${x.origin==='firewall'?'40.1 防火墙':esc(x.source)}</td><td>${x.origin==='firewall'?'--':(x.desired_state==='blocked'?`<button class="danger" data-unblock="${esc(x.id)}">解封</button>`:'--')}</td></tr>`).join(''):empty(9)}
async function loadWhitelist(){ensureListControls('whitelist','#whitelistRows',listFilters);const rows=await listApi('whitelist','/api/v1/whitelist');$('#whitelistRows').innerHTML=rows.length?rows.map(x=>`<tr><td>${esc(x.network)}</td><td>${x.direction==='dst'?'目的地址':'源地址'}</td><td>${esc(x.description||x.reason||'--')}</td><td>${badge(x.enabled?'enabled':'disabled')}</td><td>${esc(x.age_time||fmt(x.expires_at))}</td><td>${fmt(x.created_at)}</td><td>${esc(x.hit_count||0)}</td><td>${x.origin==='firewall'?'40.1 防火墙':x.origin==='local+firewall'?'本地 + 40.1':'本地'}</td><td>${x.origin==='firewall'?'--':(x.enabled?`<button class="danger" data-disable-white="${esc(x.id)}">停用</button>`:'--')}</td></tr>`).join(''):empty(9)}
async function loadLists(){await Promise.all([loadBlacklist(),loadWhitelist()])}
async function loadOperations(){ensureListControls('services','#serviceRows',serviceFilters);const rows=await listApi('services','/api/v1/services');$('#serviceRows').innerHTML=rows.length?rows.map(x=>`<tr><td>${esc(x.service)}</td><td>${badge(x.status)}</td><td>${esc(x.instance_id)}</td><td>${fmt(x.updated_at)}</td></tr>`).join(''):empty(4);if(!state.token){$('#deadRows').innerHTML=empty(4,'设置访问令牌后查看');return}ensureListControls('actions','#deadRows',actionFilters);const dead=await listApi('actions','/api/v1/actions',{},listInfo('actions').filters.status?{}:{status:'dead'});$('#deadRows').innerHTML=dead.length?dead.map(x=>`<tr><td>${esc(x.action_type)}</td><td>${esc(x.last_error||'--').slice(0,40)}</td><td>${x.attempts}/${x.max_attempts}</td><td><button data-retry="${esc(x.id)}">重试</button></td></tr>`).join(''):empty(4)}
function requireToken(){if(state.token)return true;openAuth();return false}
async function review(id,op){if(!requireToken())return;const prompts={claim:'请输入认领说明：',approve:'请输入批准及处置原因：',reject:'请输入拒绝原因：'};const reason=prompt(prompts[op]||'请输入研判原因：');if(!reason)return;await api(`/api/v1/reviews/${encodeURIComponent(id)}/${op}`,{method:'POST',body:JSON.stringify({reason})});show('研判结果已提交');loadReviews()}
async function unblock(id){if(!requireToken())return;const reason=prompt('请输入解除封禁原因：');if(!reason)return;await api(`/api/v1/blacklist/${encodeURIComponent(id)}`,{method:'DELETE',body:JSON.stringify({reason})});show('解封任务已进入队列');loadBlacklist()}
async function disableWhitelist(id){if(!requireToken())return;const reason=prompt('请输入停用白名单的原因：');if(!reason)return;await api(`/api/v1/whitelist/${encodeURIComponent(id)}`,{method:'DELETE',body:JSON.stringify({reason})});show('白名单已停用');loadWhitelist()}
async function retry(id){if(!requireToken())return;const reason=prompt('确认外部依赖已恢复，并填写重试原因：');if(!reason)return;await api(`/api/v1/actions/${encodeURIComponent(id)}/retry`,{method:'POST',body:JSON.stringify({reason})});show('任务已重新入队');loadOperations()}
const loaders={overview:loadOverview,events:loadEvents,reviews:loadReviews,lists:loadLists,operations:loadOperations};
async function updateHealth(){try{const ready=await api('/health/ready');$('#health').textContent=ready.status==='ready'?'系统就绪':'服务观察中';$('#health').className='health ok'}catch(e){$('#health').textContent='部分服务延迟';$('#health').className='health warn'}}
async function refresh(){const view=state.view,id=++state.refreshId,target=document.getElementById(view);target.classList.add('is-loading');$('#refreshButton').disabled=true;updateHealth();try{await loaders[view]();if(id===state.refreshId&&state.token)sessionStorage.setItem('monitor3_last_view',view)}catch(e){if(e.name==='AbortError')return;if(id===state.refreshId){$('#health').textContent=e.status===401?'等待认证':'数据加载失败';if(e.status===401&&!$('#authDialog').open)openAuth();else show(e.message,true)}}finally{if(id===state.refreshId){target.classList.remove('is-loading');$('#refreshButton').disabled=false}}}
function switchView(view){state.view=view;document.querySelectorAll('.nav-item').forEach(x=>x.classList.toggle('active',x.dataset.view===view));document.querySelectorAll('.view').forEach(x=>x.classList.toggle('active',x.id===view));$('#pageTitle').textContent=viewText[view][0];$('#pageDescription').textContent=viewText[view][1];refresh()}
function openAuth(){$('#tokenInput').value=state.token;$('#authDialog').showModal();$('#tokenInput').focus()}
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.view)switchView(b.dataset.view);if(b.dataset.review)review(b.dataset.review,b.dataset.op).catch(x=>show(x.message,true));if(b.dataset.unblock)unblock(b.dataset.unblock).catch(x=>show(x.message,true));if(b.dataset.disableWhite)disableWhitelist(b.dataset.disableWhite).catch(x=>show(x.message,true));if(b.dataset.retry)retry(b.dataset.retry).catch(x=>show(x.message,true));if(b.dataset.closeDialog)document.getElementById(b.dataset.closeDialog).close();if(b.dataset.listTab)setListTab(b.dataset.listTab)});
$('#refreshButton').addEventListener('click',refresh);$('#authButton').addEventListener('click',openAuth);$('#saveToken').addEventListener('click',()=>{state.token=$('#tokenInput').value.trim();if(state.token)sessionStorage.setItem('monitor3_token',state.token);else sessionStorage.removeItem('monitor3_token');refresh()});
$('#navToggle').addEventListener('click',()=>{const collapsed=!document.body.classList.contains('nav-collapsed');document.body.classList.toggle('nav-collapsed',collapsed);localStorage.setItem('monitor3_nav_collapsed',collapsed?'1':'0');$('#navToggle').textContent=collapsed?'›':'‹';$('#navToggle').title=collapsed?'展开侧栏':'收缩侧栏'});
if(localStorage.getItem('monitor3_nav_collapsed')==='1'){document.body.classList.add('nav-collapsed');$('#navToggle').textContent='›'}
$('#addBlacklist').addEventListener('click',()=>{if(requireToken())$('#blackDialog').showModal()});$('#addWhitelist').addEventListener('click',()=>{if(requireToken())$('#whiteDialog').showModal()});
$('#blackForm').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/v1/blacklist',{method:'POST',body:JSON.stringify({ip:$('#blackIp').value.trim(),minutes:Number($('#blackMinutes').value),reason:$('#blackReason').value.trim()})});$('#blackDialog').close();e.target.reset();$('#blackMinutes').value='1440';show('黑名单任务已进入处置队列');loadLists()}catch(x){show(x.message,true)}});
$('#whiteForm').addEventListener('submit',async e=>{e.preventDefault();try{const local=$('#whiteExpires').value;await api('/api/v1/whitelist',{method:'POST',body:JSON.stringify({network:$('#whiteNetwork').value.trim(),reason:$('#whiteReason').value.trim(),expires_at:local?new Date(local).toISOString():null})});$('#whiteDialog').close();e.target.reset();show('白名单已生效');loadLists()}catch(x){show(x.message,true)}});
setInterval(()=>$('#clock').textContent=new Date().toLocaleString('zh-CN',{hour12:false,timeZone:'Asia/Shanghai'}),1000);
setListTab('black');refresh();setInterval(refresh,30000);
