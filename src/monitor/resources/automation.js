'use strict';

const automationNavAnchor = document.querySelector('.nav-external');
automationNavAnchor.insertAdjacentHTML('beforebegin', `
  <button class="nav-item" data-view="discovery"><i>⌁</i><span class="nav-label">设备接入</span></button>
  <button class="nav-item" data-view="playbooks"><i>▷</i><span class="nav-label">自动化剧本</span></button>`);

document.querySelector('main').insertAdjacentHTML('beforeend', `
  <section id="discovery" class="view">
    <div class="mode-banner">新设备默认处于观察模式：只记录事件，不会自动关闭、通知或封禁。</div>
    <div id="discoverySummary" class="automation-summary"></div>
    <article class="panel"><div class="panel-head"><h2>Syslog 来源自动发现</h2><span>厂商指纹 · 解析质量 · 生命周期</span></div>
      <div class="table-wrap"><table><thead><tr><th>来源 IP</th><th>状态</th><th>识别结果</th><th>置信度</th><th>解析成功率</th><th>字段完整率</th><th>样本</th><th>操作</th></tr></thead><tbody id="discoveryRows"></tbody></table></div>
    </article>
  </section>
  <section id="playbooks" class="view">
    <div class="mode-banner">剧本先回放、再启用。V1 仅允许自动关闭研判单，不允许直接执行命令或修改防火墙。</div>
    <div id="playbookSummary" class="automation-summary"></div>
    <article class="panel"><div class="panel-head"><h2>自动化剧本</h2><button id="newPlaybook">新建剧本</button></div>
      <div class="table-wrap"><table><thead><tr><th>名称</th><th>ID</th><th>状态</th><th>优先级</th><th>版本</th><th>更新时间</th><th>操作</th></tr></thead><tbody id="playbookRows"></tbody></table></div>
    </article>
    <div id="playbookEditor" class="automation-editor hidden"><h2>剧本定义</h2><p class="quality-note">保存前会进行安全校验；建议先保持 enabled=false 并执行历史回放。</p><details class="quality-note"><summary>字段说明（点击展开）</summary><p><b>id/name</b>：唯一标识和显示名称；<b>enabled</b>：是否允许执行；<b>priority</b>：数字越小越优先；<b>trigger</b>：触发来源；<b>match</b>：匹配条件（来源、类别、等级、次数）；<b>actions</b>：处置动作。目前仅允许关闭研判单，观察模式不会执行。</p></details><textarea id="playbookJson" spellcheck="false"></textarea><div class="editor-actions"><button id="savePlaybook">保存</button><button id="replayPlaybook" class="secondary">历史回放</button><button id="closePlaybookEditor" class="secondary">关闭</button></div><div id="replayResult" class="replay-result hidden"></div></div>
  </section>
  <dialog id="deviceConfirmDialog" class="automation-dialog">
    <form id="deviceConfirmForm" method="dialog">
      <div class="dialog-head"><h2>确认设备类型</h2><button type="button" class="dialog-close" data-device-dialog-close aria-label="关闭">×</button></div>
      <p class="quality-note">请选择与设备匹配的厂商和产品类型。列表中没有时，再选择“其他”并手动填写。</p>
      <label>设备类型<select id="deviceParserSelect" required></select></label>
      <label id="deviceCustomTypeField" class="hidden">设备名称或类型<input id="deviceCustomType" maxlength="80" placeholder="例如：某厂商下一代防火墙"></label>
      <label>确认依据<textarea id="deviceConfirmReason" maxlength="500" required placeholder="例如：已核对设备型号和日志样本"></textarea></label>
      <div class="editor-actions"><button type="submit">确认并进入观察模式</button><button type="button" class="secondary" data-device-dialog-close>取消</button></div>
    </form>
  </dialog>`);

viewText.discovery = ['设备接入', '自动发现 Syslog 来源、确认厂商类型并完成观察期验证'];
viewText.playbooks = ['自动化剧本', '通过历史回放、安全校验和审计实现低风险自动化'];

const percent = value => `${Math.round(Number(value || 0) * 100)}%`;
const meter = value => `<span class="quality-meter ${Number(value)<.75?'low':''}" style="--quality:${percent(value)}"><i></i><b>${percent(value)}</b></span>`;
const statusLabel = value => ({pending:'待确认',observing:'观察中',active:'已启用',ignored:'已忽略',error:'异常'})[value] || value;

async function loadDiscovery(){
  ensureListControls('discovered-devices','#discoveryRows',[{name:'q',label:'来源 IP / 识别结果'},{name:'source_ip',label:'来源 IP'},{name:'status',label:'状态',type:'select',options:[['pending','待确认'],['observing','观察中'],['active','已启用'],['ignored','已忽略']]},{name:'parser',label:'解析器'},{name:'date_from',label:'开始日期',type:'date'},{name:'date_to',label:'结束日期',type:'date'}]);
  const [rows, parsers] = await Promise.all([listApi('discovered-devices','/api/v1/discovered-devices'), api('/api/v1/device-parsers')]);
  window.monitor3ParserOptions = parsers;
  const count = status => rows.filter(row => row.status === status).length;
  $('#discoverySummary').innerHTML = [['发现来源',rows.length],['待确认',count('pending')],['观察中',count('observing')],['正式启用',count('active')]].map(x=>`<div><span>${x[0]}</span><b>${x[1]}</b></div>`).join('');
  $('#discoveryRows').innerHTML = rows.length ? rows.map(row => `<tr><td><b>${esc(row.source_ip)}</b><div class="quality-note">${fmt(row.last_seen_at)}</div></td><td>${badge(statusLabel(row.status))}</td><td>${esc(row.source||'未识别')}<div class="quality-note">${esc(row.parser||'等待人工选择')}</div></td><td>${meter(row.confidence)}</td><td>${meter(row.parse_success_rate)}</td><td>${meter(row.field_completeness)}</td><td>${row.parsed_count}/${row.candidate_count}<div class="quality-note">共抽样 ${row.sample_count}</div></td><td><div class="row-actions">${row.status==='pending'?`<button data-device-confirm="${esc(row.id)}">确认类型</button>`:''}${row.status==='observing'?`<button data-device-promote="${esc(row.id)}">正式启用</button>`:''}${row.status==='active'?`<button class="secondary" data-device-observe="${esc(row.id)}">退回观察</button>`:''}</div></td></tr>`).join('') : empty(8,'尚未发现新的 Syslog 来源');
}

let pendingDeviceConfirmId='';
async function confirmDevice(id){
  if(!requireToken()) return;
  pendingDeviceConfirmId=id;
  const select=$('#deviceParserSelect');
  select.innerHTML='<option value="">请选择设备类型</option>'+(window.monitor3ParserOptions||[])
    .map(x=>`<option value="${esc(x.parser)}">${esc(x.label)}</option>`).join('')+
    '<option value="__other__">其他（手动输入）</option>';
  $('#deviceCustomType').value='';
  $('#deviceConfirmReason').value='';
  $('#deviceCustomTypeField').classList.add('hidden');
  $('#deviceConfirmDialog').showModal();
}
function closeDeviceConfirm(){
  pendingDeviceConfirmId='';
  $('#deviceConfirmDialog').close();
}
$('#deviceParserSelect').addEventListener('change',event=>{
  const custom=event.target.value==='__other__';
  $('#deviceCustomTypeField').classList.toggle('hidden',!custom);
  $('#deviceCustomType').required=custom;
  if(custom) $('#deviceCustomType').focus();
});
$('#deviceConfirmForm').addEventListener('submit',async event=>{
  event.preventDefault();
  if(!pendingDeviceConfirmId) return;
  const selected=$('#deviceParserSelect').value;
  const customType=$('#deviceCustomType').value.trim();
  const reason=$('#deviceConfirmReason').value.trim();
  if(!selected||!reason||(selected==='__other__'&&!customType)) return;
  const parser=selected==='__other__'?'cef_security':selected;
  const body={parser,reason};
  if(customType) body.device_name=customType;
  try {
    await api(`/api/v1/discovered-devices/${encodeURIComponent(pendingDeviceConfirmId)}/confirm`,{method:'POST',body:JSON.stringify(body)});
    closeDeviceConfirm();
    show('设备已确认并进入观察模式');
    loadDiscovery();
  } catch(error) {
    show(error.message,true);
  }
});
document.querySelectorAll('[data-device-dialog-close]').forEach(button=>button.addEventListener('click',closeDeviceConfirm));
async function changeDeviceMode(id,operation){
  if(!requireToken()) return;
  const reason=prompt(operation==='promote'?'请输入观察期验证结论：':'请输入退回观察模式的原因：'); if(!reason) return;
  await api(`/api/v1/discovered-devices/${encodeURIComponent(id)}/${operation}`,{method:'POST',body:JSON.stringify({reason})});
  show(operation==='promote'?'设备已正式启用策略和剧本':'设备已退回观察模式'); loadDiscovery();
}

const playbookTemplate = {id:'close-known-benign',name:'已确认低风险事件自动关闭',enabled:false,priority:100,trigger:'review_created',match:{decision:'MANUAL_REVIEW',source:'DPTECH_WAF',category_regex:'health.?check',severity:'low',count_lte:20},actions:[{type:'close_review',reason:'已确认的低风险事件，由剧本自动关闭'}]};
let playbookCache=[];
async function loadPlaybooks(){
  ensureListControls('playbooks','#playbookRows',[{name:'q',label:'名称 / ID'},{name:'enabled',label:'状态',type:'select',options:[['1','已启用'],['0','已停用']]}]);
  const [rows,status] = await Promise.all([listApi('playbooks','/api/v1/playbooks'),api('/api/v1/playbooks/status')]); playbookCache=rows;
  $('#playbookSummary').innerHTML=[['剧本总数',rows.length],['已启用',rows.filter(x=>x.enabled).length],['执行版本',status.version||'--'],['安全动作','仅自动关闭']].map(x=>`<div><span>${x[0]}</span><b>${esc(x[1])}</b></div>`).join('');
  $('#playbookRows').innerHTML=rows.length?rows.map(row=>`<tr><td>${esc(row.name)}</td><td>${esc(row.id)}</td><td>${badge(row.enabled?'enabled':'disabled')}</td><td>${row.priority}</td><td>v${row.version}</td><td>${fmt(row.updated_at)}</td><td><div class="row-actions"><button data-playbook-edit="${esc(row.id)}">编辑</button><button class="secondary" data-playbook-replay="${esc(row.id)}">回放</button></div></td></tr>`).join(''):empty(7,'尚未创建 Web 托管剧本');
}
function openPlaybook(definition){$('#playbookJson').value=JSON.stringify(definition,null,2);$('#playbookEditor').classList.remove('hidden');$('#replayResult').classList.add('hidden')}
async function savePlaybook(){if(!requireToken())return;let definition;try{definition=JSON.parse($('#playbookJson').value)}catch(e){show('剧本 JSON 格式错误',true);return}const reason=prompt('请输入本次剧本变更原因：');if(!reason)return;await api(`/api/v1/playbooks/${encodeURIComponent(definition.id)}`,{method:'PUT',body:JSON.stringify({definition,reason})});show('剧本已保存，采集器将自动热加载');loadPlaybooks()}
async function replayDefinition(definition){if(!requireToken())return;const result=await api('/api/v1/playbooks/replay',{method:'POST',body:JSON.stringify({definition,limit:10000})});const target=$('#replayResult');target.textContent=`只读回放完成\n扫描事件：${result.scanned}\n匹配事件：${result.matched}\n匹配率：${percent(result.match_rate)}\n不会修改数据库、研判单或防火墙。`;target.classList.remove('hidden')}
async function replayById(id){if(!requireToken())return;const row=playbookCache.find(x=>x.id===id);openPlaybook(row.definition);await replayDefinition(row.definition)}

loaders.discovery=loadDiscovery; loaders.playbooks=loadPlaybooks;
document.addEventListener('click',event=>{const b=event.target.closest('button');if(!b)return;if(b.dataset.deviceConfirm)confirmDevice(b.dataset.deviceConfirm).catch(e=>show(e.message,true));if(b.dataset.devicePromote)changeDeviceMode(b.dataset.devicePromote,'promote').catch(e=>show(e.message,true));if(b.dataset.deviceObserve)changeDeviceMode(b.dataset.deviceObserve,'observe').catch(e=>show(e.message,true));if(b.dataset.playbookEdit){const row=playbookCache.find(x=>x.id===b.dataset.playbookEdit);if(row)openPlaybook(row.definition)}if(b.dataset.playbookReplay)replayById(b.dataset.playbookReplay).catch(e=>show(e.message,true))});
$('#newPlaybook').addEventListener('click',()=>openPlaybook(playbookTemplate));
$('#savePlaybook').addEventListener('click',()=>savePlaybook().catch(e=>show(e.message,true)));
$('#replayPlaybook').addEventListener('click',()=>{try{replayDefinition(JSON.parse($('#playbookJson').value)).catch(e=>show(e.message,true))}catch(e){show('剧本 JSON 格式错误',true)}});
$('#closePlaybookEditor').addEventListener('click',()=>$('#playbookEditor').classList.add('hidden'));
