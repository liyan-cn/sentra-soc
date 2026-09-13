const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const source=fs.readFileSync('src/monitor/resources/dashboard.js','utf8');
const render=source.split('\n').find(line=>line.startsWith('function renderVpn('));
const summary={}, monitor={};
const context=vm.createContext({$:s=>s==='#vpnSummary'?summary:monitor,
  esc:v=>String(v).replaceAll('<','&lt;').replaceAll('>','&gt;'),fmt:v=>v});
vm.runInContext(render,context);
for(const client_ip of ['', '203.0.113.8']) {
  context.renderVpn([{username:'<alice>', virtual_ip:'172.16.90.8',client_ip,last_seen_at:'2026-09-11'}]);
  assert.equal(summary.textContent,'1 近期活跃会话');
  assert.ok(monitor.innerHTML.includes('VPN 172.16.90.8'));
  assert.ok(monitor.innerHTML.includes('&lt;alice&gt;'));
  assert.ok(!/审计/.test(monitor.innerHTML));
  assert.equal(monitor.innerHTML.includes('公网 203.0.113.8'), Boolean(client_ip));
  assert.ok(monitor.innerHTML.includes(client_ip?'归属地暂不可用':'公网地址未上报'));
}
for(const session_origin of ['activity','login','audit+activity']) {
  context.renderVpn([{username:'alice',virtual_ip:'172.16.90.8',client_ip:'203.0.113.8',location:'中国/四川/成都',session_origin}]);
  assert.ok(monitor.innerHTML.includes('归属地 中国/四川/成都'));
  assert.ok(!monitor.innerHTML.includes('审计'));
}
context.renderVpn([{username:'alice',client_ip:'203.0.113.8',location:'<img src=x>'}]);
assert.ok(!monitor.innerHTML.includes('<img'));
context.renderVpn([{username:'bob',virtual_ip:'',login_at:'2026-09-11'}]);
assert.ok(monitor.innerHTML.includes('地址未上报'));
context.renderVpn([]);
assert.ok(monitor.innerHTML.includes('暂无 VPN 近期活跃会话'));
console.log('VPN display checks passed');
