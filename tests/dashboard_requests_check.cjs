const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('src/monitor/resources/dashboard.js','utf8');
const request=source.slice(source.indexOf('async function apiPayload('),source.indexOf('\nasync function api('));
let timer,cleared=0,calls=0;
const abortError=()=>Object.assign(new Error('cancelled'),{name:'AbortError'});
const ctx=vm.createContext({state:{token:'test'},AbortController,
 setTimeout:(cb,ms)=>{if(ms===15000)timer=cb;else cb();return 1},clearTimeout:()=>cleared++,
 fetch:async(path,options)=>{calls++;assert.equal(options.headers.Authorization,'Bearer test');return {ok:true,json:async()=>({data:{ready:true}})}}});
vm.runInContext(request,ctx);
(async()=>{
 assert.equal((await ctx.apiPayload('/test')).data.ready,true);
 assert.equal(calls,1);assert.equal(cleared,1);
 ctx.fetch=(path,options)=>{calls++;return new Promise((resolve,reject)=>{options.signal.addEventListener('abort',()=>reject(abortError()),{once:true})})};
 calls=0;let pending=ctx.apiPayload('/write',{method:'POST',body:'{}'});timer();
 await assert.rejects(pending,/请求超时，请刷新确认操作结果/);assert.equal(calls,1);
 const parent=new AbortController();pending=ctx.apiPayload('/read',{signal:parent.signal});parent.abort();
 await assert.rejects(pending,e=>e.name==='AbortError');
 // A response with headers but a stalled body must time out too.
 let bodyReady;const bodyStarted=new Promise(resolve=>{bodyReady=resolve});
 ctx.fetch=async(path,options)=>({ok:true,json:()=>new Promise((resolve,reject)=>{options.signal.addEventListener('abort',()=>reject(abortError()),{once:true});bodyReady()})});
 pending=ctx.apiPayload('/slow-body');await bodyStarted;timer();
 await assert.rejects(pending,/请求超时/);
 console.log('Dashboard requests: timeout, cancellation, stalled body, no automatic write retry passed');
})().catch(error=>{console.error(error);process.exitCode=1});
