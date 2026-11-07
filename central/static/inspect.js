// KVNRadar native Inspect panel: cached central RIP/RDO + one-time pull-only agent jobs.
'use strict';
(()=>{
 const $=id=>document.getElementById(id);
 const isRu=()=>window.KVNI18N?.lang?.()==='ru';
 const tr=(en,ru)=>isRu()?ru:en;
 const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 let activeId=null, refreshing=false, lastJobs=[], agents=[];
 try{activeId=sessionStorage.getItem('kvnradar-inspect-active')||null}catch(_){}
 function statusBadge(s){const val=String(s||'UNKNOWN');const cls=val==='BAN'?'ban':val==='OK'?'ok':'unknown';return `<span class="inspect-badge ${cls}">${esc(val)}</span>`;}
 function translateDOM(){
   const texts={
    'inspect-heading':['Inspect','Проверка'],
    'inspect-description':['Check any host or IP against cached RIP/RDO blocklists and optionally request one-time probes from an agent.','Проверка домена или IP по загруженным RIP/RDO-спискам и разовые проверки с выбранного агента.'],
    'inspect-host-label':['Hostname or IP address','Домен или IP-адрес'],
    'inspect-port-label':['Port','Порт'],
    'inspect-agent-toggle-label':['Run one-time probes from a selected agent','Разово проверить доступность с агента'],
    'inspect-agent-label':['Agent','Агент'],
    'inspect-checks-label':['One-time checks','Разовые проверки'],
    'inspect-notice':['The request will be queued for the selected agent. The agent picks it up on its next synchronization, executes the checks once, and returns the results on a subsequent synchronization. This can take several minutes.','Задание отправится выбранному агенту при следующей синхронизации. Агент выполнит проверки один раз и передаст результаты на следующем сеансе синхронизации. Это может занять несколько минут.'],
    'inspect-submit':['Inspect host','Проверить хост'],
    'inspect-recent-heading':['Recent inspections','Последние проверки']};
   Object.entries(texts).forEach(([id,v])=>{if($(id))$(id).textContent=v[isRu()?1:0]});
   const host=$('inspect-host');if(host)host.placeholder=tr('example.org or 203.0.113.10','example.org или 203.0.113.10');
   const s=$('inspect-agent');if(s&&s.options.length)s.options[0].text=tr('Select agent','Выберите агента');
 }
 function toggle(){ $('inspect-agent-options').hidden=!$('inspect-use-agent').checked; }
 function agentOptions(){
   const chosen=$('inspect-agent').value;
   const registered=agents;
   agents=registered;
   $('inspect-agent').innerHTML='<option value="">'+tr('Select agent','Выберите агента')+'</option>'+registered.map(id=>`<option value="${esc(id)}">${esc(id)}${window.agentLabel?' · '+esc(window.agentLabel(id)):''}</option>`).join('');
   if(registered.includes(chosen))$('inspect-agent').value=chosen;
 }
 function renderCentral(job){
   if(!job)return '';
   const groups=[['RIP',job.rip],['RDO',job.rdo]];
   return `<div class="inspect-central-grid">${groups.map(([name,data])=>`<article class="inspect-result"><div class="inspect-result-top"><strong>${name}</strong>${statusBadge(data?.status)}</div><div class="inspect-result-sub">${name==='RIP'?tr('IP/CIDR feed lookup','Сопоставление с IP/CIDR-списками'):tr('Domain feed lookup','Сопоставление со списками доменов')}</div>${data?.ips?.length?`<p class="inspect-ips">${tr('Resolved IPs','IP-адреса')}: ${esc(data.ips.join(', '))}</p>`:''}${data?.matches?.length?`<ul class="inspect-matches">${data.matches.map(x=>`<li><strong>${esc(x.source)}</strong> · ${esc(x.match||x.cidr||x.domain||'')} ${x.ip?'('+esc(x.ip)+')':''}</li>`).join('')}</ul>`:`<p class="inspect-empty">${tr('No matches in loaded feeds','Совпадений в загруженных списках нет')}</p>`}</article>`).join('')}</div>`;
 }
 function stateName(state){return ({queued:tr('Queued','В очереди'),dispatched:tr('Sent to agent · awaiting results','Отправлено агенту · ожидание ответа'),complete:tr('Completed','Завершено'),expired:tr('Timed out','Время ожидания истекло')})[state]||state;}
 function renderJob(job){
   if(!job){$('inspect-current').innerHTML='';return;}
   const checks=job.checks||[],results=job.results||{};
   const done=Object.keys(results).length;
   const stage=job.state==='complete'?'complete':job.state==='expired'?'expired':'pending';
   const title=`${esc(job.host)}:${esc(job.port)}`;
   let html=`<section class="soft-card inspect-view"><div class="inspect-view-heading"><div><h2>${tr('Inspection results','Результаты проверки')}</h2><p>${title} · ${esc(job.requested_at)}</p></div><span class="inspect-stage ${stage}">${esc(stateName(job.state))}</span></div>${renderCentral(job)}`;
   if(job.agent){
     html+=`<div class="inspect-agent-section"><div class="inspect-agent-title"><strong>${tr('Agent probes','Проверки агента')}</strong><span>${esc(job.agent)} · ${done}/${checks.length}</span></div>`;
     html+=`<p class="inspect-dispatch-note">${job.state==='queued'?tr('Waiting for the agent’s next sync to deliver the task.','Ожидание следующей синхронизации для передачи задания.'):job.state==='dispatched'?tr('Task delivered. Awaiting results from the agent’s next sync.','Задание передано. Ожидание результатов следующей синхронизации агента.'):job.state==='expired'?tr('No complete agent response within 30 minutes.','Полный ответ агента не получен за 30 минут.'):tr('All selected checks returned.','Получены результаты всех выбранных проверок.')}</p>`;
     html+='<div class="inspect-check-grid">'+checks.map(k=>{
       const r=results[k];const ok=r&&String(r.status).startsWith('OK_');
       return `<div class="inspect-check-result"><div class="inspect-result-top"><strong>${esc(k==='dpi'?'DPI / Content':k.toUpperCase())}</strong><span class="inspect-badge ${!r?'unknown':ok?'ok':'ban'}">${esc(r?.status||tr('Pending','Ожидание'))}</span></div>${r?`<div class="inspect-facts">${tr('Time','Время')}: ${esc(r.duration_ms)} ms · ${tr('Bytes','Байт')}: ${esc(r.bytes)}${r.expected_bytes?' / '+esc(r.expected_bytes):''}${r.http_code?' · HTTP '+esc(r.http_code):''}</div>${r.error?`<p class="inspect-result-error">${esc(r.error)}</p>`:''}${r.details&&Object.keys(r.details).length?`<details><summary>${tr('Probe metadata','Детали проверки')}</summary><pre>${esc(JSON.stringify(r.details,null,2))}</pre></details>`:''}`:''}</div>`;
     }).join('')+'</div></div>';
   }else html+=`<p class="inspect-no-agent">${tr('Central-only check; no agent task was queued.','Только центральная проверка; агенту задание не отправлялось.')}</p>`;
   $('inspect-current').innerHTML=html+'</section>';
 }
 function renderRecent(){
   $('inspect-recent').innerHTML=lastJobs.length?lastJobs.map(j=>`<button type="button" class="inspect-recent-row ${j.id===activeId?'active':''}" data-inspect-id="${esc(j.id)}"><span><strong>${esc(j.host)}</strong><small>${esc(j.requested_at)} · ${esc(j.agent||tr('Central only','Только центр'))}</small></span><span>${statusBadge(j.rip?.status)} ${statusBadge(j.rdo?.status)}</span></button>`).join(''):`<div class="inspect-empty">${tr('No recent inspections','Проверок пока нет')}</div>`;
 }
 async function fetchJSON(url,options){const r=await fetch(url,{cache:'no-store',credentials:'same-origin',...options});let obj;try{obj=await r.json()}catch(_){throw Error('HTTP '+r.status)}if(!r.ok)throw Error(obj.error||'HTTP '+r.status);return obj;}
 async function refresh(){
   if(refreshing)return;
   refreshing=true;
   try{
     const data=await fetchJSON('/ui/api/inspect');lastJobs=data.jobs||[];agents=Array.isArray(data.agents)?data.agents:[];agentOptions();
     renderRecent();
     if(activeId){const found=lastJobs.find(j=>j.id===activeId);const job=found||(await fetchJSON('/ui/api/inspect?id='+encodeURIComponent(activeId))).job;renderJob(job);}
   }catch(e){if(currentPage())$('inspect-form-error').textContent=tr('Cannot load inspections: ','Не удалось получить проверки: ')+e.message}
   finally{refreshing=false;}
 }
 function currentPage(){return location.hash==='#inspect'}
 async function submit(e){
   e.preventDefault();
   const host=$('inspect-host').value.trim(),port=Number($('inspect-port').value);
   const use_agent=$('inspect-use-agent').checked;
   const checks=[...document.querySelectorAll('input[name="inspect-check"]:checked')].map(x=>x.value);
   if(use_agent&&!$('inspect-agent').value){$('inspect-form-error').textContent=tr('Select an agent','Выберите агента');return;}
   if(use_agent&&!checks.length){$('inspect-form-error').textContent=tr('Select at least one check','Выберите хотя бы одну проверку');return;}
   $('inspect-form-error').textContent='';$('inspect-submit').disabled=true;
   try{
     const data=await fetchJSON('/ui/api/inspect',{method:'POST',headers:{'Content-Type':'application/json','X-KVNRadar-Admin':'1'},body:JSON.stringify({host,port,use_agent,agent:$('inspect-agent').value,checks})});
     activeId=data.job.id;try{sessionStorage.setItem('kvnradar-inspect-active',activeId)}catch(_){}
     renderJob(data.job);await refresh();
   }catch(err){$('inspect-form-error').textContent=err.message}
   finally{$('inspect-submit').disabled=false;}
 }
 function load(){translateDOM();agentOptions();toggle();refresh();}
 document.addEventListener('DOMContentLoaded',()=>{
   $('inspect-form').addEventListener('submit',submit);
   $('inspect-use-agent').addEventListener('change',toggle);
   $('inspect-recent').addEventListener('click',e=>{const btn=e.target.closest('[data-inspect-id]');if(!btn)return;activeId=btn.dataset.inspectId;try{sessionStorage.setItem('kvnradar-inspect-active',activeId)}catch(_){};refresh()});
   document.addEventListener('kvnradar:language',()=>{translateDOM();if(currentPage())refresh()});
   setInterval(()=>{if(currentPage())refresh()},7000);
   if(currentPage())load();
 });
 window.KVNInspect={load};
})();
