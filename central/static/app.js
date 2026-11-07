// KVNRADAR_DISABLE_SSL_VPN_0411
'use strict';
const $=id=>document.getElementById(id);
const ICONS={
  pulse:'<path d="M22 12h-4l-2 5-4-10-2 5H2"/><rect x="3" y="3" width="18" height="18" rx="5"/>',
  plus:'<path d="M12 5v14M5 12h14"/>','refresh-cw':'<path d="M20 11a8 8 0 0 0-14-5L4 8m0-5v5h5m-5 5a8 8 0 0 0 14 5l2-2m0 5v-5h-5"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',x:'<path d="M18 6 6 18M6 6l12 12"/>',
  shield:'<path d="M12 21s8-4 8-10V5l-8-3-8 3v6c0 6 8 10 8 10z"/>', 'lock':'<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  'grid':'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  'tower':'<path d="M12 20v-7"/><path d="M8 20h8"/><path d="M12 5h.01"/><path d="M8 8a6 6 0 0 0 0 8m8-8a6 6 0 0 1 0 8"/>',
  'alert':'<path d="M12 2 2 20h20L12 2z"/><path d="M12 9v4M12 17h.01"/>', 'chevron':'<path d="m9 6 6 6-6 6"/>',
  'activity':'<path d="M3 12h4l3-8 4 16 3-8h4"/>', 'server':'<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
  edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>', 'trash':'<path d="M4 7h16"/><path d="M10 3h4"/><path d="M6 7l1 14h10l1-14"/><path d="M10 11v6M14 11v6"/>',
  'globe':'<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>'
};
function icon(name){return `<svg class="icon" viewBox="0 0 24 24">${ICONS[name]||ICONS.grid}</svg>`}
function decorate(root=document){root.querySelectorAll('[data-icon]').forEach(x=>{x.innerHTML=icon(x.dataset.icon);x.removeAttribute('data-icon')})}
function safe(x){return String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function date(x){if(!x)return '—'; const d=new Date(x); return isNaN(d)?safe(x):d.toLocaleString(window.KVNI18N?.locale()||'en-US',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})}
function number(x){return Number(x||0).toLocaleString(window.KVNI18N?.locale()||'en-US')}
// Agent IDs are sourced from actual server check-ins, not hard-coded placeholders.
function registeredAgentIDs(){return [...new Set((data.agents||[]).map(a=>a.agent).filter(Boolean))].sort()}
function defaultAgentShort(id){const letters=String(id||'').toUpperCase().replace(/[^A-Z]/g,'');return (letters+'XX').slice(0,2)}
function agentLabel(id){return (data.agent_short_names||{})[id]||defaultAgentShort(id)}

const labels={icmp:['Ping / ICMP','activity'],dns:['DNS Lookup','globe'],tcp:['TCP','server'],tls:['TLS','lock'],http_plain:['HTTP','globe'],http_status:['HTTPS','globe'],http_content:['DPI / Content','grid'],traceroute:['Traceroute','activity']};
let data={recent:[],resources:[],agents:[],agent_short_names:{},blocklists:{sources:[],hits:[]},pending:0};
let current='overview', expanded=new Set(), currentDetail='', historyFilter='', search='', filter='all', fetching=false, hasLoaded=false;
function ok(s){return ['OK_FULL','OK_TCP','OK_DNS','OK_ICMP','OK_TLS','OK_HTTP','OK_VPN_PORTAL','OK_TRACE','SHORT_RESPONSE'].includes(s)||String(s||'').startsWith('OK_')}
function tone(s){if(!s) return 'unknown'; if(ok(s)) return s==='SHORT_RESPONSE'?'warn':'ok'; if(/INCONCLUSIVE|NOT_TESTABLE|SHORT|STALE/.test(s)) return 'warn'; return 'fail'}
function statusClass(t){return t==='ok'?'state-ok':t==='warn'?'state-warn':t==='fail'?'state-fail':'state-unknown'}
function badgeStatus(text,t){return `<span class="health-badge ${t==='warn'?'warn':t==='fail'?'fail':''}"><span class="status-dot ${statusClass(t)}">${t==='ok'?'✓':t==='warn'?'!':'•'}</span>${safe(text)}</span>`}
function table(headers,rows){if(!rows.length)return '<div class="empty">Нет данных</div>';return `<table class="data-table"><thead><tr>${headers.map(h=>`<th>${safe(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map(c=>`<td>${safe(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`}
function latest(records){const map=new Map(); for(const r of records){ const k=r.target+'|'+r.agent; if(!map.has(k)) map.set(k,r)} return [...map.values()]}
// Historical samples are for charts only. Current health comes from /ui/api/current.
function enabledKinds(r){return new Set(Object.entries(r.checks||{}).filter(([kind,o])=>kind!=='ssl_vpn'&&o&&o.enabled===true).map(([kind])=>kind))}
function assignedTo(r,agent){return !Array.isArray(r.agents)||r.agents.length===0||r.agents.includes(agent)}
function resourceMeasurements(r){
  const kinds=enabledKinds(r);
  if(r.enabled===false||!kinds.size)return [];
  return (data.recent||[]).filter(x=>{
    const prefix=r.id+'--';
    return typeof x.target==='string'&&x.target.startsWith(prefix)&&kinds.has(x.target.slice(prefix.length))&&assignedTo(r,x.agent);
  });
}
function onlineAgent(agent){
  const seen=(data.agents||[]).find(a=>a.agent===agent)?.last_seen;
  const epoch=seen?Date.parse(seen):NaN;
  return Number.isFinite(epoch)&&Date.now()-epoch<10*60*1000&&epoch-Date.now()<60000;
}
function currentMeasurements(r){
  if(r.enabled===false)return [];
  const kinds=enabledKinds(r);
  if(!kinds.size)return [];
  return (data.current||[]).filter(x=>{
    const prefix=r.id+'--';
    if(typeof x.target!=='string'||!x.target.startsWith(prefix))return false;
    const kind=x.target.slice(prefix.length);
    if(!kinds.has(kind)||!assignedTo(r,x.agent)||!onlineAgent(x.agent))return false;
    const seen=Date.parse(x.received_at||x.ts);
    const updated=Date.parse(r.updated_at);
    // Old results must not be reused after an edit or re-enabling a check.
    if(!Number.isFinite(seen)||(Number.isFinite(updated)&&seen<updated))return false;
    const interval=Math.max(60,Number(r.checks[kind]?.interval_sec)||300);
    const maxAge=Math.max(900,interval*3+120)*1000;
    return seen<=Date.now()+60000 && Date.now()-seen<=maxAge;
  });
}
function summarize(r){
  const m=currentMeasurements(r);
  const hits=r.enabled===false?[]:(data.blocklists?.hits||[]).filter(h=>h.resource_id===r.id);
  const healthy=m.filter(x=>tone(x.status)==='ok').length;
  const total=m.length;
  const warns=m.filter(x=>tone(x.status)==='warn').length;
  const fails=m.filter(x=>tone(x.status)==='fail').length;
  const avg=total?Math.round(m.reduce((n,x)=>n+Number(x.duration_ms||0),0)/total):0;
  // RIP/RDO BAN is a blocklist finding, not service availability. Keep it visible in Blocklists and the central badges only.
  const t=r.enabled===false?'unknown':fails?'fail':warns?'warn':total?'ok':'unknown'; // KVNRADAR_V051_RIP_RDO_NOT_AVAILABILITY
  return {m,hits,healthy,total,warns,fails,avg,t,availability:total?Math.round(healthy/total*10000)/100:0};
}
function spark(values){
  values=values.filter(v=>Number.isFinite(v)).slice().reverse();
  if(values.length<2) return '<div class="empty">График появится после нескольких измерений</div>';
  const w=960,h=240,p=10,max=Math.max(...values),min=Math.min(...values),d=Math.max(1,max-min);
  const pts=values.map((v,i)=>{const x=i/(values.length-1)*(w-2*p)+p; const y=(h-36)-((v-min)/d)*(h-74); return [x,y]});
  const line=pts.map(p=>p.join(',')).join(' ');
  const area=`M ${pts[0][0]} ${h} L `+pts.map(p=>p.join(' ')).join(' L ')+` L ${pts[pts.length-1][0]} ${h} Z`;
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#27d66f" stop-opacity="0.18"/><stop offset="100%" stop-color="#27d66f" stop-opacity="0.02"/></linearGradient></defs><path d="${area}" fill="url(#g)"/><polyline points="${line}" fill="none" stroke="#27d66f" stroke-width="5" stroke-linejoin="round" stroke-linecap="round"/></svg>`;
}
function timeline(records){
  const items=records.slice(0,36).reverse();
  if(!items.length)return '<div class="empty">Нет измерений</div>';
  return `<div class="status-timeline">${items.map(r=>`<span class="status-slot ${tone(r.status)}" title="${safe(r.status)} · ${date(r.ts)}"></span>`).join('')}</div>`;
}
function metricCard(label,value,foot,toneName,iconName){return `<article class="metric-card"><div class="metric-label">${icon(iconName)} ${safe(label)}</div><div class="metric-value">${safe(value)}</div><div class="metric-foot ${toneName==='fail'?'red':''}">${safe(foot)}</div></article>`}
function checkLine(resourceId, kind, checkRecords){
  const label=labels[kind]?.[0]||kind;
  const t=checkRecords.some(r=>tone(r.status)==='fail')?'fail':checkRecords.some(r=>tone(r.status)==='warn')?'warn':checkRecords.length?'ok':'unknown';
  const rightIcon=t==='ok'?'✓':t==='warn'?'!':'•';
  const pills=[...new Set([...registeredAgentIDs(),...checkRecords.map(r=>r.agent)])].map(a=>{const rec=checkRecords.find(r=>r.agent===a);const cls=tone(rec?.status);return `<span class="agent-pill ${cls}"><span class="pill-dot"></span>${safe(agentLabel(a))}${rec?` · ${number(rec.duration_ms)} ms`:''}</span>`}).join('');
  const open=expanded.has(resourceId+'::'+kind);
  return `<div class="line-item"><div class="line-left">${icon(labels[kind]?.[1]||'activity')}<span>${safe(label)}</span></div><div class="line-right"><span class="status-dot ${statusClass(t)}">${rightIcon}</span><button class="chevron-btn" data-action="toggle-check" data-id="${safe(resourceId)}" data-kind="${safe(kind)}">${icon('chevron')}</button></div></div>${open?`<div class="expanded-panel"><div class="agent-pills">${pills||'<span class="empty">Нет данных</span>'}</div></div>`:''}`;
}
function hostCard(r){
  // KVNRADAR_CENTRAL_RIP_RDO_ADMIN_V0415: central checks are independent of agents.
  const central=data.central_checks?.[r.id]||{};
  const centralFresh=central.checked_at && (Date.now()-new Date(central.checked_at).getTime())<900000;
  const overviewCentralBadge=(code,value)=>{
    if((!centralFresh && value!=='EXC') || !['OK','BAN','EXC'].includes(value)) value='UNKNOWN';
    const cls=value==='OK'?'ok':value==='BAN'?'fail':value==='EXC'?'info':'unknown';
    const label=value==='UNKNOWN'?'—':value;
    return `<span class="overview-central-pill ${cls}" title="${code}: ${label}">${code} ${label}</span>`;
  };
  const centralBadge=(code,value)=>{
    if((!centralFresh && value!=='EXC') || !['OK','BAN','EXC'].includes(value)) value='UNKNOWN';
    const cls=value==='OK'?'ok':value==='BAN'?'fail':value==='EXC'?'info':'unknown';
    const symbol=value==='OK'?'✓':value==='BAN'?'×':value==='EXC'?'−':'—';
    const label=value==='UNKNOWN'?'—':value;
    return `<span class="agent-pill ${cls}"><span class="pill-dot"></span>${code} ${label} ${symbol}</span>`;
  };

  const s=summarize(r);
  const records=resourceMeasurements(r);
  const open=expanded.has(r.id);
  const statusText=s.t==='ok'?'Healthy':s.t==='warn'?'Warning':s.t==='fail'?'Issue':r.enabled===false?'Disabled':'No data';
  const enabled=Object.keys(r.checks||{}).filter(k=>r.checks[k].enabled);
  const agents=new Set(s.m.map(x=>x.agent)).size;
  const sub=[r.name&&r.name!==r.host?r.name:null,`${enabled.length} checks`,`${agents} agents`].filter(Boolean).join(' · ');
  const byCheck=enabled.map(k=>[k,s.m.filter(x=>x.target===`${r.id}--${k}`)]);
  const contentSeries=s.m.map(x=>Number(x.duration_ms||0));
  return `<article class="host-card ${open?'is-open':'is-closed'}">
    <button type="button" class="host-summary" data-action="toggle-host" data-id="${safe(r.id)}" aria-expanded="${open}" aria-label="${open?'Свернуть':'Развернуть'} ${safe(r.host)}">
      <span class="host-summary-left"><span class="ring"></span><span class="host-title-text"><strong>${safe(r.host)}</strong><small>${safe(sub)}</small></span></span>
      <span class="host-summary-right">${badgeStatus(statusText,s.t)}<span class="overview-central-badges">${overviewCentralBadge('RIP',central.rip_status)}${overviewCentralBadge('RDO',central.rdo_status)}</span><span class="host-expand-icon">${icon('chevron')}</span></span>
    </button>
    ${open?`<div class="host-expanded">
      <div class="host-availability"><div class="label">Задержка активных проверок · последние измерения</div><div class="value">${s.total?`${s.availability.toFixed(2)}%`:'—'} <small>успешных актуальных проверок</small></div></div>
      <div class="chart-wrap">${spark(contentSeries)}</div>
      ${timeline(records)}
      <div class="section-lines">${`<div class="agent-pills central-checks">${centralBadge("RIP",central.rip_status)}${centralBadge("RDO",central.rdo_status)}</div>`}${byCheck.map(([kind,items])=>checkLine(r.id,kind,items)).join('')||'<div class="empty">Нет включённых проверок</div>'}</div>
      <div class="expanded-actions"><button type="button" class="pill-btn ${r.enabled===false?'host-resume':'host-pause'}" data-action="toggle-monitoring" data-id="${safe(r.id)}">${r.enabled===false?blText('Resume monitoring','Возобновить мониторинг'):blText('Pause monitoring','Приостановить мониторинг')}</button><button class="pill-btn light" data-action="edit" data-id="${safe(r.id)}">Изменить</button><button class="pill-btn light" data-action="delete" data-id="${safe(r.id)}">Удалить</button></div>
    </div>`:''}
  </article>`;
}
function renderOverview(){
  // The native service-status renderer owns #page-overview.
  // Hosts remains the place for technical per-agent expansion.
}

async function toggleMonitoring(id){
  const r=(data.resources||[]).find(x=>x.id===id);
  if(!r) return;
  const enabled=r.enabled===false;
  const question=enabled
    ?blText('Resume monitoring for','Возобновить мониторинг для')
    :blText('Pause monitoring for','Приостановить мониторинг для');
  if(!confirm(`${question} ${r.name||r.host||id}?`)) return;
  try{
    await apiPost('/ui/api/resources/toggle',{id,enabled});
    await refresh();
    toast(enabled?blText('Monitoring resumed','Мониторинг возобновлён'):blText('Monitoring paused','Мониторинг приостановлен'));
  }catch(err){toast(blText('Unable to change monitoring','Не удалось изменить мониторинг')+': '+err.message)}
}
function renderHosts(){
  $('hosts-heading').textContent=blText('Hosts','Хосты');
  $('hosts-description').textContent=blText('Manage monitored hosts. Pause monitoring without losing configuration or history.','Управление хостами. Приостановка сохраняет настройки и историю.');
  $('add-host').textContent=blText('+ Add host','+ Добавить хост');
  let resources=[...(data.resources||[])];
  if(search){const q=search.toLowerCase(); resources=resources.filter(r=>[r.id,r.name,r.host,r.url].some(v=>String(v||'').toLowerCase().includes(q)))}
  if(filter==='healthy') resources=resources.filter(r=>summarize(r).t==='ok');
  if(filter==='issue') resources=resources.filter(r=>['warn','fail'].includes(summarize(r).t));
  if(filter==='disabled') resources=resources.filter(r=>r.enabled===false);
  $('host-total').textContent=`${resources.length} ресурсов`;
  $('hosts-list').innerHTML = resources.length?resources.map(hostCard).join(''):'<div class="soft-card empty">Ничего не найдено</div>';
}
function renderAgents(){
  const agentIds=registeredAgentIDs();
  $('agents-list').innerHTML = agentIds.map(id=>{
    const a=(data.agents||[]).find(x=>x.agent===id);
    const short=agentLabel(id);
    const jobs=(data.resources||[]).filter(r=>r.enabled!==false && (!r.agents?.length || r.agents.includes(id))).reduce((n,r)=>n+Object.values(r.checks||{}).filter(x=>x.enabled).length,0);
    const t=a&&a.last_seen&&(Date.now()-new Date(a.last_seen).getTime())<10*60*1000?'ok':'unknown';
    return `<article class="agent-card"><div class="section-top"><div><h3>${safe(id)} <span class="agent-pill ok">${safe(short)}</span></h3><p>${safe(id)}</p></div><span class="status ${t}">${t==='ok'?'Online':'Offline'}</span></div><div class="agent-facts"><div><small>Последний sync</small><strong>${a?date(a.last_seen):'—'}</strong></div><div><small>Назначено проверок</small><strong>${jobs}</strong></div><div><small>Управляющий канал</small><strong>TLS 1.3</strong></div><div><small>Режим</small><strong>короткие сеансы</strong></div></div><div class="agent-short-editor"><label>${window.KVNI18N?.lang()==='ru'?'Короткое имя':'Short name'} <input type="text" maxlength="2" pattern="[A-Za-z0-9]{2}" data-agent-short="${safe(id)}" value="${safe(short)}" aria-label="Short name for ${safe(id)}"></label><button type="button" class="pill-btn light" data-action="save-agent-short" data-id="${safe(id)}">${window.KVNI18N?.lang()==='ru'?'Сохранить':'Save'}</button><button type="button" class="pill-btn light" data-action="reset-agent-short" data-id="${safe(id)}">${window.KVNI18N?.lang()==='ru'?'Авто':'Auto'}</button></div></article>`;
  }).join('');
}
function blText(en,ru){return window.KVNI18N?.lang()==='ru'?ru:en;}
function renderBlocklists(){
  const sources=data.blocklists?.sources||[];
  const hits=[...(data.blocklists?.hits||[]),...(data.blocklists?.central_matches||[])];
  $('blocklists-heading').textContent=blText('Blocklist sources','Источники блокировок');
  $('blocklists-description').textContent=blText('Manage downloaded RIP/RDO feeds. Changes are saved in SQLite.','Управление списками RIP/RDO. Настройки сохраняются в SQLite.');
  $('add-blocklist-source').textContent=blText('+ Add source','+ Добавить источник');
  $('feed-stats').innerHTML=metricCard(blText('Sources','Источники'),sources.length,blText('Configured','Настроено'),'ok','globe')+
    metricCard(blText('Healthy','Работают'),sources.filter(s=>s.enabled&&s.status==='ok').length,blText('Active and downloaded','Активны и загружены'),'ok','shield')+
    metricCard(blText('Matches','Совпадения'),hits.length,blText('Including RIP/RDO BAN','Включая RIP/RDO BAN'),hits.length?'fail':'ok','alert');
  $('feed-sources').innerHTML=sources.map(s=>{
    const status=!s.enabled?'disabled':s.status;
    return `<article class="feed-card"><div class="section-top"><div><h3>${safe(s.name)}</h3><p>${safe(s.url)}</p></div><span class="status ${status==='ok'?'ok':status==='error'?'fail':'unknown'}">${safe(status)}</span></div>
    <div class="feed-meta"><span>${safe(s.kind==='cidr'?'IP/CIDR':'Domain')} · ${number(s.records)} ${blText('records','записей')}</span><span>${date(s.updated_at)}</span></div>
    ${s.error?`<div class="empty" style="color:#aa3a3a">${safe(s.error)}</div>`:''}
    <div class="feed-controls"><button class="pill-btn light" data-action="bl-edit" data-id="${safe(s.name)}">${blText('Edit','Изменить')}</button><button class="pill-btn light" data-action="bl-toggle" data-id="${safe(s.name)}">${s.enabled?blText('Disable','Отключить'):blText('Enable','Включить')}</button><button class="pill-btn light" data-action="bl-update" data-id="${safe(s.name)}" ${s.enabled?'':'disabled'}>${blText('Update now','Обновить')}</button><button class="pill-btn light bl-delete" data-action="bl-delete" data-id="${safe(s.name)}">${blText('Delete','Удалить')}</button></div></article>`;
  }).join('')||'<div class="soft-card empty">'+blText('No sources','Источников нет')+'</div>';
  $('feed-hits').innerHTML=table([blText('Resource','Ресурс'),blText('Type','Тип'),blText('Source','Источник'),blText('Match','Совпадение'),blText('Last check','Последняя проверка')],hits.map(h=>[h.resource_name||h.resource_id,h.type||'RKN',h.source,h.match,date(h.checked_at)]));
}
function openBlocklistSource(name=''){
  const s=(data.blocklists?.sources||[]).find(x=>x.name===name);
  $('bl-name').value=s?.name||''; $('bl-name').readOnly=!!s;
  $('bl-kind').value=s?.kind||'domain'; $('bl-url').value=s?.url||''; $('bl-enabled').checked=s?.enabled!==0;
  $('blocklist-form-title').textContent=s?blText('Edit source','Изменить источник'):blText('Add source','Добавить источник');
  $('bl-id-label').textContent=blText('Source ID','Идентификатор'); $('bl-type-label').textContent=blText('Type','Тип');
  $('bl-url-label').textContent=blText('HTTPS feed URL','HTTPS-адрес списка'); $('bl-enabled-label').textContent=blText('Enabled','Включён');
  $('blocklist-cancel').textContent=blText('Cancel','Отмена'); $('blocklist-submit').textContent=blText('Save','Сохранить');
  $('blocklist-dialog').showModal();
}
async function manageBlocklist(action,name){
  const s=(data.blocklists?.sources||[]).find(x=>x.name===name);
  if(!s)return;
  let endpoint=action==='bl-toggle'?'save':action==='bl-update'?'update':'delete';
  if(endpoint==='delete'&&!confirm(blText('Delete source ','Удалить источник ')+name+'?'))return;
  const body=endpoint==='save'?{name:s.name,kind:s.kind,url:s.url,enabled:!s.enabled}:{name};
  try{await apiPost('/ui/api/blocklists/source/'+endpoint,body);await refresh();
    toast(endpoint==='update'?blText('Download queued','Загрузка запланирована'):blText('Source updated','Источник обновлён'));
  }catch(e){toast(e.message)}
}

function renderHistory(records){$('history-count').textContent=`${records.length} записей`; $('history-list').innerHTML=table(['Время','Агент','Проверка','Статус','Байты','мс'], records.map(r=>[date(r.ts),agentLabel(r.agent),r.target,r.status,number(r.bytes),number(r.duration_ms)]))}
function render(){renderOverview(); renderHosts(); renderAgents(); renderBlocklists(); decorate();}
function showPage(page){if(!['overview','hosts','agents','blocklists','history','settings'].includes(page)) page='overview'; current=page; document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active', p.id==='page-'+page)); document.querySelectorAll('.nav-link').forEach(b=>b.classList.toggle('active', b.dataset.page===page)); location.hash=page; if(page==='history' && hasLoaded) loadHistory(); if(page==='settings') window.KVNSettings?.load();}
async function updateAgentShort(id, reset=false){
  const input=[...document.querySelectorAll('[data-agent-short]')].find(x=>x.dataset.agentShort===id);
  const short_name=reset?'':String(input?.value||'').trim().toUpperCase();
  if(!reset && !/^[A-Z0-9]{2}$/.test(short_name)){
    toast(window.KVNI18N?.lang()==='ru'?'Требуется ровно два символа A-Z/0-9':'Enter exactly two A-Z/0-9 characters'); return;
  }
  try {await apiPost('/ui/api/agents/short-name',{agent:id,short_name}); await refresh();
    if(current==='overview') document.dispatchEvent(new Event('kvnradar:agents-changed'));
    toast(window.KVNI18N?.lang()==='ru'?'Сокращение сохранено':'Short name saved');
  } catch(err){toast(err.message)}
}
async function apiGet(path){const r=await fetch(path,{cache:'no-store',credentials:'same-origin'}); if(!r.ok) throw Error('HTTP '+r.status); return r.json()}
async function apiPost(path,body){const r=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-KVNRadar-Admin':'1'},body:JSON.stringify(body)}); const d=await r.json(); if(!r.ok) throw Error(d.error||('HTTP '+r.status)); return d}
async function refresh(){ if(fetching) return; fetching=true; try{ data=await apiGet('/ui/data'); const state=await apiGet('/ui/api/current'); data.current=state.current||[]; $('error').classList.add('hidden'); const select=$('history-resource'), prev=select.value; select.innerHTML='<option value="">Все ресурсы</option>' + (data.resources||[]).map(r=>`<option value="${safe(r.id)}">${safe(r.name||r.host||r.id)}</option>`).join(''); select.value=prev; hasLoaded=true; render(); if(current==='history') await loadHistory(); } catch(e){ $('error').textContent='Не удалось получить данные центрального сервера: '+e.message; $('error').classList.remove('hidden'); } finally { fetching=false; }}
function toast(msg){$('toast').textContent=msg; $('toast').classList.add('visible'); setTimeout(()=>$('toast').classList.remove('visible'),3200)}
// KVNRADAR_HTTP_PORTS_V0413: per-check ports, no mandatory resource URL.
function openForm(id){
  const r=(data.resources||[]).find(x=>x.id===id);
  $('form-title').textContent=r?'Редактирование ресурса':'Новый ресурс';
  $('f-id').value=r?.id||'';
  $('f-id').disabled=!!r;
  $('f-name').value=r?.name||'';
  $('f-host').value=r?.host||'';
  $('f-url').value=r?.url||''; // legacy fallback kept in data but not exposed as prerequisite
  $('f-url').closest('label').style.display='none';
  $('f-enabled').checked=r?.enabled??true;
  $('f-rip-exempt').checked=r?.rip_exempt===true;
  const agentNames=[...new Set([...(data.agents||[]).map(a=>a.agent),...(r?.agents||[])])].sort();
  $('f-agents').innerHTML=agentNames.map(a=>`<label><input type="checkbox" data-agent="${safe(a)}" ${r?.agents?.includes(a)?'checked':''}> ${safe(agentLabel(a))}</label>`).join('');
  let oldURL=null;
  try {if(r?.url) oldURL=new URL(r.url);}catch(_){/* optional legacy URL */}
  $('f-checks').innerHTML=Object.entries(labels).filter(([kind])=>kind!=='ssl_vpn').map(([kind,[title]])=>{
    const o=r?.checks?.[kind]||{};
    const httpKind=['http_plain','http_status','http_content'].includes(kind);
    const portKind=['tcp','tls'].includes(kind);
    const isPlain=kind==='http_plain';
    const defaultPort=isPlain?80:443;
    const fallback=oldURL && oldURL.protocol===(isPlain?'http:':'https:')?
      Number(oldURL.port||defaultPort):defaultPort;
    const port=o.port??(httpKind?fallback:443);
    const path=o.path??(oldURL && oldURL.protocol===(isPlain?'http:':'https:')?
      oldURL.pathname+oldURL.search:'/');
    const field=(name,param,value,min,max)=>`<label>${name}<input type="number" data-for="${kind}" data-param="${param}" value="${value}" min="${min}" max="${max}" required></label>`;
    const pathField=()=>`<label>Путь<input type="text" data-for="${kind}" data-param="path" maxlength="512" value="${safe(path)}" placeholder="/"></label>`;
    const portField=(httpKind||portKind)?field('Порт','port',port,1,65535):'';
    const bytes=kind==='http_content'?field('Мин. байт','min_bytes',o.min_bytes??65536,1,4194304):'';
    let note='';
    if(kind==='icmp')note='ICMP не использует порт';
    if(kind==='dns')note='DNS через системный резолвер агента';
    if(kind==='traceroute')note='Маршрут без отдельного TCP-порта';
    if(kind==='http_plain')note='Отдельная проверка HTTP (без TLS), по умолчанию порт 80';
    if(kind==='http_status')note='Отдельная проверка HTTPS, по умолчанию порт 443';
    if(kind==='http_content')note='HTTPS/DPI проверка передачи содержимого';
    return `<div class="editor-check"><div class="editor-check-top"><strong>${safe(title)}</strong><input type="checkbox" data-kind="${kind}" ${o.enabled?'checked':''}></div><div class="editor-check-settings">${portField}${httpKind?pathField():''}${field('Интервал, сек','interval_sec',o.interval_sec??(kind==='traceroute'?900:300),60,86400)}${field('Таймаут, сек','timeout_sec',o.timeout_sec??25,1,120)}${bytes}</div>${note?`<small class="editor-explain">${safe(note)}</small>`:''}</div>`;
  }).join('');
  $('host-dialog').showModal();
}
async function saveHost(e){
  e.preventDefault();
  const obj={id:$('f-id').value.trim(),name:$('f-name').value.trim(),host:$('f-host').value.trim(),url:$('f-url').value.trim(),enabled:$('f-enabled').checked,public:(data.resources||[]).find(x=>x.id===$('f-id').value.trim())?.public===true,rip_exempt:$('f-rip-exempt').checked,
    agents:[...document.querySelectorAll('#f-agents [data-agent]:checked')].map(x=>x.dataset.agent),checks:{}};
  const original=(data.resources||[]).find(x=>x.id===obj.id);
  // Start with existing checks so custom/disabled options are preserved; retire SSL VPN.
  for(const [kind,options] of Object.entries(original?.checks||{})){
    if(kind!=='ssl_vpn')obj.checks[kind]={...options};
  }
  document.querySelectorAll('#f-checks [data-kind]').forEach(el=>{
    const kind=el.dataset.kind;
    const options={...(obj.checks[kind]||{}),enabled:el.checked};
    document.querySelectorAll('#f-checks [data-for]').forEach(input=>{
      if(input.dataset.for!==kind)return;
      const param=input.dataset.param;
      if(param==='path')options.path=input.value.trim()||'/';
      else options[param]=Number(input.value);
    });
    obj.checks[kind]=options;
  });
  for(const [kind,options] of Object.entries(obj.checks)){
    if(['http_plain','http_status','http_content'].includes(kind) && options.enabled){
      if(!options.path.startsWith('/')||options.path.startsWith('//')){
        toast('Путь '+kind+' должен начинаться с /');return;
      }
      if(!Number.isInteger(options.port)||options.port<1||options.port>65535){
        toast('Некорректный порт '+kind);return;
      }
    }
  }
  try{await apiPost('/ui/api/resources/save',obj);$('host-dialog').close();toast('Ресурс сохранён');await refresh();}
  catch(err){toast('Ошибка сохранения: '+err.message);}
}

async function deleteHost(id){ if(!confirm('Удалить ресурс '+id+'?')) return; try{ await apiPost('/ui/api/resources/delete',{id}); toast('Ресурс удалён'); await refresh(); } catch(err){ toast('Ошибка удаления: '+err.message); }}
async function showDetails(id){ currentDetail=id; const r=(data.resources||[]).find(x=>x.id===id); if(!r) return; $('detail-title').textContent=(r.name||r.host||r.id)+' · история'; $('detail-body').innerHTML='<div class="empty">Загружаем измерения…</div>'; $('detail-dialog').showModal(); try{ const d=await apiGet('/ui/api/results?resource='+encodeURIComponent(id)); const records=d.results||[]; const enabledChecks=Object.keys(r.checks||{}).filter(k=>r.checks[k].enabled); $('detail-body').innerHTML=`<div class="detail-grid"><div class="detail-stat"><span>Всего</span><strong>${records.length}</strong></div><div class="detail-stat"><span>Ошибки</span><strong>${records.filter(x=>tone(x.status)==='fail').length}</strong></div><div class="detail-stat"><span>Агенты</span><strong>${new Set(records.map(x=>x.agent)).size}</strong></div><div class="detail-stat"><span>Проверки</span><strong>${enabledChecks.length}</strong></div></div><div class="chart-panel"><h3>Latency trend</h3>${spark(records.slice(0,50).map(x=>Number(x.duration_ms||0)))}</div><div class="soft-card">${enabledChecks.map(kind=>{const items=records.filter(x=>x.target===id+'--'+kind);return `<div class="line-mini"><strong>${safe(labels[kind]?.[0]||kind)}</strong><div class="toolbar-meta">${items.slice(0,5).map(x=>`${safe(agentLabel(x.agent))}: ${safe(x.status)} (${number(x.duration_ms)} ms)`).join(' · ')||'Нет измерений'}</div></div>`}).join('')}</div><div class="soft-card" style="margin-top:16px">${table(['Время','Агент','Проверка','Статус','Байты','мс'], records.slice(0,100).map(x=>[date(x.ts),agentLabel(x.agent),x.target.split('--').pop(),x.status,number(x.bytes),number(x.duration_ms)]))}</div>`; } catch(err){ $('detail-body').innerHTML='<div class="empty">Ошибка: '+safe(err.message)+'</div>'; }}
async function loadHistory(){ const filterValue=$('history-resource').value; historyFilter=filterValue; $('history-list').innerHTML='<div class="empty">Загрузка истории…</div>'; try{ const d=await apiGet('/ui/api/results'+(filterValue?'?resource='+encodeURIComponent(filterValue):'')); if(current==='history' && $('history-resource').value===filterValue) renderHistory(d.results||[]); } catch(err){ $('history-list').innerHTML='<div class="empty">Ошибка загрузки истории: '+safe(err.message)+'</div>'; toast('Ошибка истории: '+err.message); }}
document.addEventListener('click', e=>{ const btn=e.target.closest('[data-action]'); if(!btn) return; const id=btn.dataset.id; if(btn.dataset.action==='toggle-host'){ if(expanded.has(id)) expanded.delete(id); else expanded.add(id); render(); return; } if(btn.dataset.action==='toggle-check'){ const key=id+'::'+btn.dataset.kind; if(expanded.has(key)) expanded.delete(key); else expanded.add(key); render(); return; } if(btn.dataset.action==='details') showDetails(id); if(btn.dataset.action==='edit') openForm(id); if(btn.dataset.action==='delete') deleteHost(id); if(btn.dataset.action==='toggle-monitoring') toggleMonitoring(id); if(btn.dataset.action==='save-agent-short') updateAgentShort(id); if(btn.dataset.action==='reset-agent-short') updateAgentShort(id,true); if(btn.dataset.action==='bl-edit') openBlocklistSource(id); if(['bl-toggle','bl-update','bl-delete'].includes(btn.dataset.action)) manageBlocklist(btn.dataset.action,id); });
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>showPage(b.dataset.page)); $('add-host').onclick=()=>openForm(''); $('close-form').onclick=()=>$('host-dialog').close(); $('cancel-form').onclick=()=>$('host-dialog').close(); $('host-form').onsubmit=saveHost; $('close-detail').onclick=()=>$('detail-dialog').close(); $('detail-edit').onclick=()=>{$('detail-dialog').close(); openForm(currentDetail)}; $('host-search').oninput=e=>{search=e.target.value.trim(); renderHosts()}; $('host-filter').onchange=e=>{filter=e.target.value; renderHosts()}; $('history-resource').onchange=loadHistory; $('history-refresh').onclick=loadHistory; showPage(location.hash.slice(1)||'overview'); decorate(); refresh(); setInterval(refresh,30000); document.addEventListener('kvnradar:language',()=>{if(hasLoaded){render();if(current==='history')loadHistory();}});

$('add-blocklist-source').onclick=()=>openBlocklistSource();
$('blocklist-close').onclick=()=>$('blocklist-dialog').close();
$('blocklist-cancel').onclick=()=>$('blocklist-dialog').close();
$('blocklist-form').onsubmit=async e=>{
  e.preventDefault();
  const body={name:$('bl-name').value.trim(),kind:$('bl-kind').value,url:$('bl-url').value.trim(),enabled:$('bl-enabled').checked};
  try{await apiPost('/ui/api/blocklists/source/save',body);$('blocklist-dialog').close();await refresh();toast(blText('Source saved','Источник сохранён'));}
  catch(err){toast(err.message)}
};
