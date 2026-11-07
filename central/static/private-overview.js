// Native admin Overview. No iframe, no public proxy.
(()=>{
// KVNRadar v0.5.0.3: no removed hero banner dependency; compact infrastructure icon; RIP/RDO labels.
'use strict';
const $=id=>document.getElementById(id);
const T=value=>window.KVNI18N?.translate(value)||value;
const labels={healthy:['Все активные сервисы работают','Состояние подтверждено актуальными измерениями'],degraded:['Наблюдаются неполадки','Некоторые проверки требуют внимания'],outage:['Есть недоступные сервисы','Зафиксированы отказы сервисов'],unknown:['Нет подтверждённого состояния','Недостаточно актуальных измерений']};
const stateText={healthy:'Работает',degraded:'Нестабильно',outage:'Недоступно',unknown:'Нет данных'};
function esc(x){return String(x??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]))}
function state(s){return Object.prototype.hasOwnProperty.call(stateText,s)?s:'unknown'}
function render(data){
 const services=Array.isArray(data.services)?data.services:[];
 const overall=services.length?state(data.overall):'unknown';
 const [title,subtitle]=services.length?labels[overall]:['Нет активных сервисов','Нет активных ресурсов мониторинга'];
 const banner=$('overall');
 if (banner) { banner.className='overall '+overall; banner.innerHTML=`<div class="overall-symbol">${overall==='healthy'?'✓':overall==='unknown'?'—':'!'}</div><div><h2>${T(title)}</h2><p>${T(subtitle)}</p></div>`; }
 const mark=document.querySelector('.brand-mark');
 if (mark) { const glyph=overall==='healthy' ? '<path d="M5 12h4l2-5 4 10 2-5h2"/>' : overall==='degraded' ? '<circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/>' : overall==='outage' ? '<path d="M12 3 22 20H2L12 3z"/><path d="M12 9v5m0 3h.01"/>' : '<circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/>'; const palette={healthy:['#e1f4e9','#22a95f'],degraded:['#fff0c8','#b78312'],outage:['#ffe0dd','#d3423b'],unknown:['#e9eeea','#87918a']}[overall]; mark.innerHTML=`<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${glyph}</svg>`; mark.dataset.status=overall; mark.style.backgroundColor=palette[0]; mark.style.color=palette[1]; }

 $('services').innerHTML=services.map(s=>{
  const current=state(s.status);
  const ticks=(Array.isArray(s.timeline)?s.timeline:[]).slice(0,48);
  const checks=Array.isArray(s.checks)?s.checks:[];
  const matrix=checks.map(c=>{
   const rawCode=String(c.code||'').toUpperCase();
   const code=esc(rawCode.slice(0,8));
   const hosting=Array.isArray(c.hosting)?c.hosting:[];
   // Central blocklist checks are not hosting/agent checks: show exact RIP/RDO result.
   if ((rawCode==='RIP'||rawCode==='RDO') && hosting.some(h=>['CENTRAL','CENTRA'].includes(String(h.code||'').toUpperCase()))) {
    const h=hosting.find(x=>['CENTRAL','CENTRA'].includes(String(x.code||'').toUpperCase()));
    const rawState=String(h.status||'');
    const t=rawState==='exc'?'exc':state(rawState);
    const value=t==='healthy'?'OK':t==='outage'?'BAN':t==='exc'?'EXC':'—';
    const excluded=t==='exc';
    const cls=excluded?'excluded':t==='healthy'?'healthy':t==='outage'?'outage':'unknown';
    const shown=excluded?'EXC':value;
    return `<span class="check-group central-result"><strong>${code}</strong><span class="hosting-chip ${cls}" title="${T(excluded?'Исключено из RIP':rawCode==='RIP'?'Проверка IP по локальным спискам':'Проверка домена по локальным спискам')}"><b>${shown}</b></span></span>`;
   }
   return `<span class="check-group"><strong>${code}</strong>${hosting.map(h=>{const t=state(h.status); const symbol=t==='healthy'?'✓':t==='degraded'?'!':t==='outage'?'×':'–'; return `<span class="hosting-chip ${t}" title="${T(stateText[t])}">${esc(String(h.code||'').slice(0,6))} <b>${symbol}</b></span>`}).join('')||'<span class="hosting-chip unknown">—</span>'}</span>`;
  }).join('');
  return `<article class="service"><div class="service-head"><div><h3>${esc(s.name)}</h3><p>${esc(s.description)}</p></div><div class="service-controls"><div class="status ${current}">${T(stateText[current])}</div>${s.id!=null?`<button type="button" class="service-details-btn" data-action="details" data-id="${esc(s.id)}" aria-label="${esc(T('Details')+' — '+s.name)}">${T('Details')}</button>`:''}</div></div>${matrix?`<div class="check-matrix" aria-label="${T('Проверки по хостингам')}">${matrix}</div>`:''}<div class="timeline" aria-label="${T('История за 24 часа')}">${ticks.map((v,i)=>`<span class="tick ${state(v)}" title="${48-i}–${47-i} ${T('интервалов назад')}: ${T(stateText[state(v)])}"></span>`).join('')}</div><div class="axis"><span>${T('24 часа назад')}</span><span>${T('Сейчас')}</span></div></article>`;
 }).join('')||`<div class="empty">${T('Нет активных ресурсов')}</div>`;
 const d=new Date(data.generated_at);$('updated-at').textContent=isNaN(d.getTime())?T('Данные получены'):T('Обновлено ')+d.toLocaleTimeString(window.KVNI18N?.locale()||'en-US',{hour:'2-digit',minute:'2-digit'});
 $('live-dot').className='dot ok';
}
async function refresh(){try{const r=await fetch('/ui/api/private-status',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);render(await r.json())}catch(e){$('live-dot').className='dot error';$('updated-at').textContent=T('Ошибка обновления');const banner=$('overall');if(banner){banner.className='overall unknown';banner.innerHTML=`<div class="overall-symbol">!</div><div><h2>${T('Нет связи с мониторингом')}</h2><p>${T('Не удалось получить актуальные данные')}</p></div>`;}const mark=document.querySelector('.brand-mark');if(mark){mark.dataset.status='unknown';mark.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/></svg>';}}}
refresh();setInterval(refresh,60000);document.addEventListener('kvnradar:language', refresh);document.addEventListener('kvnradar:agents-changed', refresh);

})();
