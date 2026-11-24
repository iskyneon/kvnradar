// KVNRadar native admin Settings. Read-only and explicit allowlist server-side.
'use strict';
(()=>{
 const config=document.getElementById('settings-config');
 const sel=document.getElementById('ui-language');
 const status=document.getElementById('maintenance-status');
 const clearButton=document.getElementById('settings-clear-history');
 const message=document.getElementById('maintenance-message');
 let cached=null;
 const text=(en,ru)=>window.KVNI18N?.lang()==='ru'?ru:en;
 function escape(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
 function render(){
  if(sel)sel.value=window.KVNI18N?.lang()||'en';
  if(!config || !cached)return;
  const maintenance=cached.maintenance||{};
  const title=document.getElementById('maintenance-title');
  const help=document.getElementById('maintenance-help');
  if(title)title.textContent=text('Database maintenance','Обслуживание базы данных');
  if(help)help.textContent=text('Scheduled VACUUM is configured through .env. Clearing history is irreversible; configuration and live status are preserved.','Периодический VACUUM настраивается в .env. Очистка истории необратима; конфигурация и текущие статусы сохраняются.');
  if(clearButton)clearButton.textContent=text('Clear History','Очистить историю');
  if(status){
   const size=n=>(Number(n||0)/1048576).toFixed(1)+' MiB';
   const interval=maintenance.interval_seconds===0?text('Disabled','Отключено'):
     maintenance.interval_seconds===86400?text('Every 24 hours','Каждые 24 часа'):
     Math.round(maintenance.interval_seconds/3600*10)/10+' h';
   const total=Object.values(maintenance.history_counts||{}).reduce((a,b)=>a+Number(b||0),0);
   const entries=[
     [text('VACUUM schedule','Расписание VACUUM'),interval],
     [text('Last VACUUM','Последний VACUUM'),maintenance.last_vacuum_at?new Date(maintenance.last_vacuum_at).toLocaleString():text('Not yet run','Ещё не запускался')],
     [text('Database allocated','Размер базы'),size(maintenance.db_bytes)],
     [text('Unused database pages','Свободные страницы'),size(maintenance.free_bytes)],
     [text('History records','Записей истории'),total.toLocaleString()],
     [text('VACUUM state','Состояние VACUUM'),maintenance.vacuum_running?text('Running','Выполняется'):maintenance.vacuum_error?text('Error: ','Ошибка: ')+maintenance.vacuum_error:text('Idle','Ожидание')]
   ];
   status.innerHTML=entries.map(([k,v])=>`<div class="setting-row"><code>${escape(k)}</code><div class="setting-value">${escape(v)}</div></div>`).join('');
  }
  const rows=[...(cached.entries||[]),
   {key:'COMPASS_NOTIFICATIONS',value:cached.notifications?.compass?'enabled':'disabled',source:'computed'},
   {key:'TELEGRAM_NOTIFICATIONS',value:cached.notifications?.telegram?'enabled':'disabled',source:'computed'},
   {key:'EMAIL_NOTIFICATIONS',value:cached.notifications?.email?'enabled':'disabled',source:'computed'}];
  config.innerHTML=rows.map(x=>`<div class="setting-row"><code>${escape(x.key)}</code><div class="setting-value" data-no-i18n>${escape(x.value==='enabled'?text('Enabled','Включено'):x.value==='disabled'?text('Disabled','Выключено'):x.value)}<small class="setting-source">${escape(x.source==='environment'?text('Environment','Окружение'):x.source==='default'?text('Default','По умолчанию'):text('Computed','Вычислено'))}</small></div></div>`).join('');
 }
 async function load(){if(!config)return;try{const r=await fetch('/ui/api/settings',{credentials:'same-origin',cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);cached=await r.json();render()}catch(e){config.textContent=text('Cannot load settings: ','Не удалось загрузить настройки: ')+e.message}}
 if(clearButton)clearButton.addEventListener('click',async()=>{
  const warning=text('Permanently delete measurement, RIP/RDO check, inspection, and notification failure history? Resources, current checks, feeds, and notifications remain.','Безвозвратно удалить историю измерений, RIP/RDO, проверок Inspect и ошибок доставки? Ресурсы, текущие проверки, списки и уведомления сохранятся.');
  if(!confirm(warning))return;
  clearButton.disabled=true;
  if(message)message.textContent=text('Clearing history…','Очищаем историю…');
  try{
   const r=await fetch('/ui/api/history/clear',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-KVNRadar-Admin':'1'},body:JSON.stringify({confirm:'CLEAR_HISTORY'})});
   const result=await r.json();if(!r.ok)throw Error(result.error||'HTTP '+r.status);
   cached=null;await load();
   if(message)message.textContent=text('History cleared. Database compaction queued.','История очищена. Уплотнение базы поставлено в очередь.');
  }catch(e){if(message)message.textContent=text('Error: ','Ошибка: ')+e.message}
  finally{clearButton.disabled=false}
 });
 if(sel)sel.addEventListener('change',e=>window.KVNI18N?.setLanguage(e.target.value));
 document.addEventListener('kvnradar:language',render);
 window.KVNSettings={load};
 if(location.hash==='#settings')load();
})();
