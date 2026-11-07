// KVNRadar native admin Settings. Read-only and explicit allowlist server-side.
'use strict';
(()=>{
 const config=document.getElementById('settings-config');
 const sel=document.getElementById('ui-language');
 let cached=null;
 const text=(en,ru)=>window.KVNI18N?.lang()==='ru'?ru:en;
 function escape(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
 function render(){
  if(sel)sel.value=window.KVNI18N?.lang()||'en';
  if(!config || !cached)return;
  const rows=[...(cached.entries||[]),
   {key:'COMPASS_NOTIFICATIONS',value:cached.notifications?.compass?'enabled':'disabled',source:'computed'},
   {key:'TELEGRAM_NOTIFICATIONS',value:cached.notifications?.telegram?'enabled':'disabled',source:'computed'}];
  config.innerHTML=rows.map(x=>`<div class="setting-row"><code>${escape(x.key)}</code><div class="setting-value" data-no-i18n>${escape(x.value==='enabled'?text('Enabled','Включено'):x.value==='disabled'?text('Disabled','Выключено'):x.value)}<small class="setting-source">${escape(x.source==='environment'?text('Environment','Окружение'):x.source==='default'?text('Default','По умолчанию'):text('Computed','Вычислено'))}</small></div></div>`).join('');
 }
 async function load(){if(cached){render();return}if(!config)return;try{const r=await fetch('/ui/api/settings',{credentials:'same-origin',cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);cached=await r.json();render()}catch(e){config.textContent=text('Cannot load settings: ','Не удалось загрузить настройки: ')+e.message}}
 if(sel)sel.addEventListener('change',e=>window.KVNI18N?.setLanguage(e.target.value));
 document.addEventListener('kvnradar:language',render);
 window.KVNSettings={load};
 if(location.hash==='#settings')load();
})();
