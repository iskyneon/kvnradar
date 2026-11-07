// KVNRadar v0.6.8 - read-only audit of failed notification delivery attempts.
'use strict';
(()=>{
 const root=document.getElementById('notification-failures');
 const button=document.getElementById('notification-failures-refresh');
 if(!root)return;
 const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const tr=(en,ru)=>window.KVNI18N?.lang()==='ru'?ru:en;
 let data=null,loading=false,page=1;
 const PAGE_SIZE=15,DEPTH=250;
 const pagesRoot=document.getElementById('notification-failures-pages');
 function render(){
  const title=document.getElementById('notification-failures-title');
  const desc=document.getElementById('notification-failures-description');
  if(title)title.textContent=tr('Notification delivery failures','Ошибки доставки уведомлений');
  if(desc)desc.textContent=tr('Failed Email, Telegram and Compass attempts only. No message bodies or credentials are stored.','Только неудачные попытки Email, Telegram и Compass. Тексты сообщений и секреты не сохраняются.');
  if(button)button.textContent=tr('Refresh','Обновить');
  if(data===null)return;
  if(!data.length){root.innerHTML='<div class="notification-failures-empty">'+escape(tr('No failed deliveries recorded.','Ошибок доставки не зарегистрировано.'))+'</div>';if(pagesRoot)pagesRoot.innerHTML='';return}
  const total=data.length;const pages=Math.max(1,Math.ceil(total/PAGE_SIZE));page=Math.min(Math.max(1,page),pages);
  const part=data.slice((page-1)*PAGE_SIZE,page*PAGE_SIZE);
  const headings=[tr('Time','Время'),tr('Channel','Канал'),tr('Outbox ID','ID уведомления'),tr('Attempt','Попытка'),tr('Error','Ошибка')];
  root.innerHTML='<div class="notification-failures-table"><table><thead><tr>'+headings.map(h=>'<th>'+escape(h)+'</th>').join('')+'</tr></thead><tbody>'+part.map(r=>'<tr class="notification-failure-row"><td>'+escape(r.occurred_at)+'</td><td class="channel">'+escape(r.channel)+'</td><td>'+escape(r.outbox_id)+'</td><td>'+escape(r.attempt)+'</td><td>'+escape(r.error_type)+'</td></tr>') .join('')+'</tbody></table></div>';
  if(pagesRoot){
   const links=Array.from({length:pages},(_,i)=>{const p=i+1;return '<button type="button" class="history-page-btn'+(p===page?' active':'')+'" data-notif-page="'+p+'" '+(p===page?'aria-current="page"':'')+'>'+p+'</button>'}).join('');
   pagesRoot.innerHTML=pages<=1?'':'<div class="history-pagination-info">'+escape(tr('Showing','Показано'))+' '+((page-1)*PAGE_SIZE+1)+'–'+Math.min(total,page*PAGE_SIZE)+' '+escape(tr('of','из'))+' '+total+' · '+escape(tr('Last 250 max','Не более 250 последних'))+'</div><div class="history-pagination-buttons"><button type="button" class="history-page-btn" data-notif-page="'+(page-1)+'" '+(page===1?'disabled':'')+'>‹</button>'+links+'<button type="button" class="history-page-btn" data-notif-page="'+(page+1)+'" '+(page===pages?'disabled':'')+'>›</button></div>';
  }
 }
 async function refresh(){
  if(loading)return;loading=true;
  try{const response=await fetch('/ui/api/notification-failures',{cache:'no-store',credentials:'same-origin'});
   if(!response.ok)throw Error('HTTP '+response.status);
   const body=await response.json();data=Array.isArray(body.failures)?body.failures.slice(0,DEPTH):[];render();
  }catch(err){root.textContent=tr('Cannot load notification failures: ','Не удалось загрузить ошибки доставки: ')+err.message}
  finally{loading=false}
 }
 if(button)button.addEventListener('click',refresh);
 if(pagesRoot)pagesRoot.addEventListener('click',e=>{const b=e.target.closest('[data-notif-page]');if(!b)return;const p=Number(b.dataset.notifPage);if(Number.isInteger(p)&&p>=1&&p<=Math.ceil((data||[]).length/PAGE_SIZE)){page=p;render()}});
 document.querySelectorAll('[data-page="history"]').forEach(b=>b.addEventListener('click',refresh));
 window.addEventListener('hashchange',()=>{if(location.hash==='#history')refresh()});
 document.addEventListener('kvnradar:language',render);
 if(location.hash==='#history')refresh();
 setInterval(()=>{if(location.hash==='#history')refresh()},30000);
})();
