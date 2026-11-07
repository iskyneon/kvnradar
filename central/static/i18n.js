// KVNRadar native EN/RU localization. English is the initial language.
'use strict';
(()=>{
 const ruToEn={" должен начинаться с /": " must start with /", " интервалов назад": " intervals ago", "24 часа назад": "24 hours ago", "DNS через системный резолвер агента": "DNS via agent system resolver", "HTTPS/DPI проверка передачи содержимого": "HTTPS/DPI content transfer check", "ICMP не использует порт": "ICMP does not use a port", "Агент": "Agent", "Агентов": "Agents", "Агенты": "Agents", "Байты": "Bytes", "Без проблем": "Healthy", "Блоклисты": "Blocklists", "В сети": "Online", "Включая центральные RIP/RDO BAN": "Including central RIP/RDO BAN", "Включён": "Enabled", "Вложенные проверки": "Checks", "Время": "Time", "Время ответа": "Latency", "Все активные сервисы работают": "All active services operational", "Все ресурсы": "All resources", "Все состояния": "All statuses", "Всего": "Total", "Всего ресурсов": "Total resources", "Выключен": "Disabled", "График задержки": "Latency trend", "График появится после нескольких измерений": "Chart will appear after several measurements", "Данные получены": "Data received", "До 500 записей": "Up to 500 records", "Добавить ресурс": "Add resource", "Есть недоступные сервисы": "Some services are down", "Есть проблемы": "Issues", "Загружаем измерения…": "Loading measurements…", "Загрузить": "Load", "Загрузка истории…": "Loading history…", "Загрузка…": "Loading…", "Задержка активных проверок · последние измерения": "Active checks latency · latest measurements", "Зафиксированы отказы сервисов": "Service outages detected", "Здоров": "Healthy", "Идентификатор": "Identifier", "Из окружения": "Environment", "Изменить": "Edit", "Интервал, сек": "Interval, sec", "Исключение RIP (EXC)": "RIP exception (EXC)", "Исключено из RIP": "Excluded from RIP", "Исключён": "Excluded", "История": "History", "История за 24 часа": "24-hour history", "Источник": "Source", "Источники": "Sources", "Маршрут без отдельного TCP-порта": "Route without a separate TCP port", "Мин. байт": "Min. bytes", "Наблюдаются неполадки": "Some services are degraded", "Назначено": "Assigned", "Назначено проверок": "Assigned checks", "Настроено": "Configured", "Настроить проверки": "Configure checks", "Настройки": "Settings", "Не в сети": "Offline", "Не проверять IP ресурса по центральным спискам блокировок; RDO остаётся включённым": "Skip central IP blocklists for this resource; RDO remains enabled", "Не удалось получить актуальные данные": "Unable to retrieve current data", "Не удалось получить данные центрального сервера: ": "Unable to get coordinator data: ", "Недостаточно актуальных измерений": "Not enough recent measurements", "Недоступно": "Outage", "Некорректный порт ": "Invalid port ", "Некоторые проверки требуют внимания": "Some checks require attention", "Нестабильно": "Degraded", "Нет активных ресурсов": "No active resources", "Нет активных ресурсов мониторинга": "No active monitoring resources", "Нет активных сервисов": "No active services", "Нет включённых проверок": "No enabled checks", "Нет данных": "No data", "Нет измерений": "No measurements", "Нет источников": "No sources", "Нет подтверждённого состояния": "No confirmed status", "Нет связи с мониторингом": "Monitoring unavailable", "Ничего не найдено": "Nothing found", "Новый ресурс": "New resource", "Обзор": "Overview", "Обновить": "Refresh", "Обновление состояния…": "Updating status…", "Обновлено": "Updated", "Обновлено ": "Updated ", "Обозначения": "Legend", "Отдельная проверка HTTP (без TLS), по умолчанию порт 80": "Separate HTTP check (no TLS), default port 80", "Отдельная проверка HTTPS, по умолчанию порт 443": "Separate HTTPS check, default port 443", "Отключены": "Disabled", "Отмена": "Cancel", "Отображаемое имя": "Display name", "Ошибка": "Error", "Ошибка загрузки истории: ": "History load failed: ", "Ошибка истории: ": "History error: ", "Ошибка обновления": "Refresh failed", "Ошибка сохранения: ": "Save failed: ", "Ошибка удаления: ": "Delete failed: ", "Ошибки": "Failures", "По умолчанию": "Default", "Подробнее": "Details", "Поиск по имени, хосту или IP": "Search by name, host or IP", "Показывать на публичной странице": "Show on public page", "Получено": "Received", "Порт": "Port", "Последнее обновление успешно": "Last updates OK", "Последний sync": "Last sync", "Последняя проверка": "Last check", "Предупреждение": "Warning", "Проблема": "Issue", "Проверка": "Check", "Проверка IP по локальным спискам": "IP checked against local blocklists", "Проверка домена по локальным спискам": "Domain checked against local blocklists", "Проверки": "Checks", "Проверки по хостингам": "Checks by providers", "Публичный ресурс": "Public resource", "Путь": "Path", "Путь ": "Path ", "Работает": "Operational", "Развернуть": "Expand", "Разделы": "Sections", "Распределённый проверочный агент": "Distributed monitoring agent", "Редактирование ресурса": "Edit resource", "Режим": "Mode", "Результаты": "Results", "Ресурс": "Resource", "Ресурс активен": "Resource enabled", "Ресурс сохранён": "Resource saved", "Ресурс удалён": "Resource deleted", "Ресурсы": "Resources", "Свернуть": "Collapse", "Сейчас": "Now", "Секунды": "Seconds", "Сервисы": "Services", "Совпадение": "Match", "Совпадения": "Matches", "Совпадения по хостам": "Host matches", "Состояние подтверждено актуальными измерениями": "Status confirmed by recent checks", "Сохранить ресурс": "Save resource", "Статус": "Status", "Таймаут, сек": "Timeout, sec", "Тип": "Type", "Тренд задержки": "Latency trend", "Удалить": "Delete", "Удалить ресурс ": "Delete resource ", "Управляющий канал": "Control channel", "Успешно": "Healthy", "Хост / IP": "Host / IP", "Хосты": "Hosts", "записей": "records", "история": "history", "короткие сеансы": "Short sessions", "мс": "ms", "ресурсов": "resources", "сек": "sec", "успешных актуальных проверок": "successful current checks"};
 const enToRu={}; for(const [ru,en] of Object.entries(ruToEn)) if(!(en in enToRu))enToRu[en]=ru;
 // Disambiguate UI labels that share English equivalents.
 enToRu['Agents']='Агенты';
 enToRu['Infrastructure Monitor']='Мониторинг инфраструктуры';
 const sourceNodes=new WeakMap(), sourceAttrs=new WeakMap();
 const KEYS={
  'settings.title':['Settings','Настройки'],
  'settings.description':['Language preferences and read-only runtime configuration.','Язык интерфейса и параметры окружения только для чтения.'],
  'settings.language':['Interface language','Язык интерфейса'],
  'settings.languageHelp':['English is the default. Your selection is stored in this browser.','Английский язык используется по умолчанию. Выбор сохраняется в этом браузере.'],
  'settings.choose':['Language','Язык'],
  'settings.runtime':['Runtime configuration','Текущая конфигурация'],
  'settings.runtimeHelp':['Current environment settings, read-only. Credentials, tokens, chat IDs and private values are never returned.','Текущие параметры окружения только для чтения. Пароли, токены, идентификаторы чатов и другие приватные данные не возвращаются.']
 };
 let lang='en';
 try {lang=localStorage.getItem('kvnradar-language')==='ru'?'ru':'en'}catch(_){}
 function translate(s){
  const dict=lang==='en'?ruToEn:enToRu;
  if(dict[s]!==undefined)return dict[s];
  const trim=s.trim(); if(dict[trim]!==undefined) return s.replace(trim,dict[trim]);
  // Translate known UI prefixes in dynamic status messages, not arbitrary host names.
  const prefixPairs=Object.entries(dict).filter(([source])=>source.endsWith(': ') || source.endsWith(' ')).sort((a,b)=>b[0].length-a[0].length);
  for(const [source,replacement] of prefixPairs){ if(s.startsWith(source))return replacement+s.slice(source.length); }
  return s;
 }
 function nodeText(n){
  if(n.parentElement?.closest('script,style,textarea,code,[data-no-i18n]'))return;
  const prev=sourceNodes.get(n);const actual=n.nodeValue;
  const orig=prev&&prev.rendered===actual?prev.origin:actual;
  const output=translate(orig);
  sourceNodes.set(n,{origin:orig,rendered:output});
  if(actual!==output)n.nodeValue=output;
 }
 function attr(el,name){
  const k=el.getAttribute(name);if(k===null)return;
  let data=sourceAttrs.get(el);if(!data){data={};sourceAttrs.set(el,data)}
  const prev=data[name],orig=prev&&prev.rendered===k?prev.origin:k;
  const output=translate(orig);data[name]={origin:orig,rendered:output};
  if(output!==k)el.setAttribute(name,output);
 }
 let queued=false;
 function apply(){
  queued=false;
  const root=document.body;if(!root)return;
  document.documentElement.lang=lang;
  root.querySelectorAll('[data-i18n-key]').forEach(el=>{const txt=KEYS[el.dataset.i18nKey];if(txt){const wanted=txt[lang==='en'?0:1];if(el.textContent!==wanted)el.textContent=wanted;}});
  const walk=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);let n;
  while(n=walk.nextNode())nodeText(n);
  root.querySelectorAll('[placeholder],[title],[aria-label]').forEach(el=>{for(const name of ['placeholder','title','aria-label'])attr(el,name)});
 }
 function schedule(){if(!queued){queued=true;queueMicrotask(apply)}}
 function setLanguage(value){const next=value==='ru'?'ru':'en';if(lang!==next){lang=next;try{localStorage.setItem('kvnradar-language',lang)}catch(_){};schedule();document.dispatchEvent(new CustomEvent('kvnradar:language',{detail:{lang}}));}}
 document.addEventListener('DOMContentLoaded',()=>{
  apply();const observer=new MutationObserver(schedule);observer.observe(document.body,{subtree:true,childList:true,characterData:true,attributes:true,attributeFilter:['placeholder','title','aria-label']});
 });
 window.KVNI18N={translate,locale:()=>lang==='ru'?'ru-RU':'en-US',lang:()=>lang,setLanguage,refresh:schedule,t:(key)=>KEYS[key]?.[lang==='ru'?1:0]||key};
})();
