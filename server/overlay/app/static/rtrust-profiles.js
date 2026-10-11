'use strict';
const el = id => document.getElementById(id);
const csrf = document.querySelector('meta[name="csrf-token"]').content;
let previewId = null, profiles = [], devices = [], groups = [], expiry, managedCredentials=false;
async function api(path, method='GET', body, extra={}) {
  const response = await fetch('/portal/v2/'+path, {method, credentials:'same-origin', cache:'no-store', redirect:'error', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...extra}, body:body===undefined?undefined:JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) { const error = new Error(response.status===401?'Войдите в кабинет заново.':response.status===409?'Конфиг изменён или требуется согласие на потерю полей. Обновите список.':'Операция отклонена ('+response.status+').'); error.result=result; error.status=response.status; throw error; }
  return result;
}
function status(text){el('status').textContent=text;}
function button(label, action){const node=document.createElement('button');node.textContent=label;node.onclick=()=>perform(node,action);return node;}
async function perform(node,action){node.disabled=true;try{await action();}catch(error){status(error.message);}finally{node.disabled=false;}}
function clearPreview(){previewId=null;el('preview-result').hidden=true;el('summary').textContent='';el('content').value='';el('file').value='';}
async function refresh(){
  const values=await Promise.all([api('profiles'),api('devices?include_revoked=1'),api('route-groups'),api('capabilities')]);profiles=values[0].profiles;devices=values[1].devices;groups=values[2].groups;managedCredentials=values[3].device_credentials?.version===1;
  const activeDevices=devices.filter(d=>!d.revoked);
  el('profiles').replaceChildren();el('devices').replaceChildren();
  for(const profile of profiles){
    const row=document.createElement('div');row.className='row';const title=document.createElement('strong');title.textContent=profile.summary.name+' — '+profile.summary.hostname;row.append(title);
    row.append(button('Скачать', async()=>{
      if(!confirm('Экспорт содержит VPN-пароль. Сохранить файл?'))return;
      const format=el('format').value, data={format,revision:profile.revision,include_secrets:true};let exported;
      try{exported=await api('profiles/'+profile.id+'/export','POST',data);}catch(error){
        if(!error.result?.losses||!confirm('Формат не сохранит поля:\n'+JSON.stringify(error.result.losses)+'\nПродолжить?'))throw error;
        exported=await api('profiles/'+profile.id+'/export','POST',{...data,accept_losses:true});
      }
      const url=URL.createObjectURL(new Blob([exported.content],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='rtrust-'+profile.id+({profile_json:'.json',endpoint_toml:'.toml',cli_toml:'.toml',tt:'.txt'}[format]);link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);status('Конфиг экспортирован.');
    }));
    if(profile.origin==='external_stored')row.append(button('Удалить',async()=>{if(!confirm('Удалить сохранённый профиль?'))return;await api('profiles/'+profile.id,'DELETE',undefined,{'If-Match':profile.revision});await refresh();}));
    if(activeDevices.length){const select=document.createElement('select');select.setAttribute('aria-label','Устройство для '+profile.summary.name);for(const device of activeDevices){const option=document.createElement('option');option.value=device.id;option.textContent=device.name;select.append(option);}row.append(select);
      for(const [label,allow] of [['Дать доступ',true],['Отозвать доступ',false]])row.append(button(label,async()=>{await api('profiles/'+profile.id+'/grants','POST',{device_id:Number(select.value),allow});status(managedCredentials&&profile.id.startsWith('managed-')?'Запрос credentials записан. Подтвердите применение на endpoint отдельно.':allow?'Доступ предоставлен.':'Доступ отозван в панели. Скачанные пароли остаются действующими.');await refresh();}));
    }el('profiles').append(row);
  }
  if(!profiles.length)el('profiles').textContent='Профилей пока нет.';
  renderGroups();
  for(const device of devices){
    const row=document.createElement('div');row.className='row';const title=document.createElement('strong');title.textContent=device.name+' ('+device.platform+')'+(device.revoked?' · API-доступ отозван':'');const group=groups.find(g=>g.devices.includes(device.id));row.append(title,text('Группа маршрутов TUN: '+(group?group.name:'нет')));
    if(!device.revoked)row.append(button('Отозвать устройство',async()=>{if(!confirm('Отозвать доступ устройства в панели? Managed credentials потребуют отдельного подтверждённого применения на endpoint.'))return;const result=await api('devices/'+device.id,'DELETE');await refresh();status(result.vpn?.profiles?.some(p=>p.state!=='applied')?'API-доступ отозван. Отзыв на endpoint ожидает подтверждения.':'API-доступ отозван. Общие и внешние пароли этим действием не отзываются.');}));
    if(managedCredentials || device.revoked){
      const access=await api('devices/'+device.id+'/credentials');
      for(const credential of access.profiles){
        row.append(text(credential.id+' · '+credential.state+' · поколение '+credential.generation+(credential.legacy_shared_access==='unmanaged'?' · прежний общий пароль вне управляемого отзыва':'')));
        if(!device.revoked && credential.desired==='active')row.append(button('Запросить ротацию '+credential.id,async()=>{if(!confirm('Создать новые credentials устройства? Их применение отдельно потребует рестарта endpoint.'))return;await api('profiles/'+credential.id+'/device-credentials','POST',{device_id:device.id,expected_generation:credential.generation,request_key:crypto.randomUUID(),consent:true});await refresh();status('Ротация запрошена. Применение пока не подтверждено.');}));
      }
      if(access.profiles.some(p=>p.state!=='applied'))row.append(button('Применить и проверить endpoint',async()=>{
        if(!confirm('Рестарт endpoint прервёт ВСЕ его текущие VPN-сессии. Credentials остальных устройств сохранятся. Продолжить?'))return;
        const result=await api('devices/'+device.id+'/credentials/reconcile','POST',{consent_restart_endpoint:true});await refresh();status(result.profiles.every(p=>p.state==='applied')?'Применение managed credentials подтверждено проверками HTTP/2 и HTTP/3. Общие и внешние пароли учитываются отдельно.':'Остались неподтверждённые credentials. Проверьте состояние; успех не объявлен.');
      }));
    }
    el('devices').append(row);
  }

}
el('file').onchange=async()=>{try{const file=el('file').files[0];if(!file)return;if(file.size>1048576)throw new Error('Файл больше 1 МиБ.');previewId=null;el('preview-result').hidden=true;el('content').value=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());}catch(error){status(error.message);}};
el('content').oninput=()=>{previewId=null;el('preview-result').hidden=true;};
el('preview').onclick=()=>perform(el('preview'),async()=>{const result=await api('profile-imports/preview','POST',{content:el('content').value,intent:'external_stored'});previewId=result.preview_id;el('summary').textContent=JSON.stringify(result.summary,null,2);el('preview-result').hidden=false;status('Профиль проверен. Сохранение требует подтверждения.');});
el('commit').onclick=()=>perform(el('commit'),async()=>{if(!previewId)throw new Error('Сначала проверьте профиль.');await api('profile-imports/'+previewId+'/commit','POST',{action:'create',consent:true});clearPreview();await refresh();status('Профиль сохранён.');});
el('cancel').onclick=clearPreview;
el('enroll').onclick=()=>perform(el('enroll'),async()=>{const result=await api('enrollment-codes','POST',location.protocol==='https:'?{origin:location.origin}:{});el('code').textContent=result.code;el('enrollment-qr').hidden=!result.qr_svg;if(result.qr_svg)el('enrollment-qr').src='data:image/svg+xml;base64,'+result.qr_svg;clearTimeout(expiry);expiry=setTimeout(()=>{el('code').textContent='Код истёк.';el('enrollment-qr').hidden=true;el('enrollment-qr').removeAttribute('src');},result.expires_in*1000);status('Введите адрес этой панели и код в приложении.');});
function text(value){const node=document.createElement('span');node.className='muted';node.textContent=value;return node;}
function field(label,node){const wrap=document.createElement('label');wrap.append(label,node);return wrap;}
function networks(value){return value.split(/[\s,;]+/).filter(Boolean);}
function policy(name,include,exclude,lan){return {name:name.trim(),include:networks(include),exclude:networks(exclude),exclude_lan:lan};}
async function routeApi(path,method,body,extra){
  try{return await api(path,method,body,extra);}catch(error){
    if(error.status===422)throw new Error('Проверьте название (1–80 символов) и сети: CIDR IPv4 вида 10.0.0.0/8 без битов хоста, до 16 сетей и до 64 исключений.');
    if(error.status===409)throw new Error('Группа изменена в другом окне или достигнут лимит в 50 групп. Обновите страницу.');
    throw error;
  }
}
function renderGroups(){
  const activeDevices=devices.filter(d=>!d.revoked);
  el('route-groups').replaceChildren();
  for(const group of groups){
    const row=document.createElement('div');row.className='row';const title=document.createElement('strong');title.textContent=group.name;row.append(title);
    const name=document.createElement('input');name.maxLength=80;name.value=group.name;name.autocomplete='off';
    const include=document.createElement('textarea');include.rows=2;include.spellcheck=false;include.value=group.include.join(', ');
    const exclude=document.createElement('textarea');exclude.rows=2;exclude.spellcheck=false;exclude.value=group.exclude.join(', ');
    const lan=document.createElement('input');lan.type='checkbox';lan.checked=group.exclude_lan;const check=field(lan,' Исключить локальные сети');check.className='check';
    const names=group.devices.map(id=>(devices.find(d=>d.id===id)||{name:'#'+id}).name);
    row.append(field('Название',name),field('Сети через VPN',include),field('Исключения',exclude),check,text('Устройства: '+(names.length?names.join(', '):'нет')));
    row.append(button('Сохранить',async()=>{await routeApi('route-groups/'+group.id,'PUT',{...policy(name.value,include.value,exclude.value,lan.checked),revision:group.revision});await refresh();status('Группа сохранена. Устройства получат маршруты при следующем подключении.');}));
    row.append(button('Удалить',async()=>{if(!confirm('Удалить группу маршрутов? Устройства группы останутся без серверной политики маршрутов.'))return;await routeApi('route-groups/'+group.id,'DELETE',undefined,{'If-Match':String(group.revision)});await refresh();status('Группа удалена.');}));
    if(activeDevices.length){const select=document.createElement('select');select.setAttribute('aria-label','Устройство для группы '+group.name);for(const device of activeDevices){const option=document.createElement('option');option.value=device.id;option.textContent=device.name;select.append(option);}row.append(select);
      for(const [label,member] of [['Добавить в группу',true],['Убрать из группы',false]])row.append(button(label,async()=>{await routeApi('route-groups/'+group.id+'/members','POST',{device_id:Number(select.value),member});await refresh();status(member?'Устройство добавлено в группу; прежнее членство, если было, заменено.':'Устройство убрано из группы.');}));
    }el('route-groups').append(row);
  }
  if(!groups.length)el('route-groups').textContent='Групп пока нет.';
}
el('route-create').onclick=()=>perform(el('route-create'),async()=>{await routeApi('route-groups','POST',policy(el('route-name').value,el('route-include').value,el('route-exclude').value,el('route-lan').checked));el('route-name').value='';el('route-include').value='';el('route-exclude').value='';await refresh();status('Группа создана. Добавьте в неё устройства.');});
window.addEventListener('pageshow',()=>refresh().catch(error=>status(error.message)));
