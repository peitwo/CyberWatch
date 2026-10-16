const $ = (id) => document.getElementById(id);
let events = [];
const levels = {high: '高风险', medium: '中风险', low: '低风险'};
const statusLabels = {open: '待处理', investigating: '调查中', resolved: '已解决'};
/* 徽章类名走白名单：即使接口被污染返回奇怪的值，也只会退化成固定安全类名 */
const severityValues = ['high','medium','low'];
const statusValues = ['open','investigating','resolved'];
function severityClass(value){ return severityValues.includes(value) ? value : 'low'; }
function statusClass(value){ return statusValues.includes(value) ? 'status-'+value : 'status-open'; }
/* 表格列的唯一声明处：增删列只改这里，colSpan 会自动跟随，不会再出现「加了列忘了改 colspan」 */
const COLUMNS = [
  {render: e => String(e.id)},
  {render: e => e.title},
  {badge: true, render: e => ({pill: 'pill '+severityClass(e.severity), text: levels[e.severity]||e.severity})},
  {badge: true, render: e => ({pill: 'pill '+statusClass(e.status), text: statusLabels[e.status]||e.status})},
  {render: e => e.description ?? ''},
  {render: e => displayDate(e.created_at)}
];
function displayDate(raw) { if(!raw)return '—'; const d=new Date(raw); return Number.isNaN(d.getTime())?'—':d.toLocaleString('zh-CN'); }
function setText(id, value) { $(id).textContent = String(value); }
let alertTimer = null;
let pendingDeleteId = null;
/* 统一提示条：文本一律走 textContent，避免用户输入被当成 HTML 解析 */
function notify(message, type) { const box=$('alert'); box.className=`alert ${type}`; box.textContent=message; box.hidden=false; if(alertTimer)clearTimeout(alertTimer); alertTimer=setTimeout(()=>{box.hidden=true;box.textContent='';},type==='error'?6000:4000); }
/* 把 FastAPI 的错误体翻译成可读中文，detail 可能是字符串也可能是校验错误数组 */
async function describeError(response) { if(response.status===404)return 'HTTP 404：事件不存在，可能已被删除'; const raw=await response.text(); let detail=''; try{const parsed=JSON.parse(raw);detail=parsed?.detail??'';}catch{detail=raw.slice(0,180);} if(Array.isArray(detail))detail=detail.map(item=>item?.msg??JSON.stringify(item)).join('；'); return `HTTP ${response.status}：${detail||'请求失败'}`; }
function findEvent(id) { return events.find(item=>item.id===id); }
function closeDialog(id) { const dialog=$(id); if(dialog&&dialog.open)dialog.close(); }
function actionButton(action, id, label, hint) { const btn=document.createElement('button'); btn.type='button'; btn.className=action==='delete'?'btn-mini danger':'btn-mini edit'; btn.dataset.action=action; btn.dataset.id=String(id); btn.textContent=label; btn.title=hint; btn.setAttribute('aria-label',`${hint} ${id}`); return btn; }
function actionCell(event) { const cell=document.createElement('td'); const wrap=document.createElement('div'); wrap.className='row-actions'; wrap.append(actionButton('edit',event.id,'✎ 编辑','编辑事件'),actionButton('delete',event.id,'✕ 删除','删除事件')); cell.append(wrap); return cell; }
function openEditDialog(id) { const event=findEvent(id); if(!event)return; const form=$('edit-form'); form.elements.namedItem('event_id').value=String(event.id); form.elements.namedItem('title').value=event.title??''; form.elements.namedItem('severity').value=event.severity??'low'; form.elements.namedItem('status').value=event.status??'open'; form.elements.namedItem('description').value=event.description??''; $('edit-error').textContent=''; $('edit-dialog').showModal(); }
function openConfirmDialog(id) { const event=findEvent(id); if(!event)return; pendingDeleteId=id; $('confirm-name').textContent=event.title??`#${id}`; $('confirm-dialog').showModal(); }
function render() {
  const term = $('search').value.trim().toLowerCase();
  const level = $('severity').value;
  const state = $('status').value;
  const filtered = events.filter(e => (level==='all'||e.severity===level) && (state==='all'||e.status===state) && (`${e.title} ${e.description??''}`).toLowerCase().includes(term));
  const tbody = $('event-rows'); tbody.replaceChildren();
  if (!filtered.length) { const tr=document.createElement('tr'); const td=document.createElement('td'); td.colSpan=COLUMNS.length+1;td.className='empty';td.textContent=events.length?'没有符合条件的安全事件':'还没有安全事件，点击「新建事件」创建第一条吧 ♡';tr.append(td);tbody.append(tr);return; }
  for(const e of filtered){
    const tr=document.createElement('tr');
    for(const column of COLUMNS){
      const td=document.createElement('td'); const value=column.render(e);
      if(column.badge){const badge=document.createElement('span');badge.className=value.pill;badge.textContent=String(value.text??'');td.append(badge);}else{td.textContent=String(value??'');}
      tr.append(td);
    }
    tr.append(actionCell(e));
    tbody.append(tr);
  }
}
async function loadEvents(){
  setText('api-state','连接中');
  try{
    const response=await fetch('/events?offset=0&limit=100',{cache:'no-store'});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const result=await response.json();if(!Array.isArray(result))throw new Error('接口返回格式异常');
    events=result;setText('api-state','已连接');
    setText('total',events.length);for(const key of ['high','medium','low'])setText(key,events.filter(e=>e.severity===key).length);
    setText('notice',events.length===100?'仅加载最近 100 条记录；统计卡片并非全库总数。':'统计卡片对应当前已加载的事件记录。');
    render();
  }catch(err){setText('api-state','连接失败');setText('notice',`获取事件失败：${err.message}`);notify(`获取事件失败：${err.message}`,'error');$('event-rows').replaceChildren();const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=COLUMNS.length+1;td.className='empty';td.textContent='无法读取事件，请检查后端服务器是否启动';tr.append(td);$('event-rows').append(tr);}
}
$('search').addEventListener('input',render);$('severity').addEventListener('change',render);$('status').addEventListener('change',render);$('refresh').addEventListener('click',loadEvents);
$('new-btn').addEventListener('click',()=>{$('form-error').textContent='';$('new-dialog').showModal()});
for(const id of ['close-dialog','cancel'])$(id).addEventListener('click',()=>$('new-dialog').close());
$('create-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const form=ev.currentTarget;const save=$('save');const data=Object.fromEntries(new FormData(form).entries());save.disabled=true;$('form-error').textContent='';
  try{const resp=await fetch('/events',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(!resp.ok){const body=await resp.text();throw new Error(`HTTP ${resp.status}: ${body.slice(0,180)}`)}$('new-dialog').close();form.reset();await loadEvents();}
  catch(err){$('form-error').textContent=`保存失败：${err.message}`;}
  finally{save.disabled=false;}
});
/* 操作列：用事件委托监听，重渲染后依然生效 */
$('event-rows').addEventListener('click',ev=>{const btn=ev.target.closest('button[data-action]');if(!btn)return;const id=Number(btn.dataset.id);if(btn.dataset.action==='edit')openEditDialog(id);else openConfirmDialog(id);});
for(const id of ['close-edit','edit-cancel'])$(id).addEventListener('click',()=>closeDialog('edit-dialog'));
for(const id of ['close-confirm','confirm-cancel'])$(id).addEventListener('click',()=>closeDialog('confirm-dialog'));
/* 编辑：只提交 title / severity / status / description，未提交字段由后端保持原值 */
$('edit-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const form=ev.currentTarget;const save=$('edit-save');const read=name=>form.elements.namedItem(name).value;const id=Number(read('event_id'));
  const payload={title:read('title').trim(),severity:read('severity'),status:read('status'),description:read('description')};
  save.disabled=true;$('edit-error').textContent='';
  try{const resp=await fetch(`/events/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!resp.ok)throw new Error(await describeError(resp));closeDialog('edit-dialog');await loadEvents();notify(`事件 #${id} 已更新`,'success');}
  catch(err){$('edit-error').textContent=`保存失败：${err.message}`;}
  finally{save.disabled=false;}
});
/* 删除：必须先在确认弹窗确认，再发 DELETE */
$('confirm-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const button=$('confirm-delete');const id=pendingDeleteId;
  if(id===null){closeDialog('confirm-dialog');return;}
  button.disabled=true;
  try{const resp=await fetch(`/events/${id}`,{method:'DELETE'});if(!resp.ok)throw new Error(await describeError(resp));closeDialog('confirm-dialog');pendingDeleteId=null;await loadEvents();notify(`事件 #${id} 已删除`,'success');}
  catch(err){closeDialog('confirm-dialog');notify(`删除失败：${err.message}`,'error');await loadEvents();}
  finally{button.disabled=false;}
});
loadEvents();
