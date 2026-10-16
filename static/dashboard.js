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
/* 归档中心的数据与状态：归档事件单独存一份，普通列表永远只放未归档事件 */
const ARCHIVE_PAGE_SIZE = 50;              /* 「加载更多」每次追加的条数 */
let archivedEvents = [];                   /* 已加载（当前窗口内）的归档事件 */
let archivedTotal = 0;                     /* 后端权威总数，对应「共 N 条」的 N */
let archiveWindowSize = ARCHIVE_PAGE_SIZE; /* 窗口目标条数：恢复后按它重取，保持分页位置 */
let archiveLoading = false;                /* 并发闸门：同一时刻只允许一个在途加载 */
let archivePendingWant = null;             /* 在途期间到来的新请求：只保留最后一次意图 */
let pendingRestoreId = null;
/* 统一提示条：文本一律走 textContent，避免用户输入被当成 HTML 解析 */
function notify(message, type) { const box=$('alert'); box.className=`alert ${type}`; box.textContent=message; box.hidden=false; if(alertTimer)clearTimeout(alertTimer); alertTimer=setTimeout(()=>{box.hidden=true;box.textContent='';},type==='error'?6000:4000); }
/* 把 FastAPI 的错误体翻译成可读中文，detail 可能是字符串也可能是校验错误数组 */
async function describeError(response) { if(response.status===404)return 'HTTP 404：事件不存在，可能已被删除'; const raw=await response.text(); let detail=''; try{const parsed=JSON.parse(raw);detail=parsed?.detail??'';}catch{detail=raw.slice(0,180);} if(Array.isArray(detail))detail=detail.map(item=>item?.msg??JSON.stringify(item)).join('；'); return `HTTP ${response.status}：${detail||'请求失败'}`; }
function findEvent(id) { return events.find(item=>item.id===id) || archivedEvents.find(item=>item.id===id); }
function closeDialog(id) { const dialog=$(id); if(dialog&&dialog.open)dialog.close(); }
const actionStyles = {detail:'btn-mini detail', edit:'btn-mini edit', delete:'btn-mini danger', restore:'btn-mini restore'};
function actionButton(action, id, label, hint) { const btn=document.createElement('button'); btn.type='button'; btn.className=actionStyles[action]||'btn-mini edit'; btn.dataset.action=action; btn.dataset.id=String(id); btn.textContent=label; btn.title=hint; btn.setAttribute('aria-label',`${hint} ${id}`); return btn; }
function actionCell(event) { const cell=document.createElement('td'); const wrap=document.createElement('div'); wrap.className='row-actions'; wrap.append(actionButton('detail',event.id,'☰ 详情','查看事件详情与时间线'),actionButton('edit',event.id,'✎ 编辑','编辑事件'),actionButton('delete',event.id,'✕ 归档','归档事件')); cell.append(wrap); return cell; }
/* 归档中心的每行只有「详情 / 恢复」：归档事件不可编辑，只能查看或恢复 */
function archiveActionCell(event) { const cell=document.createElement('td'); const wrap=document.createElement('div'); wrap.className='row-actions'; wrap.append(actionButton('detail',event.id,'☰ 详情','查看事件详情与时间线'),actionButton('restore',event.id,'↺ 恢复','恢复该事件')); cell.append(wrap); return cell; }
/* 状态转移的原因规则：与后端 requires_status_reason 完全一致。
   前端只是体验层（提前提示），真正的闸门在 FastAPI 后端。 */
function reasonRequirement(oldStatus, newStatus) {
  if (!oldStatus || oldStatus === newStatus) return null;
  if (oldStatus === 'investigating' && newStatus === 'resolved') return {label:'解决原因（必填）', required:true, reopen:false};
  if (oldStatus === 'resolved' && (newStatus === 'open' || newStatus === 'investigating')) return {label:'重新打开原因（必填）', required:true, reopen:true};
  return {label:'变更原因（可选）', required:false, reopen:false};
}
function editReason() { return $('edit-form').elements.namedItem('reason'); }
let editingOriginalStatus = null;
/* 按「编辑前的状态 → 下拉框选中的状态」动态显示 / 隐藏原因输入框 */
function syncReasonField() {
  const target = $('edit-form').elements.namedItem('status').value;
  const requirement = reasonRequirement(editingOriginalStatus, target);
  const label = $('edit-reason-label');
  if (!requirement) { label.hidden = true; editReason().value = ''; return; }
  $('edit-reason-text').textContent = requirement.label;
  label.hidden = false;
}
function openEditDialog(id) { const event=findEvent(id); if(!event)return; const form=$('edit-form'); editingOriginalStatus=event.status??'open'; form.elements.namedItem('event_id').value=String(event.id); form.elements.namedItem('title').value=event.title??''; form.elements.namedItem('severity').value=event.severity??'low'; form.elements.namedItem('status').value=event.status??'open'; form.elements.namedItem('description').value=event.description??''; editReason().value=''; syncReasonField(); $('edit-error').textContent=''; $('edit-dialog').showModal(); }
function openConfirmDialog(id) { const event=findEvent(id); if(!event)return; pendingDeleteId=id; $('confirm-name').textContent=event.title??`#${id}`; $('confirm-dialog').showModal(); }
/* ---------- 事件详情：基本信息 + 状态变更时间线（全部 textContent 渲染） ---------- */
function detailLine(label, value) { const p=document.createElement('p'); p.className='detail-line'; const k=document.createElement('b'); k.textContent=label; const v=document.createElement('span'); v.textContent=String(value??''); p.append(k,v); return p; }
function renderDetailMeta(event) { const box=$('detail-meta'); box.replaceChildren(); box.append(detailLine('事件标题',event.title),detailLine('风险等级',levels[event.severity]||event.severity),detailLine('生命周期状态',statusLabels[event.status]||event.status),detailLine('创建时间',displayDate(event.created_at))); if(event.deleted_at) box.append(detailLine('归档时间',displayDate(event.deleted_at))); }
function statusBadge(status) { const span=document.createElement('span'); span.className='pill '+statusClass(status); span.textContent=statusLabels[status]||status; return span; }
function renderTimeline(rows) {
  const list=$('timeline'); list.replaceChildren();
  if(!rows.length){ const li=document.createElement('li'); li.className='timeline-empty'; li.textContent='还没有状态变更记录'; list.append(li); return; }
  for(const row of rows){
    const li=document.createElement('li');
    const head=document.createElement('div'); head.className='timeline-head';
    if(row.action==='archive'){ const tag=document.createElement('span'); tag.className='pill archive-pill'; tag.textContent='已归档'; head.append(tag); }
    else{ const arrow=document.createElement('span'); arrow.className='timeline-arrow'; arrow.textContent='→'; head.append(statusBadge(row.old_status),arrow,statusBadge(row.new_status)); }
    const time=document.createElement('time'); time.className='timeline-time'; time.textContent=displayDate(row.changed_at); head.append(time);
    li.append(head);
    if(row.reason){ const p=document.createElement('p'); p.className='timeline-reason'; p.textContent=row.reason; li.append(p); }
    const meta=document.createElement('p'); meta.className='timeline-meta'; meta.textContent=`操作主体：${row.actor_id}　·　动作：${row.action}`;
    li.append(meta);
    list.append(li);
  }
}
async function openDetailDialog(id) {
  const event=findEvent(id); if(!event)return;
  renderDetailMeta(event); $('timeline').replaceChildren(); $('detail-dialog').showModal();
  try{
    const resp=await fetch(`/events/${id}/history`,{cache:'no-store'});
    if(!resp.ok)throw new Error(await describeError(resp));
    const rows=await resp.json();
    renderTimeline(Array.isArray(rows)?rows:[]);
  }catch(err){
    const li=document.createElement('li'); li.className='timeline-empty'; li.textContent=`加载时间线失败：${err.message}`; $('timeline').append(li);
  }
}
/* ---------- 归档中心：查看已归档事件 + 恢复（全部 textContent 渲染） ---------- */
function archiveEmptyRow(text) { const tr=document.createElement('tr'); const td=document.createElement('td'); td.colSpan=6; td.className='empty'; td.textContent=text; tr.append(td); return tr; }
/* 「共 N 条，当前显示 M 条」+ 「加载更多」按钮的显隐，全部集中在这里算，避免多处各写一份 */
function renderArchiveFooter() {
  const shown = archivedEvents.length;
  const remaining = Math.max(archivedTotal - shown, 0);
  setText('archive-count', archivedTotal);                                  /* 入口徽章 = 权威总数，不是当前页大小 */
  setText('archive-summary', `共 ${archivedTotal} 条，当前显示 ${shown} 条`);
  const more = $('archive-more');
  more.hidden = remaining === 0;
  more.textContent = `↧ 加载更多（还有 ${remaining} 条）`;
}
function renderArchive() {
  const tbody=$('archive-rows'); tbody.replaceChildren();
  if(!archivedEvents.length){
    tbody.append(archiveEmptyRow(archivedTotal>0?'归档事件还没加载进来，点一下下方「加载更多」把它们请出来 ♡':'归档中心是空的，暂时没有已归档事件 ♡'));
    renderArchiveFooter(); return;
  }
  for(const e of archivedEvents){
    const tr=document.createElement('tr');
    /* 列：ID / 事件名称 / 等级 / 状态 / 归档时间 —— 药丸复用白名单，文字一律 textContent */
    const cells=[String(e.id), e.title, {pill:'pill '+severityClass(e.severity), text:levels[e.severity]||e.severity}, {pill:'pill '+statusClass(e.status), text:statusLabels[e.status]||e.status}, displayDate(e.deleted_at)];
    for(const [index,value] of cells.entries()){
      const td=document.createElement('td');
      if(value && typeof value==='object' && value.pill){ const badge=document.createElement('span'); badge.className=value.pill; badge.textContent=String(value.text??''); td.append(badge); }
      else { td.textContent=String(value??''); }
      /* 标题列会被 CSS 截成省略号：补一个原生悬浮提示，完整标题仍以「详情」弹窗为准 */
      if(index===1) td.title=String(value??'');
      tr.append(td);
    }
    tr.append(archiveActionCell(e));
    tbody.append(tr);
  }
  renderArchiveFooter();
}
/* ---------- 归档中心的分页加载 ---------- */
async function fetchArchivedPage(offset, limit) {
  const resp=await fetch(`/events/archived?offset=${offset}&limit=${limit}`,{cache:'no-store'});
  if(!resp.ok)throw new Error(await describeError(resp));
  const rows=await resp.json();
  return Array.isArray(rows)?rows:[];
}
async function fetchArchivedTotal() {
  const resp=await fetch('/events/archived/count',{cache:'no-store'});
  if(!resp.ok)throw new Error(await describeError(resp));
  const body=await resp.json();
  const total=Number(body?.total);
  return Number.isFinite(total)?total:0;
}
/* 实际执行一次窗口加载：从 offset=0 起按 50 条串行抓取，直到凑够 want 条。
   - offset 用**实际返回条数**推进（不是「想要多少」），中途归档集合变化也不会跳页 → 不遗漏；
   - 同一 id 只收一次 → 不重复；
   - 只以「本页为空」为终止条件，天然不会死循环。 */
async function runArchiveLoad(want) {
  archivedTotal = await fetchArchivedTotal();
  const goal = Math.min(Math.max(want,0), archivedTotal);
  const seen = new Set();
  const items = [];
  let offset = 0;
  while (items.length < goal && offset < archivedTotal) {
    const page = await fetchArchivedPage(offset, ARCHIVE_PAGE_SIZE);
    if (!page.length) break;
    offset += page.length;
    for (const row of page) {
      if (seen.has(row.id)) continue;
      seen.add(row.id);
      items.push(row);
    }
  }
  archivedEvents = items;
  renderArchive();
}
/* 并发闸门 + 请求合并：同一时刻只允许一个在途加载；期间到来的新请求
   只保留「最后一次意图」，等当前这次跑完再补跑一次。这样连续点击
   「加载更多」既不会发出重复请求，也不会丢掉最后一次点击。 */
async function loadArchiveWindow(want) {
  if (archiveLoading) { archivePendingWant = want; return; }
  archiveLoading = true;
  try {
    let target = want;
    for (;;) {
      await runArchiveLoad(target);
      if (archivePendingWant === null) break;
      target = archivePendingWant;
      archivePendingWant = null;
    }
  } finally {
    archiveLoading = false;
  }
}
/* 归档中心关闭时只需要总数（维持入口徽章准确），打开时按当前窗口大小重取 */
async function refreshArchive() { await loadArchiveWindow($('archive-dialog').open ? archiveWindowSize : 0); }
/* 归档列表 + 普通列表 + 统计卡片一起刷新（恢复/归档成功后调用） */
async function reloadLists() { await loadEvents(); try{ await refreshArchive(); }catch(err){ setText('archive-count','—'); setText('archive-summary','归档统计获取失败'); } }
function showArchiveStatus(message,type) { const box=$('archive-status'); if(!box)return; box.className=`archive-status ${type}`; box.textContent=message; box.hidden=false; }
async function openArchiveDialog() {
  $('archive-status').hidden=true; $('archive-status').textContent='';
  archiveWindowSize=ARCHIVE_PAGE_SIZE;                 /* 每次打开都从第一页（50 条）开始 */
  $('archive-rows').replaceChildren(archiveEmptyRow('正在加载归档事件...'));
  $('archive-dialog').showModal();
  try{ await loadArchiveWindow(archiveWindowSize); }
  catch(err){ $('archive-rows').replaceChildren(archiveEmptyRow(`加载归档事件失败：${err.message}`)); }
}
function openRestoreDialog(id) {
  const event=findEvent(id); if(!event)return;
  pendingRestoreId=id;
  $('restore-name').textContent=event.title??`#${id}`;
  $('restore-error').textContent='';
  $('restore-dialog').showModal();
}
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
$('search').addEventListener('input',render);$('severity').addEventListener('change',render);$('status').addEventListener('change',render);$('refresh').addEventListener('click',reloadLists);
$('new-btn').addEventListener('click',()=>{$('form-error').textContent='';$('new-dialog').showModal()});
for(const id of ['close-dialog','cancel'])$(id).addEventListener('click',()=>$('new-dialog').close());
$('create-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const form=ev.currentTarget;const save=$('save');const data=Object.fromEntries(new FormData(form).entries());save.disabled=true;$('form-error').textContent='';
  try{const resp=await fetch('/events',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(!resp.ok){const body=await resp.text();throw new Error(`HTTP ${resp.status}: ${body.slice(0,180)}`)}$('new-dialog').close();form.reset();await loadEvents();}
  catch(err){$('form-error').textContent=`保存失败：${err.message}`;}
  finally{save.disabled=false;}
});
/* 操作列：用事件委托监听，重渲染后依然生效 */
$('event-rows').addEventListener('click',ev=>{const btn=ev.target.closest('button[data-action]');if(!btn)return;const id=Number(btn.dataset.id);const action=btn.dataset.action;if(action==='edit')openEditDialog(id);else if(action==='detail')openDetailDialog(id);else openConfirmDialog(id);});
for(const id of ['close-edit','edit-cancel'])$(id).addEventListener('click',()=>closeDialog('edit-dialog'));
for(const id of ['close-confirm','confirm-cancel'])$(id).addEventListener('click',()=>closeDialog('confirm-dialog'));
for(const id of ['close-reopen','reopen-cancel'])$(id).addEventListener('click',()=>closeDialog('reopen-dialog'));
for(const id of ['close-detail','detail-close'])$(id).addEventListener('click',()=>closeDialog('detail-dialog'));
for(const id of ['close-archive','archive-close'])$(id).addEventListener('click',()=>closeDialog('archive-dialog'));
for(const id of ['close-restore','restore-cancel'])$(id).addEventListener('click',()=>closeDialog('restore-dialog'));
$('archive-btn').addEventListener('click',openArchiveDialog);
/* 「加载更多」：每次在已加载条数基础上再加 50 条；按钮点击期间禁用，避免连点 */
$('archive-more').addEventListener('click',async ()=>{
  const button=$('archive-more');
  button.disabled=true;
  try{
    archiveWindowSize=archivedEvents.length+ARCHIVE_PAGE_SIZE;
    await loadArchiveWindow(archiveWindowSize);
  }
  catch(err){ showArchiveStatus(`加载更多失败：${err.message}`,'error'); }
  finally{ button.disabled=false; }
});
/* 归档中心的操作列：同样是事件委托（详情 / 恢复） */
$('archive-rows').addEventListener('click',ev=>{const btn=ev.target.closest('button[data-action]');if(!btn)return;const id=Number(btn.dataset.id);const action=btn.dataset.action;if(action==='detail')openDetailDialog(id);else if(action==='restore')openRestoreDialog(id);});
$('edit-form').elements.namedItem('status').addEventListener('change',syncReasonField);
/* 统一的 PATCH 提交：只发 title / severity / status / description（+ 需要时的 reason），
   未提交字段由后端保持原值（局部更新语义） */
let pendingReopen = null;
async function sendPatch(id, payload) {
  const resp=await fetch(`/events/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  if(!resp.ok)throw new Error(await describeError(resp));
  closeDialog('edit-dialog');closeDialog('reopen-dialog');pendingReopen=null;
  await loadEvents();notify(`事件 #${id} 已更新`,'success');
}
$('edit-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const form=ev.currentTarget;const save=$('edit-save');const read=name=>form.elements.namedItem(name).value;const id=Number(read('event_id'));
  const target=read('status');const reason=read('reason').trim();
  const requirement=reasonRequirement(editingOriginalStatus,target);
  $('edit-error').textContent='';
  /* 前端体验层校验：必填方向不能留空。后端还会再校验一次，绕过前端也拦得住。 */
  if(requirement&&requirement.required&&!reason){$('edit-error').textContent=`${requirement.label.replace('（必填）','')}不能为空`;return;}
  const payload={title:read('title').trim(),severity:read('severity'),status:target,description:read('description')};
  if(reason)payload.reason=reason;
  /* 已解决 → 重新打开：必须走二次确认弹窗，填好重开原因后才真正提交 */
  if(requirement&&requirement.reopen){const event=findEvent(id);pendingReopen={id,payload};$('reopen-form').elements.namedItem('reopen_reason').value='';$('reopen-error').textContent='';$('reopen-name').textContent=event?event.title:`#${id}`;closeDialog('edit-dialog');$('reopen-dialog').showModal();return;}
  save.disabled=true;
  try{await sendPatch(id,payload);}
  catch(err){$('edit-error').textContent=`保存失败：${err.message}`;}
  finally{save.disabled=false;}
});
/* 二次确认：重新打开已解决的事件（需求：resolved → open/investigating 必须二次确认 + 填原因） */
$('reopen-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const button=$('reopen-confirm');const reason=$('reopen-form').elements.namedItem('reopen_reason').value.trim();
  if(!reason){$('reopen-error').textContent='重新打开原因不能为空';return;}
  if(!pendingReopen)return;
  button.disabled=true;
  const {id,payload}=pendingReopen;payload.reason=reason;
  try{await sendPatch(id,payload);}
  catch(err){$('reopen-error').textContent=`重新打开失败：${err.message}`;}
  finally{button.disabled=false;}
});
/* 归档（软删除）：必须先在确认弹窗确认，再发 DELETE；事件与历史都保留 */
$('confirm-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const button=$('confirm-delete');const id=pendingDeleteId;
  if(id===null){closeDialog('confirm-dialog');return;}
  button.disabled=true;
  try{const resp=await fetch(`/events/${id}`,{method:'DELETE'});if(!resp.ok)throw new Error(await describeError(resp));closeDialog('confirm-dialog');pendingDeleteId=null;await reloadLists();notify(`事件 #${id} 已归档`,'success');}
  catch(err){closeDialog('confirm-dialog');notify(`归档失败：${err.message}`,'error');await reloadLists();}
  finally{button.disabled=false;}
});
/* 恢复（取消归档）：确认弹窗 → POST /events/{id}/restore
   成功后必须刷新「归档列表 + 普通列表 + 统计卡片」，并给出可见提示。 */
$('restore-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const button=$('restore-confirm');const id=pendingRestoreId;
  if(id===null){closeDialog('restore-dialog');return;}
  button.disabled=true;$('restore-error').textContent='';
  try{
    const resp=await fetch(`/events/${id}/restore`,{method:'POST'});
    if(!resp.ok)throw new Error(await describeError(resp));
    closeDialog('restore-dialog');pendingRestoreId=null;
    await reloadLists();                                   /* 归档列表 + 普通列表 + 统计卡片 */
    if($('archive-dialog').open) showArchiveStatus(`事件 #${id} 已恢复，已回到普通列表 ♡`,'success');
    notify(`事件 #${id} 已恢复`,'success');
  }
  catch(err){$('restore-error').textContent=`恢复失败：${err.message}`;}
  finally{button.disabled=false;}
});
reloadLists();
