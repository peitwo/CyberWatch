const $ = (id) => document.getElementById(id);
let events = [];
const levels = {high: '高风险', medium: '中风险', low: '低风险'};
function displayDate(raw) { if(!raw)return '—'; const d=new Date(raw); return Number.isNaN(d.getTime())?'—':d.toLocaleString('zh-CN'); }
function setText(id, value) { $(id).textContent = String(value); }
function render() {
  const term = $('search').value.trim().toLowerCase();
  const level = $('severity').value;
  const filtered = events.filter(e => (level==='all'||e.severity===level) && (`${e.title} ${e.description??''}`).toLowerCase().includes(term));
  const tbody = $('event-rows'); tbody.replaceChildren();
  if (!filtered.length) { const tr=document.createElement('tr'); const td=document.createElement('td'); td.colSpan=5;td.className='empty';td.textContent=events.length?'没有符合条件的安全事件':'还没有安全事件，点击「新建事件」创建第一条吧 ♡';tr.append(td);tbody.append(tr);return; }
  for(const e of filtered){
    const tr=document.createElement('tr');
    for(const value of [e.id,e.title,e.severity,e.description??'',displayDate(e.created_at)]){
      const td=document.createElement('td');
      if(value===e.severity){const badge=document.createElement('span');badge.className=`pill ${['high','medium','low'].includes(value)?value:'low'}`;badge.textContent=levels[value]||value;td.append(badge);}else{td.textContent=String(value??'');}
      tr.append(td);
    }
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
  }catch(err){setText('api-state','连接失败');setText('notice',`获取事件失败：${err.message}`);$('event-rows').replaceChildren();const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.className='empty';td.textContent='无法读取事件，请检查后端服务器是否启动';tr.append(td);$('event-rows').append(tr);}
}
$('search').addEventListener('input',render);$('severity').addEventListener('change',render);$('refresh').addEventListener('click',loadEvents);
$('new-btn').addEventListener('click',()=>{$('form-error').textContent='';$('new-dialog').showModal()});
for(const id of ['close-dialog','cancel'])$(id).addEventListener('click',()=>$('new-dialog').close());
$('create-form').addEventListener('submit',async ev=>{
  ev.preventDefault();const form=ev.currentTarget;const save=$('save');const data=Object.fromEntries(new FormData(form).entries());save.disabled=true;$('form-error').textContent='';
  try{const resp=await fetch('/events',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(!resp.ok){const body=await resp.text();throw new Error(`HTTP ${resp.status}: ${body.slice(0,180)}`)}$('new-dialog').close();form.reset();await loadEvents();}
  catch(err){$('form-error').textContent=`保存失败：${err.message}`;}
  finally{save.disabled=false;}
});
loadEvents();
