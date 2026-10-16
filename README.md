# CyberWatch

A beginner-friendly FastAPI security incident tracker with a login-protected
dashboard. Uses fictional incident data only.

**Current version: V0.5.1 —— 账号认证 + 服务端会话 + CSRF + 路由守卫。**

## Requirements

Python 3.11+ (3.12 recommended), Git, VS Code / Cursor.

## 首次启动（Windows PowerShell，完整流程）

V0.5.1 起，应用**不再有匿名访问入口**：必须先建库、再建一个管理员账号，
否则你连 `/dashboard` 都进不去。以下五步按顺序执行即可。

```powershell
# 0) 创建虚拟环境并安装依赖
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 1) 先看一眼将要执行的 SQL（离线，不碰任何数据库文件）
.\.venv\Scripts\python.exe -m alembic upgrade head --sql

# 2) 建库 / 升级结构
.\.venv\Scripts\python.exe -m alembic upgrade head

# 3) 创建第一个管理员（密码从环境变量读，避免落进命令历史）
$env:CYBERWATCH_ADMIN_PASSWORD = "请换成你自己的长口令-2026"
.\.venv\Scripts\python.exe -m app.cli create-admin `
    --username admin `
    --display-name "管理员" `
    --password-env CYBERWATCH_ADMIN_PASSWORD
Remove-Item Env:\CYBERWATCH_ADMIN_PASSWORD   # 用完立刻清除

# 4) 启动服务
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

然后打开 <http://127.0.0.1:8000/login> 用刚才的账号登录。

`create-admin` 的退出码（脚本可判断）：`0` 成功、`1` 业务失败
（用户名已存在 / 口令不合规）、`2` 环境未就绪（数据库缺表，先跑迁移）。
本命令**绝不会覆盖已存在账号的密码** —— 那会变成"拿到机器就能改掉管理员口令"
的后门。

口令策略：至少 12 位、不等于用户名、不在弱口令黑名单里。哈希算法为
**Argon2id**（`argon2-cffi`）。

## 账号与权限（V0.5.1 范围）

V0.5.1 只交付**认证**（谁能进来）与**路由守卫**（每个接口都挂了鉴权）。
完整的三角色权限矩阵（admin / analyst / viewer）按计划在 V0.5.2 落地；
本阶段所有业务接口都要求登录，角色判定已就位但尚未区分。

| 角色 | 计划权限 |
| --- | --- |
| `viewer` | 只读：事件列表 / 详情 / 归档中心 / 时间线 |
| `analyst` | viewer 的全部 + 新建 / 编辑 / 归档 / 恢复事件 |
| `admin` | 全部，含用户管理（V0.5.2 交付 API 与界面） |

## 安全机制（已落地）

- **服务端会话**：Cookie 里放原始令牌，数据库只存 `SHA-256` 摘要；
  令牌被拖库也无法直接冒用。
- **CSRF 双提交 + 服务端比对**：写方法（POST/PUT/PATCH/DELETE）必须带
  `X-CSRF-Token`，且与该会话在服务端存的值常量时间比对。
- **登录失败统一文案**：`用户名或密码错误`；"账号不存在"与"口令错误"
  连耗时都对齐（不存在时照样跑一次 Argon2 校验），防止账号枚举。
- **账号级登录限流**：连续 5 次失败锁定一段时间；
  ⚠️ 这本身可被用来**锁死已知用户名**（拒绝服务风险），
  公开部署前**必须**再加来源级限流与可信代理配置，见
  `docs/V0.5-需求与架构设计.md` §5.3。
- **开放重定向防护**：`/login?next=` 只接受站内相对路径，后端
  (`safe_next_path`) 与前端 (`safeNext`) 各校验一次。
- **已认证页面 `Cache-Control: no-store`**：避免退出后浏览器从缓存里
  把 dashboard 渲染出来。

## 配置项（环境变量）

| 变量 | 取值 | 说明 |
| --- | --- | --- |
| `CYBERWATCH_DATABASE_URL` | SQLAlchemy URL | 覆盖数据库位置（优先级高于默认路径） |
| `CYBERWATCH_ENV` | `development` / `production` | 默认 `development` |
| `CYBERWATCH_COOKIE_SECURE` | `true` / `false` | `production` 下必须为 `true`，否则拒绝启动 |
| `CYBERWATCH_SESSION_TTL_HOURS` | 正整数 | 会话**绝对**有效期 |
| `CYBERWATCH_SESSION_IDLE_MINUTES` | 正整数 | 会话**闲置**超时 |
| `CYBERWATCH_COOKIE_NAME` | 字符串 | 会话 Cookie 名，默认 `cw_session` |
| `CYBERWATCH_DOCS_MODE` | `admin` / `public` / `disabled` | 默认 `admin`（Swagger 仅管理员可见） |
| `CYBERWATCH_ALLOW_PUBLIC_DOCS` | `true` | `production` + `public` 需要它二次确认 |
| `CYBERWATCH_TRUST_PROXY` | `true` / `false` | 是否信任 `X-Forwarded-For` |
| `CYBERWATCH_TRUSTED_PROXY_CIDRS` | 逗号分隔的 CIDR | `TRUST_PROXY=true` 时必填 |

配置非法时应用会**在启动阶段抛出中文异常并拒绝启动**（fail-fast），
不会带病运行。开发环境特有的宽松策略（如公开 Swagger）也只对
**本机隔离环境**成立；生产环境默认管理员可见。

## 数据库迁移（Alembic）

Schema 变更全部由 Alembic 负责，应用自身**只做只读结构检查**。

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head --sql   # 先过目
.\.venv\Scripts\python.exe -m alembic upgrade head         # 再执行
```

已发布迁移：`0001` 基线 → `0002` `event.status` → `0003` `event.deleted_at`
→ `0004` `status_history` → `0005` `app_user` / `user_session`。
`0001`–`0004` 已发布，**不再修改**。

如果数据库已有 `event` 表但没有 `alembic_version`（老 `create_all()` 路径建的库），
先认领基线：`alembic stamp 0001` 再 `upgrade head`。

### 生产库迁移规程（必须照做）

1. **备份**：复制 `cyberwatch.db` 到带时间戳的位置，并记下字节数与 SHA-256；
2. **核对目标路径**：确认命令作用于备份/目标库，而不是别处的同名文件；
3. **迁移**：`alembic upgrade head`；
4. **验证完整性**：行数、`PRAGMA foreign_key_list`、`alembic_version` 全部核对。

本仓库把上述规程固化成一条命令（**只读源库**，全部动作发生在 `%TEMP%` 的副本上）：

```powershell
.\.venv\Scripts\python.exe tools\verify_migration_on_copy.py
.\.venv\Scripts\python.exe tools\verify_migration_on_copy.py --source path\to\other.db --keep
```

脚本会做"备份 → 核对目标 → 迁移 → 完整性核对 → 回退演练 → 确认源库未被改动"
六件事，任何一步不过就退出码 1。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

- `tests/conftest.py` 在 **import app 之前**把数据库重定向到系统临时目录，
  因此测试套件永远不可能碰到真实的 `cyberwatch.db`；
- 测试**不使用 `dependency_overrides` 绕过认证**（只用它把库指向临时库）。
  需要不同身份时用真实的 `POST /auth/login`。这条纪律由
  `tests/test_architecture.py` 静态扫描强制；
- `tests/test_routes_guard.py` 对**每一条**路由做双向核对，并对每条受保护路由
  发真实的匿名请求与"缺 CSRF"的写请求，新接口不可能"忘了加保护"就上线。

### 真实浏览器验收（可选，需要本机装 Chrome）

```powershell
# 另开一个终端启动服务后：
node tools\browser_acceptance.js
```

覆盖登录 / 错误口令 / 登出 / 未登录跳转 / 401 自动跳转 / CSRF / 跨站来源 /
三档视口（390 / 720 / 1440）/ 页面缓存头，输出截图到
`docs/acceptance-v051/`。

## 项目结构

```
app/
  config.py       环境判断、数据库 URL、AuthSettings fail-fast
  database.py     engine 与 get_session（切断 main ↔ auth 循环导入）
  models.py       全部枚举、表模型与请求/响应 schema
  permissions.py  权限矩阵 + 路由策略表（唯一真相来源）
  security.py     口令哈希、令牌、恒时比较、时间工具
  auth.py         会话、CSRF、require() 依赖、登录/登出路由
  cli.py          create-admin（账号引导与救援）
  main.py         业务路由与页面
templates/        dashboard.html / login.html
static/           dashboard.css / dashboard.js / api.js / login.css / login.js
migrations/       Alembic 环境与版本脚本
tools/            迁移演练与浏览器验收脚本
tests/            pytest 用例（含架构与路由守卫）
```

依赖方向严格单向、无环：
`config → database → models → permissions → security → auth → main`（`cli` 并列末层）。
这条由 `tests/test_architecture.py` 用 AST 静态扫描强制。

前端保持 **粉色 Kawaii Pastel Pop** 风格、**纯原生 JS（不引入 React）**，
配色令牌集中在 `static/dashboard.css` 的 `:root`，其它样式文件只继承不重定义。

## Important limitations

- 学习用的本地原型，**公开部署前仍需**：来源级登录限流、可信代理、
  HTTPS + `CYBERWATCH_COOKIE_SECURE=true`、`CYBERWATCH_ENV=production`。
- V0.5.1 只体现"需登录"，角色矩阵（analyst / viewer 的差异化）在 V0.5.2 交付。
- 尚无用户管理界面、无密码重置邮件、无审计导出。
- Schema 变更必须走 Alembic；应用启动只做只读结构检查，缺迁移会拒绝服务。
- 后续里程碑：完整角色矩阵与用户管理、PostgreSQL、Docker、部署。

## Personal learning tasks

1. 新增一个 `/users` 只读接口，观察 `tests/test_routes_guard.py` 是否会
   因为"忘了登记策略"而直接失败。
2. 用 Chrome DevTools 删掉 `cw_csrf` Cookie 后点一次"新建事件"，看请求返回什么。
3. 用自己的话说清"为什么数据库里不存会话令牌原文，只存 SHA-256 摘要"。
4. 试着把 `CYBERWATCH_ENV=production` 而 `CYBERWATCH_COOKIE_SECURE=false`，
   观察应用是拒绝启动还是照常运行。
