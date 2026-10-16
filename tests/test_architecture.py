"""架构与纪律守卫（评审意见 R1-1，以及批复里的开发纪律）。

这些测试不看业务行为，只看**结构**。它们要拦住的是一类特殊的退化：
功能测试全绿、但代码的骨架已经悄悄烂掉了 ——

1. :func:`test_import_graph_has_no_cycles`
   —— 模块依赖图必须无环。V0.5 之前 `main.py` 与 `auth.py` 互相 import
   的隐患就是靠"还没人踩到"侥幸没炸；现在用 AST 静态扫描把它钉死。
2. :func:`test_import_direction_follows_declared_layers`
   —— 依赖只能**自上而下**，不允许出现反向边（那正是环的前身）。
3. :func:`test_table_models_are_declared_only_in_models_module`
   —— 表模型只能声明在 `app/models.py`（R1-1 修订事项 1）。
4. :func:`test_utcnow_has_exactly_one_definition`
   —— "现在几点"只能有一个答案。
5. :func:`test_every_permission_route_carries_a_real_guard_dependency`
   —— 策略表说"要权限"，路由上就必须真的挂着守卫依赖
   （不能只在表里写、忘了挂 `Depends`）。
6. :func:`test_tests_never_override_auth_dependencies`
   —— 纪律：**不使用 `dependency_overrides` 绕过认证**。
7. :func:`test_frontend_stays_react_free_and_pastel`
   —— 纪律：不引入 React、保留 Kawaii Pastel Pop 配色。
8. :func:`test_login_and_dashboard_share_the_same_mascot_markup` /
   :func:`test_login_page_only_positions_the_shared_mascot` /
   :func:`test_art_pixel_positions_are_scoped_to_a_layout`
   —— 吉祥物是**两页共用的一个组件**：DOM 必须逐字节一致，页面只准写定位、
   不准重定义组件内部属性，且页面专属的像素坐标必须带作用域前缀。

全部为只读静态检查，不启动服务、不连接数据库。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from app.config import BASE_DIR

APP_DIR = BASE_DIR / "app"
TESTS_DIR = BASE_DIR / "tests"

#: 声明的分层顺序（左 → 右 = 低 → 高）。依赖只允许指向**更左**的层。
#: `permissions` 与 `security` 互不依赖，二者之间的相对次序不影响判定。
LAYERS: tuple[str, ...] = (
    "config",
    "database",
    "models",
    "permissions",
    "security",
    "auth",
    "main",
    "cli",
)

#: 认可的"认证/权限守卫"依赖名（FastAPI 把依赖函数记在
#: `route.dependant.dependencies[*].call.__qualname__`）。
GUARD_DEPENDENCIES = frozenset(
    {
        "require.<locals>.dependency",
        "require_html_session.<locals>.dependency",
        "require_role.<locals>.dependency",
        "get_current_user",
        "resolve_auth_context",
    }
)

#: 允许出现在测试里的 `dependency_overrides[...]` 键。**只有** session 提供者。
ALLOWED_OVERRIDE_KEYS = frozenset({"get_session"})

#: 一旦被覆盖就等于"绕过认证"的依赖名。只要键里出现其中之一，一律判违规。
FORBIDDEN_OVERRIDE_MARKERS = (
    "require",
    "require_role",
    "require_html_session",
    "get_current_user",
    "resolve_auth_context",
    "has_permission",
    "authenticate",
)


# ---------------------------------------------------------------------------
# AST 工具
# ---------------------------------------------------------------------------
def app_modules() -> list[Path]:
    return sorted(p for p in APP_DIR.glob("*.py") if p.name != "__init__.py")


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported_app_modules(path: Path) -> set[str]:
    """`app/foo.py` 直接依赖了哪些同包模块（只看 `app.*`，标准库/三方库忽略）。

    **函数体内的局部导入也算**：`import` 写在函数里能躲开"导入期"的环，
    但躲不开"这是不是一条设计上不该存在的依赖"这个问题。
    """
    names: set[str] = set()
    for node in ast.walk(parse(path)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if parts[0] == "app" and len(parts) > 1:
                    names.add(parts[1])
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:  # 相对导入：from .models import ...
                if node.module:
                    names.add(node.module.split(".")[0])
            elif node.module and node.module.split(".")[0] == "app":
                parts = node.module.split(".")
                if len(parts) > 1:
                    names.add(parts[1])
                else:  # from app import auth, main
                    names.update(alias.name for alias in node.names)
    return {name for name in names if name in LAYERS}


def build_import_graph() -> dict[str, set[str]]:
    graph = {path.stem: imported_app_modules(path) for path in app_modules()}
    return {module: deps - {module} for module, deps in graph.items()}


def import_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1) 依赖图无环
# ---------------------------------------------------------------------------
def test_import_graph_is_acyclic():
    """设计文档 §0.5 R1-1 点名要求的测试，函数名与文档保持一致以便逐条对照。"""
    graph = build_import_graph()

    visited: dict[str, int] = {}   # 0=未访问 1=在栈上 2=已完成
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        state = visited.get(node, 0)
        if state == 2:
            return
        if state == 1:
            start = stack.index(node)
            cycles.append(stack[start:] + [node])
            return
        visited[node] = 1
        stack.append(node)
        for dep in sorted(graph.get(node, ())):
            if dep in graph:
                visit(dep)
        stack.pop()
        visited[node] = 2

    for module in sorted(graph):
        visit(module)

    assert not cycles, "模块依赖图出现环（会导致启动期 ImportError 且难以排查）：\n" + "\n".join(
        " → ".join(cycle) for cycle in cycles
    )


def test_import_direction_follows_declared_layers():
    """禁止反向边：高层的模块不允许被低层 import。

    环是"反向边"的极端形式；只查环会漏掉"暂时只有一条反向边、
    还没绕回来"的中间状态 —— 那种状态最难修，也最容易在下次改动时成环。
    """
    index = {name: position for position, name in enumerate(LAYERS)}
    violations: list[str] = []
    for module, deps in sorted(build_import_graph().items()):
        if module not in index:
            continue
        for dep in sorted(deps):
            if dep not in index:
                continue
            if index[dep] > index[module]:
                violations.append(f"{module} → {dep}（{dep} 的层级更高）")
    assert not violations, "依赖方向违反 §2.0 分层：\n  " + "\n  ".join(violations)


def test_declared_layers_match_reality():
    """`LAYERS` 不能漏登记模块 —— 否则上面的方向检查会出现"检查不到"的盲区。"""
    declared = set(LAYERS)
    actual = {path.stem for path in app_modules()}
    assert actual <= declared, f"这些模块没登记进 LAYERS，不会被方向检查覆盖：{actual - declared}"
    assert declared - actual == set(), f"LAYERS 里有不存在的模块：{declared - actual}"


# ---------------------------------------------------------------------------
# 2) 表模型只能声明在 models.py
# ---------------------------------------------------------------------------
def table_model_classes(path: Path) -> list[str]:
    """找出 `class X(SQLModel, table=True)` 这类真正的**表**模型。"""
    found: list[str] = []
    for node in ast.walk(parse(path)):
        if not isinstance(node, ast.ClassDef):
            continue
        for keyword in node.keywords:
            if (
                keyword.arg == "table"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                found.append(node.name)
    return found


def test_table_models_are_declared_only_in_models_module():
    """R1-1：表模型只能有一处定义。

    V0.5 设计稿初版把 `User` / `UserSession` 放在 `app/auth.py`，
    同时又计划在 `main.py` 里 re-export —— 那样会立刻产生
    `main → auth → main` 的环。修订后统一到 `models.py`，
    这条测试负责防止它悄悄回退。
    """
    owners: dict[str, list[str]] = {}
    for path in app_modules():
        for name in table_model_classes(path):
            owners.setdefault(name, []).append(path.name)

    assert owners, "一个表模型都没找到，说明 AST 检查本身失效了（假绿）"

    wrong = {name: files for name, files in owners.items() if files != ["models.py"]}
    assert not wrong, f"表模型必须且只能声明在 app/models.py，实际：{wrong}"

    expected = {"Event", "StatusHistory", "User", "UserSession"}
    assert set(owners) == expected, f"表模型集合与预期不符：{sorted(owners)}"


def test_main_module_does_not_redefine_models():
    """`main.py` 只做兼容性 re-export，不允许出现 `X = SQLModel(...)` 式的复数定义。"""
    source = import_text(APP_DIR / "main.py")
    for name in ("Event", "StatusHistory", "User", "UserSession"):
        assert not re.search(rf"^class\s+{name}\b", source, re.MULTILINE), (
            f"app/main.py 里出现了 class {name} —— 表模型只能定义在 models.py"
        )
        assert re.search(rf"^\s*{name},\s*$", source, re.MULTILINE), (
            f"app/main.py 应继续 re-export {name}（V0.4 及其它模块依赖它）"
        )


# ---------------------------------------------------------------------------
# 3) 时间是单一真相
# ---------------------------------------------------------------------------
def test_utcnow_has_exactly_one_definition():
    definitions: list[str] = []
    for path in app_modules():
        for node in ast.walk(parse(path)):
            if isinstance(node, ast.FunctionDef) and node.name == "utcnow":
                definitions.append(path.name)

    assert definitions == ["models.py"], (
        f"utcnow 只能有一处定义（应为 models.py），实际：{definitions}；"
        "其它模块请 `from app.models import utcnow` 重新导出"
    )

    from app.models import utcnow as models_utcnow
    from app.security import utcnow as security_utcnow

    assert security_utcnow is models_utcnow, (
        "app.security.utcnow 必须是 app.models.utcnow 的同一个对象；"
        "若是两份实现，monkeypatch 时间注入会失效一半"
    )


def test_security_module_has_no_orphan_helpers():
    """`app/security.py` 是纯函数层：每个公开名字都应当**真的被用到**。

    为什么单挑这个模块查死代码：它的导出是"能力清单"。留一个没人调用的
    辅助函数，读代码的人会以为某条安全链路在用另一套实现，
    而实际上真正的逻辑写在别处（V0.5.1 就出现过：`seconds_since` 没被复用，
    `app/auth.py` 自己又写了一遍 `(now - last_seen).total_seconds()`）。
    两份相对时间运算比一份更容易在边界条件上分叉。

    统计口径：名字在 `app/` + `tests/` + `tools/` 里出现 ≥ 2 次
    （1 次是定义本身，其余为引用）。宁可宽松一点，也不制造误报。
    """
    tree = parse(APP_DIR / "security.py")
    names: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    names.append(target.id)

    assert names, "security.py 里一个公开名字都没解析出来，说明 AST 检查失效了"

    sources = []
    for base in (APP_DIR, TESTS_DIR, BASE_DIR / "tools"):
        for path in sorted(base.rglob("*")):
            if path.suffix in {".py", ".js"}:
                sources.append(path.read_text(encoding="utf-8"))
    corpus = "\n".join(sources)

    orphans = [name for name in names if corpus.count(name) < 2]
    assert not orphans, (
        f"app/security.py 里这些公开名字没人调用（疑似死代码）：{orphans}"
    )


# ---------------------------------------------------------------------------
# 4) 策略说了要权限，路由上就必须真的挂着守卫
# ---------------------------------------------------------------------------
def _route_objects():
    from app.main import app

    collected = []

    def walk(routes) -> None:
        for route in routes:
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(getattr(inner, "routes", []))
                continue
            collected.append(route)

    walk(app.routes)
    return collected


def _guard_names(route) -> list[str]:
    dependant = getattr(route, "dependant", None)
    names: list[str] = []
    for dependency in getattr(dependant, "dependencies", None) or []:
        call = getattr(dependency, "call", None)
        names.append(getattr(call, "__qualname__", repr(call)))
    return names


def test_every_permission_route_carries_a_real_guard_dependency():
    """`ROUTE_POLICY` 是"应该怎样"，路由对象是"实际怎样"。两者必须一致。

    与 `test_routes_guard.py` 的匿名请求测试是**互补**关系：
    那条测试证明"行为上确实拦住了"，这条证明"拦住是靠守卫依赖实现的"。
    只看行为的话，"把 `get_session` 当成守卫"这类错误写法也能骗过断言。
    """
    from app.permissions import Permission, policy_for

    missing: list[str] = []
    checked = 0
    for route in _route_objects():
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if not path or not methods:
            continue
        for method in methods:
            entry = policy_for(method, path)
            if not isinstance(entry, Permission):
                continue
            checked += 1
            if not (set(_guard_names(route)) & GUARD_DEPENDENCIES):
                missing.append(f"{method.upper()} {path} → {_guard_names(route)}")

    assert checked >= 9, f"只检查了 {checked} 条需权限路由，覆盖不足（疑似策略表被清空）"
    assert not missing, (
        "以下路由在策略表里声明的权限，但路由上没有挂任何守卫依赖：\n  "
        + "\n  ".join(missing)
    )


def test_session_provider_alone_is_not_a_guard():
    """反向确认：守卫名单里**不能**包含 `get_session`。

    否则"只看有没有依赖"的检查会被 `dependencies=[Depends(get_session)]` 骗过 ——
    那只是把数据库接进来，跟"谁可以访问"毫无关系。
    """
    assert "get_session" not in GUARD_DEPENDENCIES

    from app.main import app

    tokens = dict(app.dependency_overrides)
    assert tokens == {}, "本测试要求没有任何全局 dependency_overrides 残留"


# ---------------------------------------------------------------------------
# 5) 纪律：测试不得绕过认证
# ---------------------------------------------------------------------------
def test_tests_never_override_auth_dependencies():
    """批复纪律原文：**不使用 `dependency_overrides` 绕过认证**制造测试通过的假象。

    本测试扫描全部测试源码（包括它自己），只允许覆盖 `get_session`
    （把库指向临时库）。任何对守卫依赖的覆盖 —— 即使当时"看起来更方便" ——
    都会被这里拦下。

    判定规则刻意**只匹配真实的下标键**，不匹配注释、docstring 里的举例：
    键里出现守卫函数名 → 违规；键是一个裸标识符且不是 `get_session` → 也违规
    （未知的裸标识符需要人来确认，宁可让人多看一眼）。
    """
    pattern = re.compile(r"dependency_overrides\[([^\]\n]*)\]")
    bare_identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    violations: list[str] = []

    for path in sorted(TESTS_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in pattern.finditer(source):
            key = match.group(1).strip()
            if key in ALLOWED_OVERRIDE_KEYS:
                continue
            marker_hit = any(name in key for name in FORBIDDEN_OVERRIDE_MARKERS)
            unknown_bare = bool(bare_identifier.match(key)) and not key.endswith("session")
            if marker_hit or unknown_bare:
                line = source[: match.start()].count("\n") + 1
                violations.append(f"{path.name}:{line} 覆盖了 {key!r}")

    assert not violations, (
        "测试里出现了对非 session 依赖的覆盖（等于绕过认证，测试结果不可信）：\n  "
        + "\n  ".join(violations)
        + "\n需要不同身份时请用 conftest 的 make_client()，它走真实 POST /auth/login。"
    )


def test_conftest_redirects_database_before_importing_app():
    """`tests/conftest.py` 最重要的安全不变式：**先改环境变量，再 import app**。

    `app.database` 在 import 时就把 `CYBERWATCH_DATABASE_URL` 读成了模块常量，
    顺序一旦颠倒，测试进程里的 `engine` 就会指向真实 ``cyberwatch.db``，
    而所有断言依然会通过 —— 这正是最危险的一类失败。

    conftest 的 docstring 里写着这条承诺，但注释是没法被测试的；
    这里用 AST 取**代码行号**（不能拿字符串搜索：docstring 里就引用了
    `from app.main import ...` 这句话，按文本位置比较会得到错误的结论）。
    """
    tree = parse(TESTS_DIR / "conftest.py")

    env_lines: list[int] = []
    temp_root_lines: list[int] = []
    app_import_lines: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] == "app":
                app_import_lines.append(node.lineno)
            continue
        if not isinstance(node, ast.Assign):
            continue
        target_text = ast.unparse(node)
        # `ast.unparse` 统一用单引号，所以按"包含子串"判断，不写死引号形式
        if "os.environ" in target_text and "CYBERWATCH_DATABASE_URL" in target_text:
            env_lines.append(node.lineno)
        if "tempfile.mkdtemp" in ast.unparse(node.value):
            temp_root_lines.append(node.lineno)

    assert env_lines, "conftest.py 里找不到 CYBERWATCH_DATABASE_URL 的赋值"
    assert app_import_lines, "conftest.py 里找不到任何 app.* 导入"

    first_env = min(env_lines)
    first_app_import = min(app_import_lines)
    assert first_env < first_app_import, (
        f"conftest.py 第 {first_env} 行才设置 CYBERWATCH_DATABASE_URL，"
        f"但第 {first_app_import} 行就已经 import 了 app —— 测试可能会连到真实数据库"
    )

    # 临时目录必须在同一段顺序里更早创建（env 变量引用它）
    assert temp_root_lines and min(temp_root_lines) < first_env, (
        "CYBERWATCH_DATABASE_URL 必须指向 tempfile.mkdtemp() 出来的目录"
    )

    # 允许清单本身不能被顺手放宽
    assert ALLOWED_OVERRIDE_KEYS == {"get_session"}


# ---------------------------------------------------------------------------
# 6) 纪律：前端不引入 React、保留 Kawaii Pastel Pop
# ---------------------------------------------------------------------------
PASTEL_PALETTE = {
    "--pink": "#ffd1dc",
    "--rose": "#f9a9c7",
    "--purple": "#8365a6",
    "--background": "#fff8fc",
}


def test_frontend_stays_react_free():
    """批复纪律：**不引入 React**（纯原生 JS）。"""
    offenders: list[str] = []
    for path in sorted((BASE_DIR / "static").glob("*.js")) + sorted(
        (BASE_DIR / "templates").glob("*.html")
    ):
        lowered = path.read_text(encoding="utf-8").lower()
        for token in ("react", "react-dom", "jsx", "vue", "angular"):
            if token in lowered:
                offenders.append(f"{path.name} 含 {token!r}")
    assert not offenders, f"前端不得引入框架（本阶段要求纯原生 JS）：{offenders}"

    assert not (BASE_DIR / "package.json").exists(), (
        "项目根出现了 package.json —— V0.5.1 不需要前端构建链"
    )


def test_dashboard_keeps_kawaii_pastel_palette():
    """批复纪律：**保留 Kawaii Pastel Pop 风格**。

    直接把设计令牌钉死。若有人"顺手换个主题"，这条会立刻红 ——
    风格是用户明确要求保留的东西，不该在一次安全改造里被改掉。
    """
    css = (BASE_DIR / "static" / "dashboard.css").read_text(encoding="utf-8")
    compact = css.replace(" ", "")
    for token, value in PASTEL_PALETTE.items():
        assert f"{token}:{value}" in compact, (
            f"dashboard.css 的 {token} 不再是 {value}（Kawaii Pastel Pop 被改动了）"
        )

    # 新增页面（登录页）必须**复用**这套令牌，而不是另起一套配色 ——
    # 两份调色板各自进化，是"风格漂移"最常见的原因。
    login_css = (BASE_DIR / "static" / "login.css").read_text(encoding="utf-8")
    login_compact = login_css.replace(" ", "")
    assert "var(--background)" in login_compact, "登录页没有复用 dashboard.css 的调色板变量"
    for token in PASTEL_PALETTE:
        assert f"{token}:" not in login_compact, (
            f"login.css 重新定义了 {token} —— 应该直接继承 dashboard.css 的 :root"
        )

    # 继承链必须是"先 dashboard.css、后 login.css"，否则变量取不到
    login_html = (BASE_DIR / "templates" / "login.html").read_text(encoding="utf-8")
    assert login_html.index("/static/dashboard.css") < login_html.index("/static/login.css")


def test_login_request_opts_out_of_the_shared_401_redirect():
    """登录请求必须带 ``skipAuthRedirect``。

    前端只用字符串断言是无奈之举（本项目不引入 JS 测试框架，见纪律"不引入 React"
    背后的同一取向：保持零构建链）。但这条不变式值得钉住：

    共享封装 `cwFetch` 会把**任何** 401 翻译成"会话过期，正在跳转登录页"。
    登录接口的 401 含义是"口令不对"，如果不用 `skipAuthRedirect` 关掉这条分支，
    登录页就会把后端统一的「用户名或密码错误」盖成「正在跳转登录页」——
    这既是误导用户，也把后端刻意设计的防账号枚举文案白白浪费掉。

    真浏览器验收抓到过这个缺陷（docs/acceptance-v051），
    在 pytest 里再钉一次以防回退。
    """
    api_js = (BASE_DIR / "static" / "api.js").read_text(encoding="utf-8")
    login_js = (BASE_DIR / "static" / "login.js").read_text(encoding="utf-8")

    assert "opts.skipAuthRedirect" in api_js, "api.js 不再支持 skipAuthRedirect 开关"
    assert "skipAuthRedirect: true" in login_js, "登录请求漏掉了 skipAuthRedirect"


@pytest.mark.parametrize("name", ["dashboard.html", "login.html"])
def test_templates_load_static_assets(name):
    """模板必须通过 /static/ 引用资源（而不是内联大段 JS/CSS）。"""
    html = (BASE_DIR / "templates" / name).read_text(encoding="utf-8")
    assert "/static/" in html, f"{name} 没有引用 /static/ 资源"


# ---------------------------------------------------------------------------
# 7) 吉祥物：两页共用**一个**组件，页面只负责摆位
# ---------------------------------------------------------------------------
#: 白脸与表情的"长相"由 dashboard.css 的全局规则提供；这里列出**允许**
#: 出现在 .login-art .mascot 规则里的属性 —— 只有定位。
ALLOWED_LOGIN_MASCOT_PROPERTIES = frozenset({"position", "left", "top", "transform"})

#: 这些类名的像素坐标只在各自版式里有意义，**必须**带作用域前缀
#: （`.hero-art .orb` / `.login-art .orb`），不能以裸类名出现在全局。
PAGE_SCOPED_ART_CLASSES = (".orb", ".one", ".two", ".three")

MASCOT_MARKUP = re.compile(r'<div class="mascot">.*?</div>')


def css_rules(css: str) -> list[tuple[str, str]]:
    """把 CSS 拆成 (选择器, 规则体) 列表。

    `@media` 这类条件块整体不匹配（它的体内含 `{`），但其**内部**的规则会
    被单独取出 —— 这正是我们要检查的对象。
    """
    cleaned = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", cleaned)]


def declared_properties(body: str) -> set[str]:
    return {piece.split(":")[0].strip() for piece in body.split(";") if ":" in piece}


def mascot_markup(html: str) -> str:
    match = MASCOT_MARKUP.search(html)
    assert match, '模板里找不到 <div class="mascot">'
    return match.group(0)


def test_login_and_dashboard_share_the_same_mascot_markup():
    """两页的吉祥物 DOM 必须**逐字节相同**。

    表情走样最省事的"修法"是就地把某个 span 挪一挪、字号调一调 ——
    那样两个页面就会各自漂移，"风格统一"只能靠人去盯。
    钉成同一段标记之后，改一边不改另一边会立刻红。

    V0.5.1 的错位就源于此：登录页的两个 span 连 `ears`/`eyes` 类名都没有，
    于是拿不到共享排版（29px/24px、无 letter-spacing），
    表情被撑到 126px 宽，在白脸（95px）里被迫折行，尾字符掉到脸外 14px。
    """
    dashboard_html = (BASE_DIR / "templates" / "dashboard.html").read_text(encoding="utf-8")
    login_html = (BASE_DIR / "templates" / "login.html").read_text(encoding="utf-8")
    dashboard_mascot = mascot_markup(dashboard_html)
    login_mascot = mascot_markup(login_html)

    assert dashboard_mascot == login_mascot, (
        "登录页与 Dashboard 的吉祥物标记不一致：\n"
        f"  dashboard.html: {dashboard_mascot}\n"
        f"  login.html:     {login_mascot}\n"
        "两页共用同一个组件，请直接复用同一段标记（含 ears/eyes 类名）。"
    )

    # 类名是共享排版的**唯一入口**，缺了就退化成浏览器默认字号
    assert 'class="ears"' in dashboard_mascot, "吉祥物的眼睛行丢了 ears 类名"
    assert 'class="eyes"' in dashboard_mascot, "吉祥物的嘴巴/腮红行丢了 eyes 类名"
    assert 'class="mascot"' in dashboard_mascot


def test_login_page_only_positions_the_shared_mascot():
    """登录页只准写"摆在哪"，不准重定义白脸几何/字体/配色。

    这条是 V0.5.1 那个缺陷的直接防线。旧写法里 `.login-art .mascot`
    声明了 display/font-size/letter-spacing/color 却**漏了 left/top**，
    结果 dashboard 里为 230×160 hero-art 写死的 `left:80px;top:47px`
    原样泄漏到登录页：脸心偏离球心 33.5px，看起来就是"表情错位"。
    CSS 是"部分覆盖"语义 —— 少写一个属性，就等于把别人的值继承过来。
    """
    login_css = (BASE_DIR / "static" / "login.css").read_text(encoding="utf-8")
    rules = [body for selector, body in css_rules(login_css) if selector == ".login-art .mascot"]
    assert rules, "login.css 里找不到 .login-art .mascot 规则（检查本身失效了）"

    body = rules[0]
    properties = declared_properties(body)
    extra = properties - ALLOWED_LOGIN_MASCOT_PROPERTIES
    assert not extra, (
        f".login-art .mascot 多声明了 {sorted(extra)} —— 这些属于共享组件（dashboard.css），"
        "重复声明会与共享组件打架（少写一个属性就等于继承别人的值）。"
        f"本规则只允许 {sorted(ALLOWED_LOGIN_MASCOT_PROPERTIES)}。"
    )

    compact = body.replace(" ", "").replace("\n", "")
    assert "position:absolute" in compact, "吉祥物必须绝对定位才能叠在 orb 上"
    assert "left:50%" in compact and "top:50%" in compact, (
        "吉祥物必须以 50%/50% 居中，否则会退回 dashboard 的 left:80px/top:47px"
    )
    assert "translate(-50%,-50%)" in compact, "50%/50% 必须配 translate(-50%,-50%) 才是真正居中"


def test_art_pixel_positions_are_scoped_to_a_layout():
    """页面专属的像素坐标必须带作用域前缀，不能以裸类名出现在全局。

    `.orb{inset:7px 20px}` / `.one{top:6px;right:5px}` 这类值是照着
    Dashboard 的 230×160 hero-art 量的。它们一旦留在全局，新页面
    （登录页）复用同一个类名时就会**静止地**继承别人的坐标 ——
    而这类错误在代码评审里几乎看不出来，只能靠实测量的几何发现。
    """
    css = (BASE_DIR / "static" / "dashboard.css").read_text(encoding="utf-8")
    rules = css_rules(css)
    assert rules, "dashboard.css 规则解析失败（检查本身失效了）"

    violations: list[str] = []
    for selector, body in rules:
        properties = declared_properties(body)
        for part in (piece.strip() for piece in selector.split(",")):
            if not part:
                continue
            for target in PAGE_SCOPED_ART_CLASSES:
                if part.endswith(target) and " " not in part:
                    violations.append(f"裸选择器 `{part}` 声明了 {sorted(properties)}")

    assert not violations, (
        "以下规则缺少作用域前缀，会把坐标泄漏给别的页面：\n  "
        + "\n  ".join(violations)
        + "\n请写成 `.hero-art .orb` / `.login-art .spark.one` 这种带前缀的形式。"
    )


def test_mascot_face_geometry_is_declared_exactly_once():
    """白脸的长相（95×83 白底圆角）只能有一处定义，而且必须是全局的。

    与 :func:`test_login_page_only_positions_the_shared_mascot` 互补：
    那条防止登录页**加**声明，这条防止两边都声明（"共享"退化成"各写一份"）。
    """
    css = (BASE_DIR / "static" / "dashboard.css").read_text(encoding="utf-8")
    owners = [
        (selector, body)
        for selector, body in css_rules(css)
        if selector.endswith(".mascot") and " " not in selector
    ]
    assert len(owners) == 1, f"全局 .mascot 规则应当只有 1 条，实际 {len(owners)} 条"

    _selector, body = owners[0]
    properties = declared_properties(body)
    for required in ("width", "height", "background", "border-radius"):
        assert required in properties, (
            f"全局 .mascot 少了 {required} —— 白脸的长相必须在共享组件里定义完整"
        )

    # 定位不属于"长相"，不能混进这条全局规则
    assert "left" not in properties and "top" not in properties and "inset" not in properties, (
        "全局 .mascot 里出现了坐标（left/top/inset）；坐标属于各版式，请收进 .hero-art/.login-art"
    )

    login_css = (BASE_DIR / "static" / "login.css").read_text(encoding="utf-8")
    assert ".login-art .orb" in login_css, "登录页的圆球必须有自己作用域下的定义"
    assert ".login-art .mascot" in login_css
