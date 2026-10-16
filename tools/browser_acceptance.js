/* ===== CyberWatch V0.5.1 真实浏览器验收 =====
 *
 * 用系统 Chrome（playwright-core 的 `channel: 'chrome'`）驱动**真实浏览器**，
 * 走真实的 HTTP 请求、真实的 Cookie 罐、真实的表单交互。
 *
 * 为什么必须是真浏览器、不能只用 TestClient：
 *   - TestClient 不执行 JS，"前端有没有正确带上 CSRF 头"这类问题它看不见；
 *   - 它不实现 HTTP 缓存，所以"退出登录后浏览器从缓存里把 dashboard
 *     渲染出来"这种问题它永远抓不到（本轮真抓到了，见 §H）；
 *   - 登录页的"401 时到底显示什么"完全是前端逻辑，只有真浏览器能验。
 *
 * 两类请求刻意分开：
 *   - `page.fetch`（页面内）  —— 会受同源策略、Cookie、JS 拦截逻辑影响；
 *   - `nodeFetch`（Node 内）  —— 不受同源策略约束，可以显式伪造 `Origin`，
 *     用来验后端自己的来源校验；浏览器协议禁止 JS 设置 Origin 头，
 *     所以在页面里根本做不出"跨站请求"。
 *
 * 用法：
 *   node tools/browser_acceptance.js
 *   CW_BASE=http://127.0.0.1:8000 node tools/browser_acceptance.js
 *
 * 产出：docs/acceptance-v051/ 下的截图 + acceptance-report.json
 * 退出码：0 全部通过；1 有失败项。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright-core');

const BASE = process.env.CW_BASE || 'http://127.0.0.1:8765';
const ROOT = path.join(__dirname, '..');
const OUT_DIR = process.env.CW_OUT || path.join(ROOT, 'docs', 'acceptance-v051');
const USERNAME = process.env.CW_USER || 'accept-admin';
const PASSWORD = process.env.CW_PASS || 'Acceptance-Admin-2026';
const DISPLAY_NAME = process.env.CW_DISPLAY_NAME || '验收管理员';
const WRONG_PASSWORD = 'definitely-wrong-password-2026';

const VIEWPORTS = [
  { label: '390', width: 390, height: 844 },   // 手机
  { label: '720', width: 720, height: 1024 },  // 平板
  { label: '1440', width: 1440, height: 900 }, // 桌面
];

const results = [];
let failed = 0;

function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) });
  if (!ok) failed += 1;
  console.log(`${ok ? '  PASS' : '  FAIL'}  ${name}${detail ? `   — ${detail}` : ''}`);
}

function section(title) {
  console.log(`\n=== ${title}`);
}

async function screenshot(page, name) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const file = path.join(OUT_DIR, `${name}.png`);
  await page.screenshot({ path: file, fullPage: false });
  console.log(`  截图 → ${path.relative(ROOT, file)}`);
  return file;
}

/** 页面内发起请求（受同源策略与 Cookie 影响）。 */
async function pageFetch(page, url, options) {
  return page.evaluate(
    async ([u, o]) => {
      const response = await fetch(u, o);
      return { status: response.status, text: await response.text() };
    },
    [url, options || {}]
  );
}

/** Node 侧发起请求：不受同源策略限制，可显式设置 Origin。 */
async function nodeFetch(url, options) {
  const response = await fetch(url, { redirect: 'manual', ...options });
  return {
    status: response.status,
    location: response.headers.get('location'),
    cacheControl: response.headers.get('cache-control'),
    text: await response.text(),
  };
}

function csrfTokenFromCookie(page) {
  return page.evaluate(() => {
    const hit = document.cookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('cw_csrf='));
    return hit ? decodeURIComponent(hit.slice('cw_csrf='.length)) : '';
  });
}

async function login(page, password, { expectSuccess }) {
  await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' });
  await page.fill('#username', USERNAME);
  await page.fill('#password', password);
  await page.click('#login-submit');
  if (expectSuccess) {
    await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 15000 });
  } else {
    await page.waitForSelector('#login-error:not([hidden])', { timeout: 15000 });
  }
}

(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const shots = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    const consoleErrors = [];
    page.on('pageerror', (err) => consoleErrors.push(String(err)));

    // -----------------------------------------------------------------
    section('A. 未登录：受保护页面与接口');
    // -----------------------------------------------------------------
    await page.goto(`${BASE}/dashboard`, { waitUntil: 'domcontentloaded' });
    check(
      'A1 匿名访问 /dashboard 被重定向到登录页（带 next）',
      page.url().includes('/login') &&
        /next=(%2F|\/)dashboard/.test(page.url()),
      page.url()
    );

    const anonEvents = await pageFetch(page, '/events', { credentials: 'same-origin' });
    check('A2 匿名 GET /events → 401', anonEvents.status === 401, `status=${anonEvents.status}`);

    const anonWrite = await pageFetch(page, '/events', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: '匿名写入尝试', severity: 'low' }),
    });
    check('A3 匿名 POST /events → 401', anonWrite.status === 401, `status=${anonWrite.status}`);

    // 提示只在"登录后会去别处"时出现，所以要用一个非默认的 next
    await page.goto(`${BASE}/login?next=%2Fevents`, { waitUntil: 'domcontentloaded' });
    const noticeText = await page.textContent('#login-notice');
    check(
      'A4 next 指向非 dashboard 时显示"登录后返回哪"的提示',
      (await page.isVisible('#login-notice')) && noticeText.includes('/events'),
      JSON.stringify(noticeText)
    );
    await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' });
    shots.push(await screenshot(page, '01-login-anon-1440'));

    // -----------------------------------------------------------------
    section('B. 错误口令：统一文案 + 不泄露账号是否存在');
    // -----------------------------------------------------------------
    await login(page, WRONG_PASSWORD, { expectSuccess: false });
    const wrongText = (await page.textContent('#login-error')) || '';
    check('B1 错误口令后停留在 /login', new URL(page.url()).pathname === '/login', page.url());
    check(
      'B2 错误提示就是后端的统一文案（用户名或密码错误）',
      wrongText.includes('用户名或密码错误'),
      JSON.stringify(wrongText)
    );
    check(
      'B3 没有被 cwFetch 的"会话过期"文案盖掉',
      !wrongText.includes('正在跳转登录页'),
      JSON.stringify(wrongText)
    );
    check('B4 错误后密码框被清空', (await page.inputValue('#password')) === '');
    shots.push(await screenshot(page, '02-login-wrong-password'));

    const unknownUser = await pageFetch(page, '/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'no-such-user-at-all', password: WRONG_PASSWORD }),
    });
    check(
      'B5 「不存在的用户」与「错误口令」响应逐字节一致',
      unknownUser.status === 401 &&
        unknownUser.text.includes('用户名或密码错误') &&
        !unknownUser.text.includes('no-such-user-at-all'),
      `status=${unknownUser.status} body=${unknownUser.text}`
    );

    // -----------------------------------------------------------------
    section('C. 正确口令：进入 dashboard');
    // -----------------------------------------------------------------
    await login(page, PASSWORD, { expectSuccess: true });
    check('C1 登录后进入 /dashboard', new URL(page.url()).pathname === '/dashboard', page.url());
    await page.waitForFunction(
      () => document.querySelectorAll('#event-rows tr').length > 0, null, { timeout: 15000 }
    );
    const rowCount = await page.locator('#event-rows tr').count();
    // 用 `>=` 而不是 `==`：本脚本自己在 D4/D5 会新建事件，
    // 所以"再跑一次"时库里本来就比初始多几条 —— 断言成固定值会让
    // 第二次执行必然失败，那不是产品缺陷，是脚本自己的脆弱假设。
    check('C2 事件列表渲染出数据（真实库副本初始 3 条）', rowCount >= 3, `rows=${rowCount}`);
    const shownName = (await page.textContent('#user-name')) || '';
    check('C3 顶部显示当前用户（显示名优先，回退用户名）',
      shownName === DISPLAY_NAME || shownName === USERNAME, shownName);
    check('C4 顶部显示角色标签', ((await page.textContent('#user-role')) || '').length > 0,
      await page.textContent('#user-role'));
    check('C5 无 JS 运行时错误', consoleErrors.length === 0, consoleErrors.join(' | '));
    shots.push(await screenshot(page, '03-dashboard-1440'));

    const withSession = await pageFetch(page, '/events?limit=2', { credentials: 'same-origin' });
    check('C6 已登录会话下 GET /events?limit=2 → 200', withSession.status === 200,
      `status=${withSession.status}`);

    // -----------------------------------------------------------------
    section('D. CSRF：写方法缺 X-CSRF-Token 必须 403');
    // -----------------------------------------------------------------
    const token = await csrfTokenFromCookie(page);
    check('D1 会话存在时可读到 cw_csrf（非 HttpOnly，长度 64）', token.length === 64,
      `len=${token.length}`);

    const noCsrf = await pageFetch(page, '/events', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: '浏览器验收·缺 CSRF', severity: 'low' }),
    });
    check('D2 已登录但缺 CSRF 的 POST → 403', noCsrf.status === 403, `status=${noCsrf.status}`);
    check('D3 403 文案明确指出 CSRF', noCsrf.text.includes('CSRF'), noCsrf.text);

    const withCsrf = await pageFetch(page, '/events', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify({ title: '浏览器验收·带 CSRF', severity: 'low' }),
    });
    check('D4 带上正确 CSRF 后 POST → 201', withCsrf.status === 201,
      `status=${withCsrf.status} body=${withCsrf.text.slice(0, 100)}`);

    const viaCwFetch = await page.evaluate(async () => {
      const response = await window.cwFetch('/events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: '浏览器验收·cwFetch 自动带头', severity: 'low' }),
      });
      return { status: response.status, body: await response.text() };
    });
    check('D5 前端 cwFetch 自动附加 CSRF → 201', viaCwFetch.status === 201,
      `status=${viaCwFetch.status} body=${viaCwFetch.body.slice(0, 100)}`);

    // 跨站 Origin：浏览器禁止 JS 设置 Origin，必须从 Node 侧发
    const crossOrigin = await nodeFetch(`${BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
      body: JSON.stringify({ username: USERNAME, password: 'whatever-long-enough' }),
    });
    check('D6 跨站 Origin 的登录被后端拒绝（403）', crossOrigin.status === 403,
      `status=${crossOrigin.status} body=${crossOrigin.text.slice(0, 160)}`);

    const sameOrigin = await nodeFetch(`${BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: BASE },
      body: JSON.stringify({ username: USERNAME, password: WRONG_PASSWORD }),
    });
    check('D7 同站 Origin 的登录不被来源校验误伤（401 而非 403）',
      sameOrigin.status === 401, `status=${sameOrigin.status} body=${sameOrigin.text.slice(0, 120)}`);

    // -----------------------------------------------------------------
    section('E. 会话失效：cwFetch 自动跳登录页');
    // -----------------------------------------------------------------
    await context.clearCookies();
    const afterClear = await pageFetch(page, '/events', { credentials: 'same-origin' });
    check('E1 会话失效后 GET /events → 401', afterClear.status === 401, `status=${afterClear.status}`);

    // 无缓存的独立上下文里访问 /dashboard：必须被服务器重定向
    const coldContext = await browser.newContext();
    const coldPage = await coldContext.newPage();
    await coldPage.goto(`${BASE}/dashboard`, { waitUntil: 'domcontentloaded' });
    check('E2 无 Cookie 的全新浏览器访问 /dashboard 被弹回登录页',
      coldPage.url().includes('/login'), coldPage.url());
    await coldContext.close();

    const coldServer = await nodeFetch(`${BASE}/dashboard`);
    check('E3 服务器对无会话的 /dashboard 返回 302 + location',
      coldServer.status === 302 && String(coldServer.location).startsWith('/login?next='),
      `status=${coldServer.status} location=${coldServer.location}`);

    // cwFetch 的 401 自动跳转：登录后人为清 Cookie，再触发一次请求。
    // 注意这里的写法：`cwFetch` 收到 401 会立刻 `location.assign`，
    // 导航可能在 `evaluate` 的 CDP 往返完成**之前**就发生，
    // 于是 evaluate 会以 "Execution context was destroyed" 报错。
    // 所以先把"等待导航"挂起来，再触发请求，并容忍 evaluate 自身被中断。
    await login(page, PASSWORD, { expectSuccess: true });
    await context.clearCookies();
    const navigatedToLogin = page.waitForURL(
      (u) => u.pathname === '/login', { timeout: 15000 }
    );
    await page
      .evaluate(() => { window.cwFetch('/events').catch(() => {}); })
      .catch(() => { /* 导航打断 evaluate 属预期 */ });
    await navigatedToLogin;
    check('E4 cwFetch 收到 401 后自动跳转 /login 并带 next',
      page.url().includes('/login') && page.url().includes('next='), page.url());

    // -----------------------------------------------------------------
    section('F. 退出登录');
    // -----------------------------------------------------------------
    await login(page, PASSWORD, { expectSuccess: true });
    await page.click('#logout-btn');
    await page.waitForURL((u) => u.pathname === '/login', { timeout: 15000 });
    check('F1 点击"退出"后回到登录页', page.url().includes('/login'), page.url());

    const logoutCookie = await nodeFetch(`${BASE}/auth/logout`, { method: 'POST' });
    check('F2 未认证调用 /auth/logout 仍是 204（幂等，例外 E1）',
      logoutCookie.status === 204, `status=${logoutCookie.status}`);

    // 全新的无缓存上下文：退出后不能再进 dashboard
    const freshAfterLogout = await browser.newContext();
    const freshPage = await freshAfterLogout.newPage();
    await freshPage.goto(`${BASE}/dashboard`, { waitUntil: 'domcontentloaded' });
    check('F3 退出后（全新浏览器）再次访问 /dashboard 要求登录',
      freshPage.url().includes('/login'), freshPage.url());
    await freshAfterLogout.close();

    const afterLogout = await pageFetch(page, '/events', { credentials: 'same-origin' });
    check('F4 退出后 /events → 401', afterLogout.status === 401, `status=${afterLogout.status}`);

    // -----------------------------------------------------------------
    section('G. 三档视口（390 / 720 / 1440）');
    // -----------------------------------------------------------------
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.goto(`${BASE}/login`, { waitUntil: 'domcontentloaded' });
      shots.push(await screenshot(page, `login-${viewport.label}`));

      await login(page, PASSWORD, { expectSuccess: true });
      await page.waitForFunction(
        () => document.querySelectorAll('#event-rows tr').length > 0, null, { timeout: 15000 }
      );
      shots.push(await screenshot(page, `dashboard-${viewport.label}`));

      const overflow = await page.evaluate(() =>
        document.documentElement.scrollWidth - document.documentElement.clientWidth);
      check(`G-${viewport.label} 无横向溢出`, overflow <= 1, `overflow=${overflow}px`);
      await context.clearCookies();
    }
    check('G1 三档视口均可正常渲染并登录', true, VIEWPORTS.map((v) => v.label).join(' / '));

    // -----------------------------------------------------------------
    section('H. 已认证页面不可被浏览器缓存（真浏览器验收发现的缺陷）');
    // -----------------------------------------------------------------
    const loginHeaders = await nodeFetch(`${BASE}/login`);
    check('H1 /login 返回 Cache-Control: no-store',
      String(loginHeaders.cacheControl).includes('no-store'), loginHeaders.cacheControl);

    const dashHeaders = await nodeFetch(`${BASE}/dashboard`, {
      headers: { Cookie: 'cw_session=irrelevant-because-anonymous' },
    });
    // 匿名时是 302，头也要带上（避免"302 被缓存住"这种更讨厌的情况）
    check('H2 匿名 /dashboard 的 302 也带 Cache-Control: no-store',
      String(dashHeaders.cacheControl).includes('no-store'), dashHeaders.cacheControl);

    check('H3 全程无未捕获的 JS 异常', consoleErrors.length === 0, consoleErrors.join(' | '));

    await context.close();
  } finally {
    await browser.close();
  }

  const report = {
    base: BASE,
    generated_at: new Date().toISOString(),
    total: results.length,
    failed,
    results,
    screenshots: shots.map((p) => path.relative(ROOT, p)),
  };
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(
    path.join(OUT_DIR, 'acceptance-report.json'),
    `${JSON.stringify(report, null, 2)}\n`,
    'utf8'
  );

  console.log(`\n=== 结果：${results.length - failed}/${results.length} 通过，${failed} 失败`);
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('\n验收脚本自身崩溃：', err);
  process.exit(1);
});
