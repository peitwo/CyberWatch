/* ===== V0.5.1 共享请求封装（dashboard.js 与 login.js 共用） =====
 *
 * 只做三件事，刻意不做更多（避免变成"看不见的框架"）：
 *
 *   1. 写方法自动带上 `X-CSRF-Token`（值取自非 HttpOnly 的 cw_csrf Cookie）；
 *   2. `credentials: 'same-origin'` —— 会话靠 Cookie，必须允许同源携带；
 *   3. **401 统一跳登录页**（带 next），403 交给调用方提示"权限不足"。
 *
 * 为什么需要它：V0.4.2 的 dashboard.js 直接调 `fetch`，一旦后端启用认证，
 * 会话过期时页面只会显示一句"加载失败"，用户完全不知道该去登录。
 * 把"401 → 跳登录"收敛到一个地方，就不会有某个请求漏掉这条分支。
 *
 * 唯一的例外是 `skipAuthRedirect: true`：登录接口自己的 401 意思是
 * "口令不对"，不是"会话过期"。真浏览器验收抓到过这个坑 —— 不加这个开关，
 * 登录页会把后端的「用户名或密码错误」盖成「正在跳转登录页」，
 * 既误导用户，也把后端刻意统一的防枚举文案白白浪费掉。
 *
 * 注意：本文件**不持有任何权限判断**。前端隐藏按钮只是体验优化，
 * 真正的闸门在 FastAPI 的 require() 依赖里（见设计文档 §4.4）。
 */
(function () {
  'use strict';

  var CSRF_COOKIE = 'cw_csrf';
  var CSRF_HEADER = 'X-CSRF-Token';
  var LOGIN_PATH = '/login';
  var WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

  function readCookie(name) {
    var target = name + '=';
    var parts = String(document.cookie || '').split(';');
    for (var i = 0; i < parts.length; i += 1) {
      var item = parts[i].trim();
      if (item.indexOf(target) === 0) return decodeURIComponent(item.slice(target.length));
    }
    return '';
  }

  function currentPath() {
    return window.location.pathname + window.location.search;
  }

  var redirecting = false;

  function redirectToLogin() {
    if (redirecting) return;                       /* 多个请求同时 401 时只跳一次 */
    if (window.location.pathname === LOGIN_PATH) return;
    redirecting = true;
    window.location.assign(LOGIN_PATH + '?next=' + encodeURIComponent(currentPath()));
  }

  function cwFetch(url, options) {
    var opts = options || {};
    var method = String(opts.method || 'GET').toUpperCase();
    var headers = {};
    /* 复制调用方给的 headers（Options 对象不能直接展开赋值到原生 headers） */
    if (opts.headers) {
      Object.keys(opts.headers).forEach(function (key) { headers[key] = opts.headers[key]; });
    }
    if (WRITE_METHODS.indexOf(method) !== -1) {
      var token = readCookie(CSRF_COOKIE);
      if (token) headers[CSRF_HEADER] = token;
    }
    return window.fetch(url, {
      method: method,
      headers: headers,
      body: opts.body,
      cache: 'no-store',
      credentials: 'same-origin'
    }).then(function (response) {
      /* skipAuthRedirect：调用方自己处理 401（登录接口专用），
         此时把响应原样交回去，不跳转、不抛错。 */
      if (response.status === 401 && !opts.skipAuthRedirect) {
        redirectToLogin();
        throw new Error('未登录或会话已过期，正在跳转登录页');
      }
      return response;
    });
  }

  window.cwFetch = cwFetch;
  window.cwAuth = { readCookie: readCookie, redirectToLogin: redirectToLogin };
})();
