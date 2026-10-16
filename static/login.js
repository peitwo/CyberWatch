/* ===== V0.5.1 登录页行为 =====
 * 失败一律用 textContent 渲染（后端返回的 detail 不进 innerHTML）；
 * 成功后只允许跳转到**站内相对路径**（开放重定向防护的第二道，
 * 第一道在后端 app/auth.py::safe_next_path）。
 */
(function () {
  'use strict';

  var form = document.getElementById('login-form');
  var errorBox = document.getElementById('login-error');
  var noticeBox = document.getElementById('login-notice');
  var submit = document.getElementById('login-submit');
  var usernameInput = document.getElementById('username');
  var passwordInput = document.getElementById('password');

  /* 只接受以单个 / 开头的站内路径：拒绝 //evil.com、http://…、/a\b 这类值 */
  function safeNext(raw) {
    if (!raw) return '/dashboard';
    var value = String(raw).trim();
    if (value.charAt(0) !== '/' || value.indexOf('//') === 0) return '/dashboard';
    if (value.indexOf('\\') !== -1 || value.indexOf(':') !== -1) return '/dashboard';
    return value;
  }

  function nextTarget() {
    var params = new URLSearchParams(window.location.search);
    return safeNext(params.get('next'));
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  function clearError() {
    errorBox.textContent = '';
    errorBox.hidden = true;
  }

  /* 从 /login?next=... 回填一句提示，让用户知道"登录后会回到哪" */
  (function initNotice() {
    var target = nextTarget();
    if (target !== '/dashboard') {
      noticeBox.textContent = '登录成功后将返回：' + target;
      noticeBox.hidden = false;
    }
    usernameInput.focus();
  })();

  async function readDetail(response) {
    try {
      var body = await response.json();
      var detail = body && body.detail;
      if (Array.isArray(detail)) {
        return detail.map(function (item) { return (item && item.msg) || JSON.stringify(item); }).join('；');
      }
      return detail ? String(detail) : '';
    } catch (err) {
      return '';
    }
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    clearError();

    var username = usernameInput.value.trim();
    var password = passwordInput.value;
    if (!username || !password) {
      showError('请输入用户名与密码');
      return;
    }

    submit.disabled = true;
    submit.textContent = '登录中…';
    try {
      var response = await window.cwFetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password }),
        /* 登录接口的 401 = 「口令不对」，不是「会话过期」。
           必须关掉共享封装的 401 自动跳转，否则它会用
           「正在跳转登录页」盖掉后端统一的「用户名或密码错误」——
           那正是防账号枚举的关键文案。 */
        skipAuthRedirect: true
      });
      if (!response.ok) {
        var detail = await readDetail(response);
        if (response.status === 401) {
          /* 后端对"用户不存在"与"密码错误"返回完全相同的文案，前端不再加工 */
          showError(detail || '用户名或密码错误');
        } else if (response.status === 403) {
          showError(detail || '登录请求来源校验失败，请通过本站页面登录');
        } else {
          showError('登录失败：HTTP ' + response.status + (detail ? '：' + detail : ''));
        }
        passwordInput.value = '';
        passwordInput.focus();
        return;
      }
      /* 登录成功：Cookie 已由后端下发，直接跳到目标页 */
      window.location.assign(nextTarget());
    } catch (err) {
      showError('登录失败：' + (err && err.message ? err.message : '网络错误'));
    } finally {
      submit.disabled = false;
      submit.textContent = '登 录';
    }
  });
})();
