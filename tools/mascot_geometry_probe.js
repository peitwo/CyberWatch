/* ===== CyberWatch 吉祥物几何探针（发布前 UI 修复的取证工具） =====
 *
 * 背景：登录页右侧的白色圆脸吉祥物表情错位，眼睛/嘴巴/腮红被挤到圆脸外侧。
 * "看起来错了"不是可交付的证据 —— 这个脚本把"错位"翻译成**可断言的数字**：
 *
 *   1. 用 `Range.getBoundingClientRect()` **逐字形**取包围盒
 *      （整行文字取包围盒是验不出左右对称的：两个字形偏了同样的距离，
 *        整行包围盒仍然居中 —— 那正是"看起来居中、其实是歪的"的来源）；
 *   2. 逐项核对：眼睛左右对称、嘴巴居中、每个字形都落在白脸矩形内、
 *      白脸完全落在 orb 内、脸心与球心重合；
 *   3. 把 `position / left / top / transform / 容器宽高` 一并打出来，
 *      定位上下文（containing block）出问题时会直接体现在这几个值上；
 *   4. 在 390 / 720 / 1440 三档视口各跑一遍，并检查横向溢出。
 *
 * 刻意**不**用单元测试替代：TestClient 不跑布局、不实现 CSS 级联，
 * 而本缺陷 100% 出在 CSS 级联与定位上下文上。
 *
 * 用法：
 *   node tools/mascot_geometry_probe.js                 # 三档视口 + 截图 + JSON
 *   CW_TAG=after node tools/mascot_geometry_probe.js    # 给产物打标签，便于改前/改后对比
 *   CW_SWEEP=1 node tools/mascot_geometry_probe.js      # 额外来一遍 640→1600 宽度扫描
 *   CW_BASE=http://127.0.0.1:8000 node tools/mascot_geometry_probe.js
 *
 * 产出：docs/acceptance-v051/mascot-<TAG>.json + mascot-<TAG>-<page>-<width>.png
 * 退出码：0 全部通过；1 有失败项（含"看门狗"式断言失败）。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright-core');

const BASE = process.env.CW_BASE || 'http://127.0.0.1:8765';
const ROOT = path.join(__dirname, '..');
const OUT_DIR = process.env.CW_OUT || path.join(ROOT, 'docs', 'acceptance-v051');
const TAG = process.env.CW_TAG || 'current';
const USERNAME = process.env.CW_USER || 'accept-admin';
const PASSWORD = process.env.CW_PASS || 'Acceptance-Admin-2026';
const DO_SWEEP = process.env.CW_SWEEP === '1';

const VIEWPORTS = [
  { label: '390', width: 390, height: 844 },
  { label: '720', width: 720, height: 1024 },
  { label: '1440', width: 1440, height: 900 },
];

/** 白脸是 95×83 的盒子，字形包围盒允许有 1px 的亚像素余量。 */
const EDGE_EPS = 1.0;
/** 对称/居中判定容差：1px（亚像素渲染会带来 0.5px 级别的抖动）。 */
const SYMMETRY_EPS = 1.0;
/** 脸心 ↔ 球心 的允许偏移。 */
const CENTER_EPS = 2.0;

const report = { tag: TAG, base: BASE, generatedAt: new Date().toISOString(), cases: [], sweep: [], failures: [] };

function fail(scope, message) {
  report.failures.push(`${scope}: ${message}`);
}

function show(value) {
  return value === null || value === undefined ? '—' : value;
}

// ---------------------------------------------------------------------------
// 页面内测量：一次 evaluate 把所有几何量取回来（避免多次往返导致布局抖动）
// ---------------------------------------------------------------------------
function measureInPage() {
  const ART_SELECTOR = '.login-art, .hero-art';

  function boxOf(element) {
    if (!element) return null;
    const rect = element.getBoundingClientRect();
    return {
      x: +rect.x.toFixed(2),
      y: +rect.y.toFixed(2),
      w: +rect.width.toFixed(2),
      h: +rect.height.toFixed(2),
      cx: +(rect.x + rect.width / 2).toFixed(2),
      cy: +(rect.y + rect.height / 2).toFixed(2),
      right: +(rect.right).toFixed(2),
      bottom: +(rect.bottom).toFixed(2),
    };
  }

  function boxOfRange(node, start, end) {
    const range = document.createRange();
    range.setStart(node, start);
    range.setEnd(node, end);
    const rect = range.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return null;
    return {
      x: +rect.x.toFixed(2),
      y: +rect.y.toFixed(2),
      w: +rect.width.toFixed(2),
      h: +rect.height.toFixed(2),
      cx: +(rect.x + rect.width / 2).toFixed(2),
      cy: +(rect.y + rect.height / 2).toFixed(2),
      right: +rect.right.toFixed(2),
      bottom: +rect.bottom.toFixed(2),
    };
  }

  /** 逐字形取包围盒：整行取一次是验不出对称性的（见文件头注释）。 */
  function glyphsOf(span) {
    if (!span || !span.firstChild || span.firstChild.nodeType !== 3) return [];
    const node = span.firstChild;
    const text = node.textContent;
    const out = [];
    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      if (char === '\u3000' || char === ' ') continue; // 全角空格不作为字形
      const rect = boxOfRange(node, index, index + 1);
      if (!rect) continue;
      out.push(Object.assign({ char, index }, rect));
    }
    return out;
  }

  function stylesOf(element, props) {
    if (!element) return null;
    const computed = getComputedStyle(element);
    const out = {};
    props.forEach(function (prop) {
      out[prop] = computed[prop];
    });
    return out;
  }

  const art = document.querySelector(ART_SELECTOR);
  const result = {
    url: location.pathname + location.search,
    artSelector: art ? art.className.split(' ')[0] : null,
    viewport: { width: window.innerWidth, height: window.innerHeight },
    artifact: null,
  };

  // 以装饰区为查询根。**不要**写成 document.querySelector(ART_SELECTOR + ' .orb') ——
  // '.' 前面的选择器列表里有逗号，会被解析成两条并列分支
  // （`.login-art` 与 `.hero-art .orb`），于是登录页上 `.orb` 会解析成 `.login-art` 本身。
  const pick = function (selector) {
    return art ? art.querySelector(selector) : null;
  };

  if (art) {
    const artStyle = getComputedStyle(art);
    const artBox = boxOf(art);
    result.artifact = {
      display: artStyle.display,
      rect: artBox,
      padding: artStyle.padding,
      visible: artStyle.display !== 'none' && artBox.w > 0 && artBox.h > 0,
    };
  }

  const orb = pick('.orb');
  const face = pick('.mascot');
  // 行元素优先按共享类名取；取不到就退回"脸内第 1/2 个子元素"。
  // 兜底是**有意为之**：改前登录页的两个 span 压根没有 class
  // （这正是"没接上共享组件"的证据），没有兜底就量不出"字形跑到脸外"。
  const childSpans = face ? Array.from(face.children) : [];
  const eyesLine = pick('.ears') || childSpans[0] || null;
  const mouthLine = pick('.eyes') || childSpans[1] || null;
  const sparks = Array.from(art ? art.querySelectorAll('.spark') : []).map(boxOf);

  result.orb = {
    rect: boxOf(orb),
    styles: stylesOf(orb, ['position', 'inset', 'left', 'top', 'width', 'height', 'borderRadius']),
  };
  result.face = {
    rect: boxOf(face),
    styles: stylesOf(face, [
      'position',
      'left',
      'top',
      'transform',
      'width',
      'height',
      'display',
      'flexDirection',
      'alignItems',
      'paddingTop',
      'fontSize',
      'letterSpacing',
      'backgroundColor',
    ]),
  };
  result.eyeGlyphs = glyphsOf(eyesLine);
  result.mouthGlyphs = glyphsOf(mouthLine);
  result.lineBoxes = { eyes: boxOf(eyesLine), mouth: boxOf(mouthLine) };
  result.mascotMarkup = face
    ? {
        childCount: face.children.length,
        className: face.className,
        firstChildClass: face.children[0] ? face.children[0].className : null,
        secondChildClass: face.children[1] ? face.children[1].className : null,
        usesSharedClasses: !!(pick('.ears') && pick('.eyes')),
      }
    : null;
  result.sparks = sparks;

  // 定位上下文：白脸的 offsetParent 说明了它的 left/top 是相对谁算的
  if (face) {
    const parent = face.offsetParent;
    result.face.offsetParent = parent
      ? (parent.className ? '.' + String(parent.className).split(' ')[0] : parent.tagName)
      : null;
  }
  if (orb) {
    const parent = orb.offsetParent;
    result.orb.offsetParent = parent
      ? (parent.className ? '.' + String(parent.className).split(' ')[0] : parent.tagName)
      : null;
  }

  result.overflow = {
    docScrollWidth: document.documentElement.scrollWidth,
    bodyScrollWidth: document.body.scrollWidth,
    innerWidth: window.innerWidth,
    horizontal: document.documentElement.scrollWidth > window.innerWidth + 1,
  };

  return result;
}

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------
function inside(inner, outer, eps) {
  if (!inner || !outer) return false;
  return (
    inner.x >= outer.x - eps &&
    inner.y >= outer.y - eps &&
    inner.right <= outer.right + eps &&
    inner.bottom <= outer.bottom + eps
  );
}

function analyse(scope, pageKey, data) {
  const caseRecord = {
    scope,
    page: pageKey,
    viewport: data.viewport,
    artVisible: !!(data.artifact && data.artifact.visible),
    checks: [],
    measurements: data,
  };

  function check(name, ok, detail) {
    caseRecord.checks.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) });
    if (!ok) fail(`${scope} ${name}`, detail);
  }

  if (!caseRecord.artVisible) {
    // 装饰区在窄屏按既有设计隐藏：此时唯一要保证的是"没有把布局撑坏"
    check('装饰区隐藏时无横向溢出', !data.overflow.horizontal, `scrollWidth=${data.overflow.docScrollWidth} innerWidth=${data.overflow.innerWidth}`);
    report.cases.push(caseRecord);
    return caseRecord;
  }

  const face = data.face.rect;
  const orb = data.orb.rect;
  const eyeGlyphs = data.eyeGlyphs;
  const mouthGlyphs = data.mouthGlyphs;

  check('存在白脸与 orb', !!face && !!orb, `face=${!!face} orb=${!!orb}`);
  if (!face || !orb) {
    report.cases.push(caseRecord);
    return caseRecord;
  }

  // 1) 白脸必须完整落在 orb 内（"跑出圆脸"的宏观版本）
  check(
    '白脸完全位于 orb 内',
    inside(face, orb, EDGE_EPS),
    `face=[${face.x},${face.y},${face.right},${face.bottom}] orb=[${orb.x},${orb.y},${orb.right},${orb.bottom}]`
  );

  // 2) 脸心 ↔ 球心
  //    Dashboard 的 orb 是个 190×146 的斜椭圆，白脸刻意偏右下（构图需要），
  //    所以"同心"只对登录页的**圆形** orb 成立；Dashboard 只要求"在球内"。
  const dx = +(face.cx - orb.cx).toFixed(2);
  const dy = +(face.cy - orb.cy).toFixed(2);
  caseRecord.faceCenterDelta = [dx, dy];
  if (pageKey === 'login') {
    check(
      '白脸中心与 orb 中心重合',
      Math.abs(dx) <= CENTER_EPS && Math.abs(dy) <= CENTER_EPS,
      `Δ=(${dx}, ${dy})`
    );
  } else {
    check('Dashboard 白脸仍在 orb 内（构图偏移属既有设计）', inside(face, orb, EDGE_EPS), `Δ=(${dx}, ${dy})`);
  }

  // 3) 每个字形都必须在白脸矩形内（"元素跑到圆脸外侧"的直接判据）
  const allGlyphs = eyeGlyphs.concat(mouthGlyphs);
  // 看门狗：字形取不到时"全部在脸内"会**空集合通过**，是最危险的假绿
  check(
    '字形总数 = 5（2 眼 + 2 腮红 + 1 嘴）',
    allGlyphs.length === 5,
    `实际取到 ${allGlyphs.length} 个字形（${allGlyphs.map((g) => g.char).join('') || '无'}）`
  );
  // 行包围盒也必须在白脸内 —— 比逐字形更严格：行盒包含行高与首尾的
  // letter-spacing 尾随空白，而"字被拉出脸外"最先体现在行盒上。
  const lineBoxes = data.lineBoxes || {};
  [
    ['eyes', '眼睛'],
    ['mouth', '嘴巴+腮红'],
  ].forEach(function (pair) {
    const line = lineBoxes[pair[0]];
    if (!line) return;
    check(
      `「${pair[1]}」整行落在白脸内`,
      inside(line, face, EDGE_EPS),
      `行=[x${line.x} y${line.y} → ${line.right},${line.bottom}] 脸=[x${face.x} y${face.y} → ${face.right},${face.bottom}]`
    );
  });

  const strays = allGlyphs.filter(function (glyph) {
    return !inside(glyph, face, EDGE_EPS);
  });
  check(
    '全部字形都在白脸范围内',
    allGlyphs.length > 0 && strays.length === 0,
    strays.length
      ? strays
          .map(function (glyph) {
            const overflow = Math.max(
              face.x - glyph.x,
              glyph.right - face.right,
              face.y - glyph.y,
              glyph.bottom - face.bottom
            );
            return `「${glyph.char}」溢出 ${overflow.toFixed(1)}px`;
          })
          .join('; ')
      : `${allGlyphs.length} 个字形全部在脸内`
  );

  // 4) 眼睛左右对称：一对「◠」必须关于**脸心**中点对称
  const twoEyes = eyeGlyphs.filter(function (glyph) {
    return glyph.char === '◠';
  });
  check('眼睛是两个字形', twoEyes.length === 2, `找到 ${twoEyes.length} 个「◠」`);
  if (twoEyes.length === 2) {
    const left = twoEyes[0];
    const right = twoEyes[1];
    const leftGap = +(face.cx - left.cx).toFixed(2);
    const rightGap = +(right.cx - face.cx).toFixed(2);
    const eyeMidOffset = +((left.cx + right.cx) / 2 - face.cx).toFixed(2);
    check(
      '眼睛左右对称（相对于脸心等距）',
      Math.abs(leftGap - rightGap) <= SYMMETRY_EPS,
      `左 ${leftGap}px / 右 ${rightGap}px（差 ${Math.abs(leftGap - rightGap).toFixed(2)}px）`
    );
    check('双眼中点与脸心重合', Math.abs(eyeMidOffset) <= SYMMETRY_EPS, `中点偏移 ${eyeMidOffset}px`);
    check(
      '双眼同高',
      Math.abs(left.cy - right.cy) <= SYMMETRY_EPS,
      `Δy=${Math.abs(left.cy - right.cy).toFixed(2)}px`
    );
  }

  // 5) 嘴巴居中：中间那个「ᴗ」的横向中心必须与脸心重合
  const mouth = mouthGlyphs.find(function (glyph) {
    return glyph.char === 'ᴗ';
  });
  check('找到嘴巴字形「ᴗ」', !!mouth, mouth ? `cx=${mouth.cx}` : '未找到');
  if (mouth) {
    const offset = +(mouth.cx - face.cx).toFixed(2);
    check('嘴巴水平居中于白脸', Math.abs(offset) <= SYMMETRY_EPS, `偏移 ${offset}px（脸心 ${face.cx}）`);
  }

  // 6) 腮红：与嘴巴同行的两个「•」必须左右对称且在脸内
  const blush = mouthGlyphs.filter(function (glyph) {
    return glyph.char === '•';
  });
  check('腮红是两个字形', blush.length === 2, `找到 ${blush.length} 个「•」`);
  if (blush.length === 2) {
    const leftBlush = blush[0];
    const rightBlush = blush[1];
    const leftGap = +(face.cx - leftBlush.cx).toFixed(2);
    const rightGap = +(rightBlush.cx - face.cx).toFixed(2);
    const blushMidOffset = +((leftBlush.cx + rightBlush.cx) / 2 - face.cx).toFixed(2);
    check(
      '腮红左右对称（相对于脸心等距）',
      Math.abs(leftGap - rightGap) <= SYMMETRY_EPS,
      `左 ${leftGap}px / 右 ${rightGap}px（差 ${Math.abs(leftGap - rightGap).toFixed(2)}px）`
    );
    check('腮红中点与脸心重合', Math.abs(blushMidOffset) <= SYMMETRY_EPS, `中点偏移 ${blushMidOffset}px`);
    check(
      '腮红在白脸范围内',
      inside(leftBlush, face, EDGE_EPS) && inside(rightBlush, face, EDGE_EPS),
      `左 right=${leftBlush.right} 脸 right=${face.right}；右 x=${rightBlush.x} 脸 x=${face.x}`
    );
    if (mouth) {
      check(
        '腮红与嘴巴同高（同一行）',
        Math.abs(leftBlush.cy - mouth.cy) <= SYMMETRY_EPS * 2,
        `Δy=${Math.abs(leftBlush.cy - mouth.cy).toFixed(2)}px`
      );
      check(
        '嘴巴位于两腮红之间',
        mouth.cx > leftBlush.cx && mouth.cx < rightBlush.cx,
        `嘴 ${mouth.cx} ∈ (${leftBlush.cx}, ${rightBlush.cx})`
      );
    }
  }

  // 7) 布局本身不能坏
  check(
    '无横向溢出',
    !data.overflow.horizontal,
    `scrollWidth=${data.overflow.docScrollWidth} innerWidth=${data.overflow.innerWidth}`
  );

  // 8) 定位上下文：白脸必须是绝对定位、且相对装饰区定位
  check(
    '白脸定位上下文是装饰区',
    data.face.offsetParent === '.' + data.artSelector || data.face.offsetParent === null,
    `offsetParent=${show(data.face.offsetParent)} art=${data.artSelector}`
  );

  report.cases.push(caseRecord);
  return caseRecord;
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------
async function login(context) {
  const response = await context.request.post(BASE + '/auth/login', {
    data: { username: USERNAME, password: PASSWORD },
    headers: { 'Content-Type': 'application/json' },
  });
  if (!response.ok()) {
    throw new Error(`登录失败 HTTP ${response.status()}：${await response.text()}`);
  }
}

async function measure(page, url, pageKey, scope, label) {
  await page.goto(BASE + url, { waitUntil: 'load' });
  await page.waitForTimeout(120);
  const data = await page.evaluate(measureInPage);
  const record = analyse(scope, pageKey, data);

  fs.mkdirSync(OUT_DIR, { recursive: true });
  const file = path.join(OUT_DIR, `mascot-${TAG}-${pageKey}-${label}.png`);
  await page.screenshot({ path: file });
  record.screenshot = path.relative(ROOT, file).replace(/\\/g, '/');
  return record;
}

function describeFace(record) {
  const face = record.measurements.face;
  const orb = record.measurements.orb;
  if (!face || !face.rect) return '   （无白脸）';
  return [
    `   orb  ${JSON.stringify(orb.rect)}  styles=${JSON.stringify({
      position: orb.styles.position,
      inset: orb.styles.inset,
      width: orb.styles.width,
      height: orb.styles.height,
    })}`,
    `   face ${JSON.stringify(face.rect)}`,
    `   face styles=${JSON.stringify(face.styles)}`,
    `   face offsetParent=${show(face.offsetParent)}   orb offsetParent=${show(orb.offsetParent)}`,
    `   行盒 ${JSON.stringify(record.measurements.lineBoxes)}`,
    `   标记 ${JSON.stringify(record.measurements.mascotMarkup)}`,
  ].join('\n');
}

(async function main() {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await login(context);
  const page = await context.newPage();

  console.log(`=== 吉祥物几何探针  tag=${TAG}  base=${BASE}`);
  console.log(`=== 视口：${VIEWPORTS.map((v) => v.label).join(' / ')}`);

  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });

    for (const target of [
      { url: '/login', key: 'login', scope: `login@${viewport.label}` },
      { url: '/dashboard', key: 'dashboard', scope: `dashboard@${viewport.label}` },
    ]) {
      console.log(`\n=== ${target.scope}（${viewport.width}×${viewport.height}）`);
      const record = await measure(page, target.url, target.key, target.scope, viewport.label);
      if (!record.artVisible) {
        console.log('   装饰区在本视口按既有设计隐藏（display:none）');
      } else {
        console.log(describeFace(record));
      }
      record.checks.forEach(function (item) {
        console.log(`   ${item.ok ? 'PASS' : 'FAIL'}  ${item.name}${item.detail ? `   — ${item.detail}` : ''}`);
      });
    }
  }

  if (DO_SWEEP) {
    console.log('\n=== 宽度扫描 640 → 1600（步长 40，只报失败项与装饰区可见性）');
    await page.goto(BASE + '/login', { waitUntil: 'load' });
    for (let width = 640; width <= 1600; width += 40) {
      await page.setViewportSize({ width, height: 900 });
      await page.waitForTimeout(60);
      const data = await page.evaluate(measureInPage);
      const before = report.failures.length;
      const record = analyse(`sweep@${width}`, 'login', data);
      const visible = record.artVisible;
      report.sweep.push({
        width,
        artVisible: visible,
        failed: report.failures.length - before,
        faceCenterDelta: visible && data.face.rect && data.orb.rect
          ? [+(data.face.rect.cx - data.orb.rect.cx).toFixed(2), +(data.face.rect.cy - data.orb.rect.cy).toFixed(2)]
          : null,
      });
      console.log(
        `   ${width}px  art=${visible ? 'visible' : 'hidden '}  ` +
          `${visible ? `脸心偏移=${JSON.stringify(report.sweep[report.sweep.length - 1].faceCenterDelta)}` : ''}  ` +
          `${record.checks.some((c) => !c.ok) ? 'FAIL' : 'ok'}`
      );
    }
    await page.setViewportSize({ width: 1440, height: 900 });
  }

  const jsonFile = path.join(OUT_DIR, `mascot-${TAG}.json`);
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(jsonFile, JSON.stringify(report, null, 2), 'utf8');

  const total = report.cases.reduce((sum, item) => sum + item.checks.length, 0) + report.sweep.reduce((sum, item) => sum + 0, 0);
  const failed = report.failures.length;

  console.log('\n=== 汇总');
  console.log(`   用例断点 ${total} 项，失败 ${failed} 项`);
  if (failed) {
    report.failures.forEach(function (item) {
      console.log(`   FAIL  ${item}`);
    });
  }
  console.log(`   证据 → ${path.relative(ROOT, jsonFile).replace(/\\/g, '/')}`);

  await browser.close();
  process.exit(failed ? 1 : 0);
})().catch(function (error) {
  console.error('探针异常终止：', error);
  process.exit(2);
});
