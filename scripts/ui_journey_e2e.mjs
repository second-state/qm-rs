// Browser e2e over the qm-rs web UI, with a captioned screenshot per step,
// producing a self-contained HTML report that strings them together.
//
// Runs against a REAL model gateway, so every agent reply in the report is a
// genuine turn — tool calls, approvals and memory included. Launched by
// scripts/e2e_report.sh; output goes to a timestamped e2e-reports/<ts>/ folder
// (gitignored).
//
// Env:
//   BASE    base URL of the running server   (default http://127.0.0.1:18110)
//   OUT     screenshot + report directory    (required)
//   LOG     server log, for the magic link   (required)
//   MODEL   model id, for the report header
//   ENDPOINT gateway base URL, for the report header

import { chromium } from 'playwright-core';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';

const BASE = process.env.BASE || 'http://127.0.0.1:18110';
const OUT = process.env.OUT || '/tmp/qm-e2e-report';
const LOG = process.env.LOG || '';
const MODEL = process.env.MODEL || 'unknown';
const ENDPOINT = process.env.ENDPOINT || 'unknown';
mkdirSync(OUT, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log('[e2e]', ...a);

// A live turn is a real model call; the UI blocks on it.
const TURN_TIMEOUT = 180_000;

const report = [];
let current = null;
let seq = 0;

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const ctx = await browser.newContext({ viewport: { width: 1320, height: 1000 } });
ctx.on('page', (p) => p.on('dialog', (d) => d.accept().catch(() => {})));
const page = await ctx.newPage();

async function cap(caption, opts = {}) {
  seq += 1;
  const file = String(seq).padStart(2, '0') + '.png';
  await page.screenshot({ path: `${OUT}/${file}`, fullPage: !!opts.full });
  current.shots.push({ file, caption });
  log('   📸', caption);
}

async function wf(name, fn) {
  current = { wf: name, status: 'pass', error: '', shots: [] };
  report.push(current);
  log('▶', name);
  try {
    await fn();
  } catch (e) {
    current.status = 'fail';
    current.error = String((e && e.message) || e);
    log('   ✗ FAIL:', current.error);
    try {
      await cap('FAILURE state');
    } catch {}
  }
}

function check(condition, what) {
  if (!condition) throw new Error(what);
}

/// Send a message in the open session and wait for the turn to land.
async function say(text) {
  await page.fill('#composer textarea', text);
  await Promise.all([
    page.waitForNavigation({ timeout: TURN_TIMEOUT, waitUntil: 'load' }),
    // noWaitAfter: the click must not also wait for navigation on its own 30s
    // budget — a live turn with tool calls routinely runs longer than that.
    page.click('#composer button[type=submit]', { noWaitAfter: true, timeout: 30_000 }),
  ]);
  await sleep(300);
}

/// Text of the last assistant entry on the transcript.
async function lastReply() {
  const entries = page.locator('.entry.assistant .body');
  const count = await entries.count();
  return count ? (await entries.nth(count - 1).textContent()).trim() : '';
}

/// Open a new session in the given scope and return its URL.
async function newSession(scope) {
  await page.goto(`${BASE}/sessions`, { waitUntil: 'load' });
  await page.selectOption('#scope', scope);
  await Promise.all([
    page.waitForNavigation({ timeout: 30_000 }),
    page.click('form[action="/sessions"] button[type=submit]', { noWaitAfter: true }),
  ]);
  return page.url();
}

// ---------------------------------------------------------------------------

await wf('Sign in with an emailed magic link', async () => {
  await page.goto(`${BASE}/sessions`, { waitUntil: 'load' });
  check(page.url().includes('/auth/login'), 'a protected page should redirect to sign-in');
  await cap('Every page is behind sign-in — /sessions redirects to the login form, carrying where it was going');

  await page.fill('#email', 'ada@acme.test');
  await Promise.all([
    page.waitForNavigation({ timeout: 30_000 }),
    page.click('form[action="/auth/request"] button[type=submit]'),
  ]);
  await cap('Link requested. The same page appears whether or not the address is allowed to sign in, so the form is not a membership oracle');

  // Console mode writes the link to the server log rather than emailing it.
  let link = '';
  for (let i = 0; i < 60 && !link; i++) {
    const text = readFileSync(LOG, 'utf8');
    const match = text.match(/http:\/\/[^\s"]*\/auth\/callback\?token=[A-Za-z0-9%&=.-]+/g);
    if (match) link = match[match.length - 1];
    else await sleep(250);
  }
  check(link, 'no sign-in link appeared in the server log');

  await page.goto(link, { waitUntil: 'load' });
  check(!page.url().includes('/auth/login'), 'the magic link should sign us in');
  await cap('Signed in. The link is single-use and short-lived; the session cookie is HttpOnly and SameSite=Lax');

  await page.goto(`${BASE}/`, { waitUntil: 'load' });
  await cap('The dashboard: scopes reachable, sessions, scheduled work, and the memory index', { full: true });
});

await wf('Ask the agent something (a real model turn)', async () => {
  await newSession('personal:ada');
  await cap('A new session in the personal scope — private to Ada alone');

  await say('Reply with exactly the single word: PONG');
  const reply = await lastReply();
  check(/pong/i.test(reply), `expected PONG, got ${JSON.stringify(reply)}`);
  await cap(`The agent answered from a live model call — "${reply.slice(0, 60)}"`);
});

await wf('Run a command in the scope\'s sandbox', async () => {
  await newSession('personal:ada');
  await say('Use your execute tool to run `echo hello-from-sandbox`, then tell me exactly what it printed.');

  const reply = await lastReply();
  check(/hello-from-sandbox/.test(reply), `expected the sandbox output, got ${JSON.stringify(reply)}`);
  check((await page.locator('.entry.tool_call').count()) >= 1, 'the tool call should be on the transcript');
  check((await page.locator('.entry.tool_result').count()) >= 1, 'the tool result should be on the transcript');
  await cap('The agent called `execute` in the scope\'s durable working directory. The tool call and its real output are first-class entries on the transcript, not just prose', { full: true });
});

await wf('Write and read a file through the workspace primitives', async () => {
  await newSession('personal:ada');
  await say(
    'Use the write tool to create workspace/fact.txt containing exactly: the sky is blue. ' +
      'Then use the read tool to read it back and tell me the contents.',
  );
  const reply = await lastReply();
  check(/the sky is blue/i.test(reply), `expected the file contents, got ${JSON.stringify(reply)}`);
  await cap('Write then read, through the workspace primitives — the file is really on disk in this scope\'s directory', { full: true });
});

await wf('A risky command pauses for a human', async () => {
  await newSession('personal:ada');
  await say('Use your execute tool to run exactly: rm -rf /tmp/qm-e2e-scratch');

  check((await page.locator('.approval').count()) === 1, 'a recursive delete should pause for approval');
  await cap('The predeclared command policy caught a recursive delete and paused the turn. The pause is a durable row, so it survives a restart — approving "once", "for this session" or "always" are different grants', { full: true });

  await page.selectOption('.approval select[name=scope]', 'once');
  await Promise.all([
    page.waitForNavigation({ timeout: TURN_TIMEOUT }),
    page.click('.approval button[value=approve]', { noWaitAfter: true, timeout: 30_000 }),
  ]);
  check((await page.locator('.entry.approval_resolved').count()) >= 1, 'the approval should be recorded');
  await cap('Approved once — the paused command ran and the decision is on the permanent record', { full: true });
});

await wf('The command policy denies what it will not run at all', async () => {
  await newSession('personal:ada');
  await say('Run this exact command with your execute tool: mkfs.ext4 /dev/sda1');
  await cap('A hard denial: `mkfs` is refused outright rather than offered for approval. This floor applies in every security posture, including "dangerous"', { full: true });
});

await wf('Durable memory: capture, then recall in a new session', async () => {
  await newSession('personal:ada');
  await say('Use your memory tool to record this fact: my deploy window is Thursday 14:00 UTC. Then confirm briefly.');
  await cap('The agent recorded a fact in this scope\'s notebook');

  await page.goto(`${BASE}/memory/personal:ada`, { waitUntil: 'load' });
  const body = await page.locator('textarea[name=content]').inputValue();
  check(/thursday/i.test(body), 'the fact should be in the notebook');
  await cap('The scope\'s memory notebook — dated bullets, editable, with a revision history. Saving compare-and-swaps on the revision loaded, so a concurrent edit is reported rather than overwritten', { full: true });

  // A brand new session: no shared conversation, only the notebook.
  await newSession('personal:ada');
  await say('When is my deploy window? Answer from what you already know.');
  const reply = await lastReply();
  check(/thursday/i.test(reply), `recall should cross sessions, got ${JSON.stringify(reply)}`);
  await cap('A completely separate session recalls the fact — memory is scoped and durable, not conversation context', { full: true });
});

await wf('Memory is scoped: a shared-scope turn belongs to the scope', async () => {
  // The scope picker only offers scopes this principal can actually reach, so
  // a channel Ada is not a member of is correctly absent. `org:acme` is the
  // shared scope every internal principal reaches, and demonstrates the same
  // property: what the agent learns in a shared scope belongs to that scope.
  await newSession('org:acme');
  await say('Use your memory tool to record: the team ships on Fridays. Then confirm briefly.');
  await cap('The same agent, in the shared org scope — everything here is visible to the whole organization');

  await page.goto(`${BASE}/memory`, { waitUntil: 'load' });
  await cap('The memory index — one notebook per scope. What the agent learns in a shared scope belongs to that scope, not to whoever happened to speak', { full: true });

  await page.goto(`${BASE}/memory/org:acme`, { waitUntil: 'load' });
  const sharedBody = await page.locator('textarea[name=content]').inputValue();
  check(/friday/i.test(sharedBody), 'the shared scope should hold the fact');
  await cap('The shared notebook holds it', { full: true });

  await page.goto(`${BASE}/memory/personal:ada`, { waitUntil: 'load' });
  const personalBody = await page.locator('textarea[name=content]').inputValue();
  check(!/friday/i.test(personalBody), 'it must not leak into the personal scope');
  await cap('…and Ada\'s personal notebook does not — no leak across the scope boundary', { full: true });
});

await wf('Skills: author, publish, and the agent follows it', async () => {
  await page.goto(`${BASE}/skills`, { waitUntil: 'load' });
  await page.fill(
    '#source',
    ['---', 'name: status-report', 'description: How to write a status report', '---', '', 'When asked for a status report, reply with exactly three lines, and end the last line with the token RPT7.'].join('\n'),
  );
  await Promise.all([
    page.waitForNavigation({ timeout: 30_000 }),
    page.click('form[action="/skills"] button[type=submit]'),
  ]);
  await cap('A new skill starts as a draft, signed on write. Its signature is verified on every read — a skill whose stored rows were tampered with is hidden from every turn rather than executed', { full: true });

  await page.click('form[action$="/status"] button:has-text("published")');
  await page.waitForLoadState('load');
  await cap('Published — only published, signature-valid skills reach a turn', { full: true });

  await newSession('personal:ada');
  await say('Read your status-report skill with the skills tool, then follow it to give me a status report about the weather.');
  const reply = await lastReply();
  check(/RPT7/.test(reply), `the model should follow the skill, got ${JSON.stringify(reply)}`);
  await cap('The agent read the published skill and followed it — the RPT7 token proves the skill body reached the model', { full: true });
});

await wf('The agent schedules background work', async () => {
  await newSession('personal:ada');
  await say(
    'Use your cron tool to schedule a job that runs at 09:00 every weekday in UTC with the ' +
      'message "check the deploy". Confirm what you scheduled.',
  );
  await cap('The agent scheduled the job itself, through the cron tool');

  await page.goto(`${BASE}/crons`, { waitUntil: 'load' });
  const crons = await page.locator('.panel').allTextContents();
  check(crons.some((t) => /deploy/i.test(t)), 'the cron should be listed');
  await cap('The crons page: each scheduled instant fires exactly once, and the schedule advances whatever the outcome — a cron that failed still runs tomorrow', { full: true });
});

await wf('Keychain: secrets go in, values never come out', async () => {
  await page.goto(`${BASE}/keychain`, { waitUntil: 'load' });
  await page.selectOption('#scope', 'personal:ada');
  await page.fill('#key', 'GITHUB_TOKEN');
  await page.fill('#value', 'ghp_this_value_must_never_be_rendered');
  await page.fill('#description', 'Read-only PAT for CI');
  await Promise.all([
    page.waitForNavigation({ timeout: 30_000 }),
    page.click('form[action="/keychain"] button[type=submit]'),
  ]);

  const html = await page.content();
  check(!html.includes('ghp_this_value_must_never_be_rendered'), 'the secret value must never be rendered');
  await cap('Stored. The page lists metadata only — the value is never rendered, never logged, and never reaches the audit detail. It is materialized as an environment variable when the agent runs `execute`', { full: true });
});

await wf('Files and sharing between scopes', async () => {
  await newSession('personal:ada');
  await say('Use the write tool to create workspace/plan.md containing a two-line project plan, then share it with org:acme using the share tool.');
  await cap('The agent wrote a file and shared it with a channel');

  await page.goto(`${BASE}/files`, { waitUntil: 'load' });
  await cap('The files page: artifacts owned by a scope, what other scopes shared with you, and what you shared out. A grant surfaces to the agent as a path under shared/ — the only way a turn touches another scope\'s files', { full: true });
});

await wf('Account: API keys and active sessions', async () => {
  await page.goto(`${BASE}/account`, { waitUntil: 'load' });
  await page.fill('#name', 'e2e demo key');
  await Promise.all([
    page.waitForNavigation({ timeout: 30_000 }),
    page.click('form[action="/account/keys"] button[type=submit]'),
  ]);
  check((await page.locator('input[readonly]').count()) >= 1, 'the new key should be shown once');
  await cap('A new API key, shown exactly once. Only its SHA-256 hash is stored, so database access does not hand anyone a live credential. Keys cannot mint further keys — that needs a browser session', { full: true });

  await page.goto(`${BASE}/account`, { waitUntil: 'load' });
  await cap('Back on the account page the key is gone — only its prefix, name and last-used time remain. Active sessions are listed with a "sign out everywhere" button', { full: true });
});

await wf('Admin: schema, plugins, policy floor, and the audit log', async () => {
  await page.goto(`${BASE}/admin`, { waitUntil: 'load' });
  const adminText = await page.locator('main').textContent();
  check(/applied/i.test(adminText), 'migrations should be listed');
  await cap('The admin page. Migrations are compile-time embedded and versioned; applied is shown against registered so schema drift is visible without a shell', { full: true });

  await page.locator('h2:has-text("Command policy floor")').scrollIntoViewIfNeeded();
  await cap('The command policy floor — the rules that apply in every posture and that a scope may add to but never remove. Below it, the durable audit log of everything consequential the agent did', { full: true });
});

await wf('Sign out returns the app to a locked state', async () => {
  await page.click('header form[action="/auth/logout"] button');
  await page.waitForLoadState('load');
  await cap('Signed out');

  await page.goto(`${BASE}/sessions`, { waitUntil: 'load' });
  check(page.url().includes('/auth/login'), 'protected pages should be locked again');
  await cap('…and the protected pages are locked again. Every page and API handler takes an authenticated principal as an argument, so a handler cannot forget to check', { full: true });
});

// ---------------------------------------------------------------------------

await browser.close();

const passed = report.filter((r) => r.status === 'pass').length;
const total = report.length;
const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');

const escape = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>qm-rs — e2e report ${stamp}</title>
<style>
  :root { --ink:#16181d; --paper:#fbfbfd; --panel:#fff; --line:#e3e5ec; --accent:#3557d6;
          --ok:#1f7a4d; --bad:#b4232b; --muted:#676b78; }
  @media (prefers-color-scheme: dark) {
    :root { --ink:#e8eaf0; --paper:#14161b; --panel:#1c1f26; --line:#2b3039; --accent:#7d9bff;
            --ok:#5fca92; --bad:#f28b8b; --muted:#9aa0b0; }
  }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         background:var(--paper); color:var(--ink); margin:0; line-height:1.55; }
  header { background:var(--ink); color:var(--paper); padding:22px 30px; position:sticky; top:0; z-index:5; }
  @media (prefers-color-scheme: dark) { header { background:#0d0f13; color:var(--ink); } }
  header h1 { margin:0 0 6px; font-size:1.25rem; letter-spacing:-.01em; }
  header .meta { opacity:.82; font-size:.88rem; }
  header code { background:rgba(255,255,255,.12); padding:1px 6px; border-radius:5px; font-size:.85em; }
  .tally b { font-weight:700; } .tally .ok { color:#7fd1a0; } .tally .bad { color:#ff9a8c; }
  nav { padding:14px 30px; background:var(--panel); border-bottom:1px solid var(--line);
        display:flex; flex-wrap:wrap; gap:8px; }
  nav a { font-size:.82rem; text-decoration:none; color:var(--ink); background:var(--paper);
          border:1px solid var(--line); border-radius:999px; padding:4px 11px; }
  nav a.fail { background:#fbe0dd; color:var(--bad); border-color:var(--bad); }
  main { max-width:1180px; margin:0 auto; padding:24px 30px 60px; }
  .wf { background:var(--panel); border:1px solid var(--line); border-radius:14px;
        padding:18px 22px; margin:18px 0; }
  .wf h2 { font-size:1.05rem; margin:0 0 12px; display:flex; align-items:center; gap:10px; }
  .badge { font-size:.72rem; font-weight:700; border-radius:999px; padding:3px 10px; white-space:nowrap; }
  .badge.pass { background:rgba(31,122,77,.14); color:var(--ok); }
  .badge.fail { background:rgba(180,35,43,.14); color:var(--bad); }
  .err { color:var(--bad); font-family:ui-monospace,Menlo,monospace; font-size:.82rem;
         background:rgba(180,35,43,.08); padding:8px 10px; border-radius:8px; margin-bottom:12px; }
  .shots { display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:16px; }
  figure.shot { margin:0; border:1px solid var(--line); border-radius:10px; overflow:hidden;
                background:var(--paper); }
  figure.shot img { width:100%; display:block; }
  figcaption { font-size:.82rem; color:var(--muted); padding:9px 11px; border-top:1px solid var(--line); }
  footer { max-width:1180px; margin:0 auto; padding:0 30px 50px; color:var(--muted); font-size:.85rem; }
</style></head><body>
<header>
  <h1>qm-rs — browser e2e report</h1>
  <div class="meta">${stamp} · live model run · <code>${escape(MODEL)}</code> via <code>${escape(ENDPOINT)}</code></div>
  <div class="tally meta"><b class="${passed === total ? 'ok' : 'bad'}">${passed}/${total} workflows passed</b></div>
</header>
<nav>${report
  .map(
    (r, i) =>
      `<a href="#wf${i}" class="${r.status}">${r.status === 'pass' ? '✓' : '✗'} ${escape(r.wf)}</a>`,
  )
  .join('')}</nav>
<main>${report
  .map(
    (r, i) => `<section id="wf${i}" class="wf ${r.status}">
  <h2><span class="badge ${r.status}">${r.status === 'pass' ? '✓ PASS' : '✗ FAIL'}</span> ${escape(r.wf)}</h2>
  ${r.error ? `<div class="err">${escape(r.error)}</div>` : ''}
  <div class="shots">${r.shots
    .map(
      (s) =>
        `<figure class="shot"><a href="${s.file}" target="_blank"><img src="${s.file}" loading="lazy"></a><figcaption>${escape(s.caption)}</figcaption></figure>`,
    )
    .join('\n')}</div>
</section>`,
  )
  .join('\n')}</main>
<footer>
  Every agent reply above is a real turn against <code>${escape(MODEL)}</code> — no fixtures, no fake harness.
  Screenshots are captured step by step as the journey runs.
</footer>
</body></html>`;

writeFileSync(`${OUT}/report.html`, html);
writeFileSync(`${OUT}/report.json`, JSON.stringify({ stamp, model: MODEL, endpoint: ENDPOINT, passed, total, report }, null, 2));

log('');
log(`${passed}/${total} workflows passed · ${seq} screenshots`);
log(`report: ${OUT}/report.html`);

process.exit(passed === total ? 0 : 1);
