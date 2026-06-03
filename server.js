const express = require('express');
const Database = require('better-sqlite3');
const { nanoid } = require('nanoid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // we load inline scripts
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');

// Rate limiting
const createLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: 'Too many pastes created. Slow down.'
});

// Init DB
const db = new Database(path.join(__dirname, 'sloxbin.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS pastes (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author TEXT DEFAULT 'Anonymous',
    syntax TEXT DEFAULT 'plaintext',
    expiry INTEGER DEFAULT 0,
    password_hash TEXT DEFAULT NULL,
    views INTEGER DEFAULT 0,
    pinned INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS hall_of_fame (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    title TEXT NOT NULL,
    paste_id TEXT,
    category TEXT DEFAULT 'legend',
    created_at INTEGER NOT NULL
  );
`);

// Seed hall of fame if empty
const hofCount = db.prepare('SELECT COUNT(*) as c FROM hall_of_fame').get();
if (hofCount.c === 0) {
  const seedHof = db.prepare(`INSERT INTO hall_of_fame (username, title, paste_id, category, created_at) VALUES (?, ?, ?, ?, ?)`);
  const now = Date.now();
  seedHof.run('xXd4rkn3tXx', 'First blood', 'abc123', 'legend', now - 86400000 * 10);
  seedHof.run('null_ptr', 'SQL injection master', null, 'big_brain', now - 86400000 * 7);
  seedHof.run('voidwalker', 'Dropped the hottest paste of 2024', null, 'legend', now - 86400000 * 3);
  seedHof.run('anonGhost', 'Posted more than anyone else', null, 'grinder', now - 86400000 * 1);
  seedHof.run('0x41414141', 'Buffer overflow of the year', null, 'big_brain', now - 3600000);
}

// Helpers
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'sloxbin_salt_2024').digest('hex');
}

function readFile(filePath) {
  return require('fs').readFileSync(path.join(__dirname, filePath), 'utf8');
}

function cleanExpired() {
  const now = Date.now();
  db.prepare('DELETE FROM pastes WHERE expiry > 0 AND expiry < ?').run(now);
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// GET /
app.get('/', (req, res) => {
  cleanExpired();
  const q = req.query.q || '';
  let pastes;
  if (q) {
    pastes = db.prepare(`
      SELECT id, title, author, syntax, views, created_at
      FROM pastes
      WHERE (title LIKE ? OR author LIKE ?) AND (expiry = 0 OR expiry > ?)
      ORDER BY created_at DESC LIMIT 50
    `).all(`%${q}%`, `%${q}%`, Date.now());
  } else {
    pastes = db.prepare(`
      SELECT id, title, author, syntax, views, created_at
      FROM pastes
      WHERE expiry = 0 OR expiry > ?
      ORDER BY created_at DESC LIMIT 50
    `).all(Date.now());
  }

  const pinned = db.prepare(`
    SELECT id, title, author, syntax, views, created_at
    FROM pastes WHERE pinned = 1 AND (expiry = 0 OR expiry > ?)
    ORDER BY created_at DESC LIMIT 5
  `).all(Date.now());

  const stats = db.prepare('SELECT COUNT(*) as total FROM pastes WHERE expiry = 0 OR expiry > ?').get(Date.now());

  res.send(renderPage('home', { pastes, pinned, q, stats, req }));
});

// GET /new
app.get('/new', (req, res) => {
  res.send(renderPage('new', { req }));
});

// POST /new
app.post('/new', createLimiter, (req, res) => {
  cleanExpired();
  let { title, content, author, syntax, expiry, password } = req.body;

  if (!content || content.trim() === '') {
    return res.status(400).send(renderPage('new', { error: 'Content cannot be empty.', req }));
  }

  title = (title || 'Untitled').trim().slice(0, 200);
  content = content.trim();
  author = (author || 'Anonymous').trim().slice(0, 50);
  syntax = syntax || 'plaintext';

  const expiryMs = expiry === '1h' ? Date.now() + 3600000
    : expiry === '24h' ? Date.now() + 86400000
    : expiry === '7d' ? Date.now() + 604800000
    : expiry === '30d' ? Date.now() + 2592000000
    : 0;

  const passwordHash = password ? hashPassword(password) : null;
  const id = nanoid(8);

  db.prepare(`
    INSERT INTO pastes (id, title, content, author, syntax, expiry, password_hash, views, pinned, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
  `).run(id, title, content, author, syntax, expiryMs, passwordHash, Date.now());

  res.redirect(`/paste/${id}`);
});

// GET /paste/:id
app.get('/paste/:id', (req, res) => {
  cleanExpired();
  const paste = db.prepare('SELECT * FROM pastes WHERE id = ?').get(req.params.id);
  if (!paste) {
    return res.status(404).send(renderPage('404', { req }));
  }

  // Check expiry
  if (paste.expiry > 0 && paste.expiry < Date.now()) {
    db.prepare('DELETE FROM pastes WHERE id = ?').run(paste.id);
    return res.status(404).send(renderPage('404', { req }));
  }

  // Password check
  if (paste.password_hash && req.query.pw !== paste.password_hash) {
    if (req.query.pw) {
      const attempt = hashPassword(req.query.pw_raw || '');
      if (attempt !== paste.password_hash) {
        return res.send(renderPage('password', { id: paste.id, error: 'Wrong password.', req }));
      }
    } else {
      return res.send(renderPage('password', { id: paste.id, error: null, req }));
    }
  }

  // Increment views
  db.prepare('UPDATE pastes SET views = views + 1 WHERE id = ?').run(paste.id);
  paste.views += 1;

  res.send(renderPage('paste', { paste, req }));
});

// POST /paste/:id/password
app.post('/paste/:id/password', (req, res) => {
  const paste = db.prepare('SELECT * FROM pastes WHERE id = ?').get(req.params.id);
  if (!paste) return res.status(404).send(renderPage('404', { req }));

  const attempt = hashPassword(req.body.password || '');
  if (attempt !== paste.password_hash) {
    return res.send(renderPage('password', { id: paste.id, error: 'Wrong password.', req }));
  }

  db.prepare('UPDATE pastes SET views = views + 1 WHERE id = ?').run(paste.id);
  paste.views += 1;
  res.send(renderPage('paste', { paste, req }));
});

// GET /paste/:id/raw
app.get('/paste/:id/raw', (req, res) => {
  const paste = db.prepare('SELECT * FROM pastes WHERE id = ?').get(req.params.id);
  if (!paste) return res.status(404).send('Not found');
  if (paste.password_hash) return res.status(403).send('Password protected');
  res.set('Content-Type', 'text/plain');
  res.send(paste.content);
});

// GET /hall-of-clowns
app.get('/hall-of-clowns', (req, res) => {
  const entries = db.prepare('SELECT * FROM hall_of_fame ORDER BY created_at DESC').all();
  res.send(renderPage('hof', { entries, req }));
});

// GET /rules
app.get('/rules', (req, res) => {
  res.send(renderPage('rules', { req }));
});

// GET /recent
app.get('/recent', (req, res) => {
  cleanExpired();
  const pastes = db.prepare(`
    SELECT id, title, author, syntax, views, created_at
    FROM pastes WHERE expiry = 0 OR expiry > ?
    ORDER BY created_at DESC LIMIT 100
  `).all(Date.now());
  res.send(renderPage('recent', { pastes, req }));
});

// ─── TEMPLATE ENGINE ─────────────────────────────────────────────────────────

function timeAgo(ts) {
  const diff = Date.now() - ts;
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function syntaxBadge(syntax) {
  const colors = {
    plaintext: '#666',
    javascript: '#f7df1e',
    python: '#3776ab',
    bash: '#4eaa25',
    sql: '#e38c00',
    html: '#e34c26',
    css: '#264de4',
    json: '#00bcd4',
    cpp: '#00549d',
    php: '#777bb3',
  };
  const c = colors[syntax] || '#666';
  return `<span class="syntax-badge" style="border-color:${c};color:${c}">${syntax}</span>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function pasteRow(p) {
  return `
    <tr class="paste-row">
      <td class="paste-title-cell">
        <a href="/paste/${escapeHtml(p.id)}" class="paste-link">${escapeHtml(p.title)}</a>
      </td>
      <td class="paste-author">${escapeHtml(p.author)}</td>
      <td>${syntaxBadge(p.syntax)}</td>
      <td class="paste-meta">${timeAgo(p.created_at)}</td>
      <td class="paste-views">${p.views} <span class="dim">views</span></td>
    </tr>`;
}

function layout(title, body, req) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${escapeHtml(title)} | SLOX BIN</title>
  <link rel="stylesheet" href="/style.css"/>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap" rel="stylesheet">
  <!-- Highlight.js -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/base16/monokai.min.css"/>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
</head>
<body>
  <div id="scanlines"></div>
  <nav class="navbar">
    <div class="nav-inner">
      <a href="/" class="logo">SLOX<span class="logo-accent">BIN</span></a>
      <div class="nav-links">
        <a href="/new" class="nav-link nav-cta">+ CREATE PASTE</a>
        <a href="/recent" class="nav-link">RECENT</a>
        <a href="/hall-of-clowns" class="nav-link">HALL OF CLOWNS</a>
        <a href="/rules" class="nav-link">RULES</a>
      </div>
    </div>
  </nav>
  <main class="main">
    ${body}
  </main>
  <footer class="footer">
    <span>SLOX BIN &copy; ${new Date().getFullYear()}</span>
    <span class="dim">|</span>
    <span class="dim">no logs. no mercy. no refunds.</span>
    <span class="dim">|</span>
    <a href="/rules" class="footer-link">rules</a>
  </footer>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      document.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el));
    });
  </script>
</body>
</html>`;
}

function renderPage(page, ctx) {
  const { req } = ctx;

  if (page === 'home') {
    const { pastes, pinned, q, stats } = ctx;
    const pinnedHtml = pinned.length ? `
      <section class="section">
        <h2 class="section-title"><span class="accent">//</span> PINNED</h2>
        <table class="paste-table">
          <thead><tr>
            <th>TITLE</th><th>AUTHOR</th><th>SYNTAX</th><th>POSTED</th><th>VIEWS</th>
          </tr></thead>
          <tbody>${pinned.map(pasteRow).join('')}</tbody>
        </table>
      </section>` : '';

    const pasteRows = pastes.length
      ? pastes.map(pasteRow).join('')
      : '<tr><td colspan="5" class="empty-row">no pastes found.</td></tr>';

    return layout('Home', `
      <div class="hero">
        <div class="hero-text">
          <h1 class="hero-title">SLOX<span class="accent">BIN</span></h1>
          <p class="hero-sub">underground paste service. no ads. no tracking. no bullshit.</p>
          <div class="hero-stats">
            <span class="stat-pill">${stats.total} pastes indexed</span>
          </div>
        </div>
        <form class="search-form" action="/" method="get">
          <input type="text" name="q" class="search-input" placeholder="search pastes..." value="${escapeHtml(q)}" autocomplete="off"/>
          <button type="submit" class="btn btn-search">SEARCH</button>
        </form>
        <a href="/new" class="btn btn-create-big">// CREATE NEW PASTE</a>
      </div>
      ${pinnedHtml}
      <section class="section">
        <h2 class="section-title">
          <span class="accent">//</span> ${q ? `RESULTS FOR "${escapeHtml(q)}"` : 'LATEST PASTES'}
        </h2>
        <table class="paste-table">
          <thead><tr>
            <th>TITLE</th><th>AUTHOR</th><th>SYNTAX</th><th>POSTED</th><th>VIEWS</th>
          </tr></thead>
          <tbody>${pasteRows}</tbody>
        </table>
      </section>
    `, req);
  }

  if (page === 'new') {
    const { error } = ctx;
    return layout('Create Paste', `
      <section class="section">
        <h2 class="section-title"><span class="accent">//</span> NEW PASTE</h2>
        ${error ? `<div class="alert-error">${escapeHtml(error)}</div>` : ''}
        <form class="paste-form" action="/new" method="post">
          <div class="form-row">
            <div class="form-group flex2">
              <label class="form-label">TITLE</label>
              <input type="text" name="title" class="form-input" placeholder="Untitled" maxlength="200"/>
            </div>
            <div class="form-group">
              <label class="form-label">AUTHOR</label>
              <input type="text" name="author" class="form-input" placeholder="Anonymous" maxlength="50"/>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">SYNTAX</label>
              <select name="syntax" class="form-select">
                <option value="plaintext">Plain Text</option>
                <option value="javascript">JavaScript</option>
                <option value="python">Python</option>
                <option value="bash">Bash/Shell</option>
                <option value="sql">SQL</option>
                <option value="html">HTML</option>
                <option value="css">CSS</option>
                <option value="json">JSON</option>
                <option value="cpp">C/C++</option>
                <option value="php">PHP</option>
                <option value="xml">XML</option>
                <option value="markdown">Markdown</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">EXPIRY</label>
              <select name="expiry" class="form-select">
                <option value="0">Never</option>
                <option value="1h">1 Hour</option>
                <option value="24h">24 Hours</option>
                <option value="7d">7 Days</option>
                <option value="30d">30 Days</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">PASSWORD <span class="dim">(optional)</span></label>
              <input type="password" name="password" class="form-input" placeholder="leave blank = public" maxlength="100"/>
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">CONTENT <span class="required">*</span></label>
            <textarea name="content" class="form-textarea" rows="22" placeholder="paste your content here..." required></textarea>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-submit">// SUBMIT PASTE</button>
            <a href="/" class="btn btn-cancel">CANCEL</a>
          </div>
        </form>
      </section>
    `, req);
  }

  if (page === 'paste') {
    const { paste } = ctx;
    const expiryInfo = paste.expiry > 0
      ? `<span class="meta-item warn">expires ${timeAgo(paste.created_at - paste.expiry + Date.now())}</span>`
      : `<span class="meta-item">never expires</span>`;

    const lineCount = paste.content.split('\n').length;

    return layout(paste.title, `
      <section class="section">
        <div class="paste-header">
          <div>
            <h1 class="paste-title-big">${escapeHtml(paste.title)}</h1>
            <div class="paste-meta-bar">
              <span class="meta-item">by <strong>${escapeHtml(paste.author)}</strong></span>
              <span class="meta-sep">·</span>
              <span class="meta-item">${timeAgo(paste.created_at)}</span>
              <span class="meta-sep">·</span>
              ${syntaxBadge(paste.syntax)}
              <span class="meta-sep">·</span>
              <span class="meta-item">${paste.views} views</span>
              <span class="meta-sep">·</span>
              <span class="meta-item">${lineCount} lines</span>
              <span class="meta-sep">·</span>
              ${expiryInfo}
            </div>
          </div>
          <div class="paste-actions">
            <button class="btn btn-sm" onclick="copyPaste()">COPY</button>
            <a href="/paste/${escapeHtml(paste.id)}/raw" class="btn btn-sm" target="_blank">RAW</a>
            <a href="/new" class="btn btn-sm btn-accent">+ FORK</a>
          </div>
        </div>
        <div class="paste-content-wrapper">
          <div class="line-numbers" id="lineNums"></div>
          <pre class="paste-pre"><code class="language-${escapeHtml(paste.syntax)}" id="pasteCode">${escapeHtml(paste.content)}</code></pre>
        </div>
        <div id="copy-toast" class="copy-toast">COPIED TO CLIPBOARD</div>
      </section>
      <script>
        function copyPaste() {
          const text = document.getElementById('pasteCode').innerText;
          navigator.clipboard.writeText(text).then(() => {
            const t = document.getElementById('copy-toast');
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 1800);
          });
        }
        window.addEventListener('DOMContentLoaded', () => {
          const code = document.getElementById('pasteCode');
          const lines = code.innerText.split('\\n').length;
          const nums = document.getElementById('lineNums');
          let html = '';
          for (let i = 1; i <= lines; i++) html += '<span>' + i + '</span>';
          nums.innerHTML = html;
        });
      </script>
    `, req);
  }

  if (page === 'password') {
    const { id, error } = ctx;
    return layout('Password Required', `
      <section class="section center-section">
        <div class="password-box">
          <div class="lock-icon">🔒</div>
          <h2 class="section-title"><span class="accent">//</span> PASSWORD REQUIRED</h2>
          <p class="dim">This paste is locked.</p>
          ${error ? `<div class="alert-error">${escapeHtml(error)}</div>` : ''}
          <form action="/paste/${escapeHtml(id)}/password" method="post">
            <input type="password" name="password" class="form-input" placeholder="enter password" autofocus/>
            <button type="submit" class="btn btn-submit" style="margin-top:1rem;width:100%">UNLOCK</button>
          </form>
        </div>
      </section>
    `, req);
  }

  if (page === 'hof') {
    const { entries } = ctx;
    const categoryLabel = { legend: '👑 LEGEND', big_brain: '🧠 BIG BRAIN', grinder: '⚡ GRINDER' };
    const rows = entries.map(e => `
      <tr class="paste-row">
        <td><span class="hof-rank">#${e.id}</span></td>
        <td><strong class="accent">${escapeHtml(e.username)}</strong></td>
        <td>${e.paste_id ? `<a href="/paste/${escapeHtml(e.paste_id)}" class="paste-link">${escapeHtml(e.title)}</a>` : escapeHtml(e.title)}</td>
        <td><span class="category-badge">${categoryLabel[e.category] || e.category}</span></td>
        <td class="paste-meta">${timeAgo(e.created_at)}</td>
      </tr>`).join('');

    return layout('Hall of Clowns', `
      <section class="section">
        <h2 class="section-title"><span class="accent">//</span> HALL OF CLOWNS</h2>
        <p class="section-desc dim">the biggest clowns to ever grace this platform. you know who you are.</p>
        <table class="paste-table">
          <thead><tr>
            <th>RANK</th><th>HANDLE</th><th>CLAIM TO FAME</th><th>CATEGORY</th><th>INDUCTED</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </section>
    `, req);
  }

  if (page === 'rules') {
    return layout('Rules', `
      <section class="section rules-section">
        <h2 class="section-title"><span class="accent">//</span> RULES</h2>
        <p class="dim section-desc">break these and you're gone. simple.</p>
        <ol class="rules-list">
          <li><span class="rule-num">01.</span> No posting personal information of minors. Zero tolerance.</li>
          <li><span class="rule-num">02.</span> No malware distribution disguised as legitimate content.</li>
          <li><span class="rule-num">03.</span> No spam. One paste at a time, you absolute gremlin.</li>
          <li><span class="rule-num">04.</span> No CSAM. Instant permaban + report. No exceptions ever.</li>
          <li><span class="rule-num">05.</span> Keep it text-based. This is a paste site, not imgur.</li>
          <li><span class="rule-num">06.</span> Don't post content that gets the whole site taken down. Use your head.</li>
          <li><span class="rule-num">07.</span> Passwords on pastes don't mean you can post whatever you want.</li>
          <li><span class="rule-num">08.</span> If you find a bug, report it. Don't be that guy.</li>
        </ol>
        <div class="rules-footer">
          <p class="dim">Admins reserve the right to remove any content at any time.</p>
          <p class="dim">This site is provided as-is. You use it at your own risk.</p>
        </div>
      </section>
    `, req);
  }

  if (page === 'recent') {
    const { pastes } = ctx;
    const pasteRows = pastes.length
      ? pastes.map(pasteRow).join('')
      : '<tr><td colspan="5" class="empty-row">nothing here yet.</td></tr>';
    return layout('Recent Pastes', `
      <section class="section">
        <h2 class="section-title"><span class="accent">//</span> RECENT PASTES</h2>
        <table class="paste-table">
          <thead><tr>
            <th>TITLE</th><th>AUTHOR</th><th>SYNTAX</th><th>POSTED</th><th>VIEWS</th>
          </tr></thead>
          <tbody>${pasteRows}</tbody>
        </table>
      </section>
    `, req);
  }

  if (page === '404') {
    return layout('404', `
      <section class="section center-section">
        <div class="error-box">
          <div class="error-code">404</div>
          <p class="error-msg">paste not found or expired.</p>
          <a href="/" class="btn btn-submit" style="margin-top:1.5rem">← BACK HOME</a>
        </div>
      </section>
    `, req);
  }

  return layout('Error', '<p>Unknown page.</p>', req);
}

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ███████╗██╗      ██████╗ ██╗  ██╗    ██████╗ ██╗███╗   ██╗`);
  console.log(`  ██╔════╝██║     ██╔═══██╗╚██╗██╔╝    ██╔══██╗██║████╗  ██║`);
  console.log(`  ███████╗██║     ██║   ██║ ╚███╔╝     ██████╔╝██║██╔██╗ ██║`);
  console.log(`  ╚════██║██║     ██║   ██║ ██╔██╗     ██╔══██╗██║██║╚██╗██║`);
  console.log(`  ███████║███████╗╚██████╔╝██╔╝ ██╗    ██████╔╝██║██║ ╚████║`);
  console.log(`  ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═══╝`);
  console.log(`\n  running on http://localhost:${PORT}\n`);
});
