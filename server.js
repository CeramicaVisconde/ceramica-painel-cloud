const express = require('express');
const crypto  = require('crypto');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT           = process.env.PORT || 3001;
const PAINEL_SECRET  = process.env.PAINEL_SECRET  || '';
const OWNER_PIN      = process.env.OWNER_PIN      || '1234';
const SESSION_SECRET = process.env.SESSION_SECRET || 'painel-session-secret';

let snapshot = null; // dados mais recentes enviados pela fabrica

// ── helpers ──────────────────────────────────────────────────────────────────

function makeToken(pin) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(pin).digest('hex');
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v || '');
  }
  return null;
}

function isAuthed(req) {
  const tok = getCookie(req, 'painel_tok');
  return tok === makeToken(OWNER_PIN);
}

function fmtBRL(v) {
  return Number(v || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

function fmtData(iso) {
  if (!iso) return '—';
  const [y, m, d] = iso.slice(0, 10).split('-');
  return `${d}/${m}/${y}`;
}

// ── recebimento de dados da fabrica ──────────────────────────────────────────

app.post('/sync', (req, res) => {
  if (req.headers['x-painel-secret'] !== PAINEL_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  snapshot = { ...req.body, recebido_em: new Date().toISOString() };
  res.json({ ok: true });
});

// ── auth do dono ─────────────────────────────────────────────────────────────

app.get('/painel/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/painel');
  res.send(loginPage());
});

app.post('/painel/login', (req, res) => {
  const pin = String(req.body.pin || '').trim();
  if (pin !== OWNER_PIN) {
    return res.send(loginPage('PIN incorreto'));
  }
  const tok = makeToken(pin);
  const maxAge = 7 * 24 * 3600;
  res.setHeader('Set-Cookie', `painel_tok=${tok}; Max-Age=${maxAge}; HttpOnly; SameSite=Strict; Path=/`);
  res.redirect('/painel');
});

app.get('/painel/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'painel_tok=; Max-Age=0; Path=/');
  res.redirect('/painel/login');
});

// ── API de dados (usada pelo JS do painel) ────────────────────────────────────

app.get('/painel/dados', (req, res) => {
  if (!isAuthed(req)) return res.status(401).json({ error: 'Unauthorized' });
  res.json(snapshot || null);
});

// ── painel principal ──────────────────────────────────────────────────────────

app.get(['/painel', '/'], (req, res) => {
  if (!isAuthed(req)) return res.redirect('/painel/login');
  res.send(painelPage());
});

// ── start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => console.log(`Painel cloud rodando na porta ${PORT}`));

// ── HTML: login ───────────────────────────────────────────────────────────────

function loginPage(erro) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel — Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0f172a;font-family:system-ui,sans-serif}
.card{background:#1e293b;border-radius:16px;padding:40px 32px;width:100%;max-width:360px;
      box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{color:#f1f5f9;font-size:1.4rem;margin-bottom:8px;text-align:center}
p.sub{color:#94a3b8;font-size:.85rem;text-align:center;margin-bottom:28px}
input{width:100%;padding:14px 16px;border-radius:10px;border:1px solid #334155;
      background:#0f172a;color:#f1f5f9;font-size:1.1rem;letter-spacing:6px;
      text-align:center;outline:none;margin-bottom:16px}
input:focus{border-color:#6366f1}
button{width:100%;padding:14px;border-radius:10px;border:none;
       background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;
       font-size:1rem;font-weight:600;cursor:pointer}
button:hover{opacity:.9}
.erro{color:#f87171;text-align:center;margin-bottom:12px;font-size:.9rem}
</style>
</head>
<body>
<div class="card">
  <h1>🏭 Cerâmica Visconde</h1>
  <p class="sub">Painel do Proprietário</p>
  ${erro ? `<p class="erro">${erro}</p>` : ''}
  <form method="POST" action="/painel/login">
    <input type="password" name="pin" placeholder="••••" autofocus inputmode="numeric">
    <button type="submit">Entrar</button>
  </form>
</div>
</body>
</html>`;
}

// ── HTML: painel ──────────────────────────────────────────────────────────────

function painelPage() {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel — Cerâmica Visconde</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;color:#f1f5f9;font-family:system-ui,sans-serif;padding-bottom:40px}
header{background:#1e293b;padding:16px 20px;display:flex;align-items:center;
       justify-content:space-between;border-bottom:1px solid #334155;position:sticky;top:0;z-index:10}
header h1{font-size:1rem;font-weight:700}
.sync-badge{font-size:.7rem;color:#94a3b8;background:#0f172a;
            padding:4px 8px;border-radius:20px}
.logout{font-size:.75rem;color:#64748b;text-decoration:none}
.logout:hover{color:#f87171}
.container{padding:16px}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px}
.card{background:#1e293b;border-radius:14px;padding:16px}
.card .label{font-size:.7rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.card .valor{font-size:1.3rem;font-weight:700}
.card.verde .valor{color:#4ade80}
.card.vermelho .valor{color:#f87171}
.card.amarelo .valor{color:#fbbf24}
.card.azul .valor{color:#60a5fa}
.section{background:#1e293b;border-radius:14px;padding:16px;margin-bottom:16px}
.section h2{font-size:.85rem;font-weight:700;color:#94a3b8;text-transform:uppercase;
            letter-spacing:.5px;margin-bottom:12px}
.item{padding:10px 0;border-bottom:1px solid #334155;display:flex;
      justify-content:space-between;align-items:center;gap:8px}
.item:last-child{border-bottom:none}
.item-nome{font-size:.85rem;flex:1;min-width:0}
.item-nome .sub{font-size:.72rem;color:#64748b;margin-top:2px;
                white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item-valor{font-size:.9rem;font-weight:700;white-space:nowrap}
.badge{font-size:.65rem;padding:2px 7px;border-radius:10px;font-weight:600;white-space:nowrap}
.badge.vencido{background:#7f1d1d;color:#fca5a5}
.badge.pendente{background:#1e3a5f;color:#93c5fd}
.prioridade-alta{border-left:3px solid #f87171;padding-left:8px}
.prioridade-media{border-left:3px solid #fbbf24;padding-left:8px}
.prioridade-baixa{border-left:3px solid #4ade80;padding-left:8px}
.empty{color:#64748b;font-size:.85rem;text-align:center;padding:20px 0}
.loading{text-align:center;padding:60px 20px;color:#64748b}
</style>
</head>
<body>
<header>
  <h1>🏭 Cerâmica Visconde</h1>
  <span class="sync-badge" id="sync-badge">aguardando...</span>
  <a href="/painel/logout" class="logout">Sair</a>
</header>
<div class="container" id="conteudo">
  <div class="loading">Carregando dados...</div>
</div>

<script>
function fmtBRL(v){
  return Number(v||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
}
function fmtData(iso){
  if(!iso) return '—';
  const [y,m,d]=iso.slice(0,10).split('-');
  return d+'/'+m+'/'+y;
}
function fmtHora(iso){
  if(!iso) return '';
  const d=new Date(iso);
  return d.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
}

async function carregar(){
  try{
    const r=await fetch('/painel/dados');
    if(r.status===401){location.href='/painel/login';return;}
    const dados=await r.json();
    renderizar(dados);
  }catch(e){
    document.getElementById('conteudo').innerHTML=
      '<div class="loading">Erro ao carregar dados.</div>';
  }
}

function renderizar(d){
  const badge=document.getElementById('sync-badge');
  if(!d){
    badge.textContent='sem dados';
    document.getElementById('conteudo').innerHTML=
      '<div class="loading" style="padding-top:80px">⏳ Aguardando o primeiro envio de dados da fábrica...</div>';
    return;
  }

  const recebidoEm=new Date(d.recebido_em);
  badge.textContent='Sync: '+recebidoEm.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});

  const t=d.totais||{};
  const aReceber=d.a_receber||[];
  const aPagar=d.a_pagar||[];
  const tarefas=d.tarefas||[];

  const html=\`
    <div class="cards">
      <div class="card verde">
        <div class="label">A Receber</div>
        <div class="valor">\${fmtBRL(t.a_receber)}</div>
      </div>
      <div class="card vermelho">
        <div class="label">A Pagar</div>
        <div class="valor">\${fmtBRL(t.a_pagar)}</div>
      </div>
      <div class="card amarelo">
        <div class="label">Vencido</div>
        <div class="valor">\${fmtBRL(t.vencido)}</div>
      </div>
      <div class="card azul">
        <div class="label">Saldo do Mês</div>
        <div class="valor">\${fmtBRL(t.saldo_mes)}</div>
      </div>
    </div>

    <div class="section">
      <h2>📥 Contas a Receber</h2>
      \${aReceber.length===0
        ? '<p class="empty">Nenhuma conta pendente</p>'
        : aReceber.map(c=>\`
          <div class="item">
            <div class="item-nome">
              \${c.descricao||'—'}
              <div class="sub">\${c.cliente_nome||''} · \${fmtData(c.vencimento)}</div>
            </div>
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">
              <span class="item-valor" style="color:#4ade80">\${fmtBRL(c.valor)}</span>
              <span class="badge \${c.status}">\${c.status}</span>
            </div>
          </div>\`).join('')}
    </div>

    <div class="section">
      <h2>📤 Contas a Pagar</h2>
      \${aPagar.length===0
        ? '<p class="empty">Nenhuma conta pendente</p>'
        : aPagar.map(c=>\`
          <div class="item">
            <div class="item-nome">
              \${c.descricao||'—'}
              <div class="sub">\${c.cliente_nome||''} · \${fmtData(c.vencimento)}</div>
            </div>
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">
              <span class="item-valor" style="color:#f87171">\${fmtBRL(c.valor)}</span>
              <span class="badge \${c.status}">\${c.status}</span>
            </div>
          </div>\`).join('')}
    </div>

    <div class="section">
      <h2>✅ Tarefas Ativas</h2>
      \${tarefas.length===0
        ? '<p class="empty">Nenhuma tarefa ativa</p>'
        : tarefas.map(t=>\`
          <div class="item prioridade-\${t.prioridade||'baixa'}">
            <div class="item-nome">
              \${t.titulo||'—'}
              <div class="sub">\${fmtData(t.data)}</div>
            </div>
            <span class="badge" style="background:#1e3a5f;color:#93c5fd">\${t.prioridade||'—'}</span>
          </div>\`).join('')}
    </div>
  \`;

  document.getElementById('conteudo').innerHTML=html;
}

carregar();
setInterval(carregar, 5*60*1000);
</script>
</body>
</html>`;
}
