const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT           = process.env.PORT           || 3001;
const PAINEL_SECRET  = process.env.PAINEL_SECRET  || '';
const OWNER_PIN      = process.env.OWNER_PIN      || '1234';
const SESSION_SECRET = process.env.SESSION_SECRET || 'painel-session-secret';

let snapshots = {};

function makeToken(pin) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(pin).digest('hex');
}
function getCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const [k, v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v || '');
  }
  return null;
}
function isAuthed(req) {
  return getCookie(req, 'painel_tok') === makeToken(OWNER_PIN);
}

app.post('/sync', (req, res) => {
  if (req.headers['x-painel-secret'] !== PAINEL_SECRET)
    return res.status(401).json({ error: 'Unauthorized' });
  const dados = req.body;
  const nome  = dados.empresa || 'Empresa';
  snapshots[nome] = { ...dados, recebido_em: new Date().toISOString() };
  console.log(`[sync] ${nome} — ${new Date().toLocaleTimeString('pt-BR')}`);
  res.json({ ok: true });
});

app.get('/painel/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/painel');
  res.send(loginPage());
});
app.post('/painel/login', (req, res) => {
  const pin = String(req.body.pin || '').trim();
  if (pin !== OWNER_PIN) return res.send(loginPage('PIN incorreto'));
  res.setHeader('Set-Cookie',
    `painel_tok=${makeToken(pin)}; Max-Age=${7*24*3600}; HttpOnly; SameSite=Strict; Path=/`);
  res.redirect('/painel');
});
app.get('/painel/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'painel_tok=; Max-Age=0; Path=/');
  res.redirect('/painel/login');
});
app.get('/painel/empresas', (req, res) => {
  if (!isAuthed(req)) return res.status(401).json({ error: 'Unauthorized' });
  const lista = Object.entries(snapshots).map(([nome, d]) => ({
    nome, recebido_em: d.recebido_em,
    a_receber: d.totais?.a_receber || 0,
    a_pagar:   d.totais?.a_pagar   || 0,
    vencido:   d.totais?.vencido   || 0,
  }));
  res.json(lista);
});
app.get('/painel/dados/:empresa', (req, res) => {
  if (!isAuthed(req)) return res.status(401).json({ error: 'Unauthorized' });
  const d = snapshots[decodeURIComponent(req.params.empresa)];
  if (!d) return res.status(404).json({ error: 'Empresa nao encontrada' });
  res.json(d);
});
app.get(['/painel', '/'], (req, res) => {
  if (!isAuthed(req)) return res.redirect('/painel/login');
  res.send(painelPage());
});

app.listen(PORT, () => console.log(`Painel cloud na porta ${PORT}`));

// ── ESTILOS COMPARTILHADOS ────────────────────────────────────────────────────

const FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="icon" href="/favicon.ico">`;

const BASE_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0D0D0D;color:#EDEDED;font-family:'Outfit',system-ui,sans-serif;
     -webkit-font-smoothing:antialiased;min-height:100vh}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.15);border-radius:4px}
`;

// ── LOGIN ─────────────────────────────────────────────────────────────────────

function loginPage(erro) {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel — Cerâmica Visconde</title>${FONTS}
<style>
${BASE_CSS}
body{display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#141414;border:1px solid rgba(255,255,255,.08);border-radius:20px;
      padding:40px 32px;width:100%;max-width:380px;box-shadow:0 24px 64px rgba(0,0,0,.8)}
.logo-wrap{display:flex;flex-direction:column;align-items:center;margin-bottom:28px;gap:14px}
.logo-wrap img{height:56px;object-fit:contain;filter:drop-shadow(0 2px 8px rgba(255,212,0,.2))}
.logo-wrap h1{font-size:1.1rem;font-weight:700;color:#EDEDED;text-align:center;line-height:1.3}
.logo-wrap p{font-size:.8rem;color:#6b7280;text-align:center}
label{display:block;font-size:.72rem;color:#9CA3AF;font-weight:600;
      text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
input{width:100%;padding:16px;border-radius:12px;border:1px solid rgba(255,255,255,.1);
      background:#1c1c1c;color:#EDEDED;font-size:1.5rem;letter-spacing:10px;
      font-family:'Outfit',sans-serif;text-align:center;outline:none;
      margin-bottom:16px;transition:border .2s}
input:focus{border-color:#FFD400;box-shadow:0 0 0 3px rgba(255,212,0,.1)}
button{width:100%;padding:16px;border-radius:12px;border:none;
       background:#FFD400;color:#0D0D0D;font-size:.95rem;font-weight:700;
       font-family:'Outfit',sans-serif;cursor:pointer;letter-spacing:.2px;
       transition:opacity .15s,transform .1s}
button:hover{opacity:.9}
button:active{transform:scale(.98)}
.erro{color:#f87171;text-align:center;margin-bottom:14px;font-size:.85rem;
      background:rgba(248,113,113,.1);padding:10px;border-radius:10px;
      border:1px solid rgba(248,113,113,.2)}
</style></head><body>
<div class="card">
  <div class="logo-wrap">
    <img src="/logo.png" alt="Cerâmica Visconde">
    <div>
      <h1>Cerâmica Visconde</h1>
      <p>Painel do Proprietário</p>
    </div>
  </div>
  ${erro ? `<p class="erro">${erro}</p>` : ''}
  <form method="POST" action="/painel/login">
    <label>PIN de acesso</label>
    <input type="password" name="pin" placeholder="••••" autofocus inputmode="numeric" maxlength="8">
    <button type="submit">Entrar</button>
  </form>
</div>
</body></html>`;
}

// ── PAINEL ────────────────────────────────────────────────────────────────────

function painelPage() {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel — Cerâmica Visconde</title>${FONTS}
<style>
${BASE_CSS}
body{padding-bottom:48px}

/* header */
header{background:#141414;height:56px;padding:0 16px;display:flex;align-items:center;
       justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.08);
       position:sticky;top:0;z-index:10;gap:10px}
.hd-logo{display:flex;align-items:center;gap:10px;min-width:0}
.hd-logo img{height:32px;object-fit:contain}
.hd-logo span{font-size:.9rem;font-weight:700;color:#EDEDED;
              white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sync-badge{font-size:.65rem;color:#9CA3AF;background:#1c1c1c;
            padding:3px 9px;border-radius:20px;border:1px solid rgba(255,255,255,.08);
            white-space:nowrap;flex-shrink:0}
.sync-badge.ok{color:#34d472;border-color:rgba(52,212,114,.3)}
.logout{font-size:.75rem;color:#6b7280;text-decoration:none;padding:5px 10px;
        border-radius:8px;border:1px solid rgba(255,255,255,.08);
        transition:color .2s,border-color .2s;white-space:nowrap;flex-shrink:0}
.logout:hover{color:#f87171;border-color:rgba(248,113,113,.3)}

.container{padding:14px;max-width:600px;margin:0 auto}

/* cards de totais */
.cards{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.card{background:#141414;border:1px solid rgba(255,255,255,.08);
      border-radius:14px;padding:16px}
.card .lbl{font-size:.65rem;color:#9CA3AF;text-transform:uppercase;
           letter-spacing:.6px;font-weight:600;margin-bottom:8px}
.card .val{font-size:1.2rem;font-weight:700;letter-spacing:-.5px}
.card.amarelo{border-color:rgba(255,212,0,.15)}
.card.amarelo .val{color:#FFD400}
.card.verde .val{color:#34d472}
.card.vermelho .val{color:#f87171}
.card.azul .val{color:#60a5fa}

/* empresa cards */
.emp-card{background:#141414;border:1px solid rgba(255,255,255,.08);
          border-radius:14px;padding:16px;margin-bottom:10px;cursor:pointer;
          display:flex;justify-content:space-between;align-items:center;gap:12px;
          transition:border-color .2s,background .2s}
.emp-card:hover{border-color:rgba(255,212,0,.4);background:#1a1900}
.emp-card:active{transform:scale(.99)}
.emp-nome{font-size:.95rem;font-weight:600;color:#EDEDED}
.emp-sync{font-size:.7rem;color:#6b7280;margin-top:3px}
.emp-vals .rec{font-size:.9rem;font-weight:700;color:#34d472;text-align:right}
.emp-vals .pag{font-size:.72rem;color:#f87171;margin-top:2px;text-align:right}
.emp-arrow{color:#6b7280;font-size:1rem;flex-shrink:0}

/* seções */
.section{background:#141414;border:1px solid rgba(255,255,255,.08);
         border-radius:14px;padding:16px;margin-bottom:12px}
.sec-title{font-size:.7rem;font-weight:700;color:#6b7280;text-transform:uppercase;
           letter-spacing:.6px;margin-bottom:12px}
.item{padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05);
      display:flex;justify-content:space-between;align-items:center;gap:10px}
.item:last-child{border-bottom:none;padding-bottom:0}
.item-info{flex:1;min-width:0}
.item-nome{font-size:.85rem;font-weight:500;white-space:nowrap;
           overflow:hidden;text-overflow:ellipsis}
.item-sub{font-size:.7rem;color:#6b7280;margin-top:2px;
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item-right{display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0}
.item-val{font-size:.88rem;font-weight:700}
.badge{font-size:.6rem;padding:2px 7px;border-radius:20px;font-weight:700;
       text-transform:uppercase;letter-spacing:.3px}
.badge.vencido{background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.2)}
.badge.pendente{background:rgba(96,165,250,.1);color:#60a5fa;border:1px solid rgba(96,165,250,.2)}
.badge.alta{background:rgba(248,113,113,.12);color:#f87171}
.badge.media{background:rgba(255,212,0,.1);color:#FFD400}
.badge.baixa{background:rgba(52,212,114,.1);color:#34d472}
.p-alta{border-left:3px solid #f87171;padding-left:10px}
.p-media{border-left:3px solid #FFD400;padding-left:10px}
.p-baixa{border-left:3px solid #34d472;padding-left:10px}

.btn-back{display:inline-flex;align-items:center;gap:6px;margin-bottom:14px;
          font-size:.8rem;color:#9CA3AF;cursor:pointer;padding:7px 12px;
          border-radius:10px;border:1px solid rgba(255,255,255,.08);
          background:#141414;transition:color .2s,border-color .2s}
.btn-back:hover{color:#FFD400;border-color:rgba(255,212,0,.3)}
.tela-label{font-size:.7rem;color:#6b7280;text-transform:uppercase;
            letter-spacing:.6px;font-weight:600;margin-bottom:10px}
.empty{color:#6b7280;font-size:.82rem;text-align:center;padding:20px 0}
.loading{text-align:center;padding:60px 20px;color:#6b7280}
.waiting{text-align:center;padding:60px 20px}
.waiting .icon{font-size:3rem;margin-bottom:16px}
.waiting p{color:#6b7280;font-size:.9rem;line-height:1.6}
</style></head><body>

<header>
  <div class="hd-logo">
    <img src="/logo.png" alt="Logo">
    <span>Cerâmica Visconde</span>
  </div>
  <span class="sync-badge" id="sync-badge">carregando...</span>
  <a href="/painel/logout" class="logout">Sair</a>
</header>

<div class="container">
  <div id="tela-empresas"><div class="loading">Carregando...</div></div>
  <div id="tela-detalhe" style="display:none">
    <div class="btn-back" id="btn-back">← Voltar</div>
    <div id="det-conteudo"></div>
  </div>
</div>

<script>
const fmt = v => Number(v||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
const fmtD = iso => {
  if(!iso) return '—';
  const [y,m,d] = iso.slice(0,10).split('-');
  return d+'/'+m+'/'+y;
};
const fmtH = iso => iso ? new Date(iso).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}) : '';

let empAtual = null;

async function carregarEmpresas() {
  try {
    const r = await fetch('/painel/empresas');
    if(r.status===401){location.href='/painel/login';return;}
    renderEmpresas(await r.json());
  } catch(e) {
    document.getElementById('tela-empresas').innerHTML =
      '<div class="loading">Erro ao carregar. Tente novamente.</div>';
  }
}

function renderEmpresas(lista) {
  const badge = document.getElementById('sync-badge');
  if(!lista.length) {
    badge.textContent = 'sem dados';
    document.getElementById('tela-empresas').innerHTML = \`
      <div class="waiting">
        <div class="icon">⏳</div>
        <p>Aguardando o primeiro envio de dados da fábrica...<br><br>
        O sistema instalado no PC da empresa enviará os dados automaticamente em alguns minutos.</p>
      </div>\`;
    return;
  }
  badge.textContent = lista.length + ' empresa' + (lista.length>1?'s':'');
  badge.className = 'sync-badge ok';
  document.getElementById('tela-empresas').innerHTML =
    '<p class="tela-label">Selecione a empresa</p>' +
    lista.map(e => \`
      <div class="emp-card" onclick="abrirEmpresa('\${encodeURIComponent(e.nome)}','\${e.nome}')">
        <div>
          <div class="emp-nome">\${e.nome}</div>
          <div class="emp-sync">Atualizado às \${fmtH(e.recebido_em)}</div>
        </div>
        <div class="emp-vals">
          <div class="rec">\${fmt(e.a_receber)}</div>
          <div class="pag">↑ pagar \${fmt(e.a_pagar)}</div>
        </div>
        <div class="emp-arrow">›</div>
      </div>\`).join('');
}

async function abrirEmpresa(slug, nome) {
  empAtual = {slug, nome};
  document.getElementById('tela-empresas').style.display = 'none';
  document.getElementById('tela-detalhe').style.display  = '';
  document.getElementById('det-conteudo').innerHTML = '<div class="loading">Carregando...</div>';
  try {
    const r = await fetch('/painel/dados/'+slug);
    if(r.status===401){location.href='/painel/login';return;}
    renderDetalhe(await r.json());
  } catch(e) {
    document.getElementById('det-conteudo').innerHTML = '<div class="loading">Erro ao carregar.</div>';
  }
}

function renderDetalhe(d) {
  const badge = document.getElementById('sync-badge');
  badge.textContent = 'Sync ' + fmtH(d.recebido_em);
  badge.className = 'sync-badge ok';
  const tot = d.totais||{}, rec = d.a_receber||[], pag = d.a_pagar||[], tar = d.tarefas||[];
  document.getElementById('det-conteudo').innerHTML = \`
    <div class="cards">
      <div class="card verde"><div class="lbl">A Receber</div><div class="val">\${fmt(tot.a_receber)}</div></div>
      <div class="card vermelho"><div class="lbl">A Pagar</div><div class="val">\${fmt(tot.a_pagar)}</div></div>
      <div class="card amarelo"><div class="lbl">Vencido</div><div class="val">\${fmt(tot.vencido)}</div></div>
      <div class="card azul"><div class="lbl">Saldo do Mês</div><div class="val">\${fmt(tot.saldo_mes)}</div></div>
    </div>
    <div class="section">
      <div class="sec-title">📥 Contas a Receber</div>
      \${!rec.length ? '<p class="empty">Nenhuma conta pendente</p>' : rec.map(c=>\`
        <div class="item">
          <div class="item-info">
            <div class="item-nome">\${c.descricao||'—'}</div>
            <div class="item-sub">\${[c.cliente_nome,fmtD(c.vencimento)].filter(Boolean).join(' · ')}</div>
          </div>
          <div class="item-right">
            <span class="item-val" style="color:#34d472">\${fmt(c.valor)}</span>
            <span class="badge \${c.status}">\${c.status}</span>
          </div>
        </div>\`).join('')}
    </div>
    <div class="section">
      <div class="sec-title">📤 Contas a Pagar</div>
      \${!pag.length ? '<p class="empty">Nenhuma conta pendente</p>' : pag.map(c=>\`
        <div class="item">
          <div class="item-info">
            <div class="item-nome">\${c.descricao||'—'}</div>
            <div class="item-sub">\${[c.cliente_nome,fmtD(c.vencimento)].filter(Boolean).join(' · ')}</div>
          </div>
          <div class="item-right">
            <span class="item-val" style="color:#f87171">\${fmt(c.valor)}</span>
            <span class="badge \${c.status}">\${c.status}</span>
          </div>
        </div>\`).join('')}
    </div>
    <div class="section">
      <div class="sec-title">✅ Tarefas Ativas</div>
      \${!tar.length ? '<p class="empty">Nenhuma tarefa ativa</p>' : tar.map(t=>\`
        <div class="item p-\${t.prioridade||'baixa'}">
          <div class="item-info">
            <div class="item-nome">\${t.titulo||'—'}</div>
            <div class="item-sub">\${fmtD(t.data)}</div>
          </div>
          <span class="badge \${t.prioridade||'baixa'}">\${t.prioridade||'—'}</span>
        </div>\`).join('')}
    </div>\`;
}

document.getElementById('btn-back').addEventListener('click', () => {
  empAtual = null;
  document.getElementById('tela-detalhe').style.display  = 'none';
  document.getElementById('tela-empresas').style.display = '';
  document.getElementById('sync-badge').textContent = 'carregando...';
  document.getElementById('sync-badge').className   = 'sync-badge';
  carregarEmpresas();
});

carregarEmpresas();
setInterval(() => {
  if(empAtual) abrirEmpresa(empAtual.slug, empAtual.nome);
  else carregarEmpresas();
}, 5*60*1000);
</script>
</body></html>`;
}
