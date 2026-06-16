const express = require('express');
const crypto  = require('crypto');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT           = process.env.PORT || 3001;
const PAINEL_SECRET  = process.env.PAINEL_SECRET  || '';
const OWNER_PIN      = process.env.OWNER_PIN      || '1234';
const SESSION_SECRET = process.env.SESSION_SECRET || 'painel-session-secret';

let snapshot = null;

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
  return getCookie(req, 'painel_tok') === makeToken(OWNER_PIN);
}

app.post('/sync', (req, res) => {
  if (req.headers['x-painel-secret'] !== PAINEL_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  snapshot = { ...req.body, recebido_em: new Date().toISOString() };
  res.json({ ok: true });
});

app.get('/painel/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/painel');
  res.send(loginPage());
});

app.post('/painel/login', (req, res) => {
  const pin = String(req.body.pin || '').trim();
  if (pin !== OWNER_PIN) return res.send(loginPage('PIN incorreto'));
  const tok = makeToken(pin);
  res.setHeader('Set-Cookie', `painel_tok=${tok}; Max-Age=${7*24*3600}; HttpOnly; SameSite=Strict; Path=/`);
  res.redirect('/painel');
});

app.get('/painel/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'painel_tok=; Max-Age=0; Path=/');
  res.redirect('/painel/login');
});

app.get('/painel/dados', (req, res) => {
  if (!isAuthed(req)) return res.status(401).json({ error: 'Unauthorized' });
  res.json(snapshot || null);
});

app.get(['/painel', '/'], (req, res) => {
  if (!isAuthed(req)) return res.redirect('/painel/login');
  res.send(painelPage());
});

app.listen(PORT, () => console.log(`Painel cloud rodando na porta ${PORT}`));

// ── LOGIN ─────────────────────────────────────────────────────────────────────

function loginPage(erro) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel — Cerâmica Visconde</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0D0D0D;font-family:'Outfit',system-ui,sans-serif;
     -webkit-font-smoothing:antialiased}
.card{background:#141414;border:1px solid rgba(255,255,255,.08);
      border-radius:16px;padding:40px 32px;width:100%;max-width:360px;
      box-shadow:0 16px 48px rgba(0,0,0,.8)}
.logo{display:flex;align-items:center;gap:10px;justify-content:center;margin-bottom:8px}
.logo-icon{width:36px;height:36px;background:#FFD400;border-radius:8px;
           display:flex;align-items:center;justify-content:center;font-size:18px}
h1{color:#EDEDED;font-size:1.1rem;font-weight:700;text-align:center}
p.sub{color:#6b7280;font-size:.82rem;text-align:center;margin-bottom:28px;margin-top:4px}
label{display:block;font-size:.75rem;color:#9CA3AF;font-weight:600;
      text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
input{width:100%;padding:14px 16px;border-radius:10px;
      border:1px solid rgba(255,255,255,.08);background:#1c1c1c;
      color:#EDEDED;font-size:1.4rem;letter-spacing:8px;font-family:'Outfit',sans-serif;
      text-align:center;outline:none;margin-bottom:16px;transition:border .2s}
input:focus{border-color:#FFD400}
button{width:100%;padding:14px;border-radius:10px;border:none;
       background:#FFD400;color:#0D0D0D;
       font-size:.95rem;font-weight:700;font-family:'Outfit',sans-serif;
       cursor:pointer;letter-spacing:.3px;transition:opacity .2s}
button:hover{opacity:.88}
.erro{color:#f87171;text-align:center;margin-bottom:12px;font-size:.85rem;
      background:rgba(248,113,113,.1);padding:8px 12px;border-radius:8px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">🏭</div>
    <h1>Cerâmica Visconde</h1>
  </div>
  <p class="sub">Painel do Proprietário</p>
  ${erro ? `<p class="erro">${erro}</p>` : ''}
  <form method="POST" action="/painel/login">
    <label>PIN de acesso</label>
    <input type="password" name="pin" placeholder="••••" autofocus inputmode="numeric" maxlength="8">
    <button type="submit">Entrar</button>
  </form>
</div>
</body>
</html>`;
}

// ── PAINEL PRINCIPAL ──────────────────────────────────────────────────────────

function painelPage() {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Painel — Cerâmica Visconde</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0D0D0D;color:#EDEDED;font-family:'Outfit',system-ui,sans-serif;
     padding-bottom:48px;-webkit-font-smoothing:antialiased}

/* header */
header{background:#141414;padding:0 16px;height:52px;display:flex;align-items:center;
       justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.08);
       position:sticky;top:0;z-index:10}
.logo{display:flex;align-items:center;gap:8px}
.logo-icon{width:28px;height:28px;background:#FFD400;border-radius:6px;
           display:flex;align-items:center;justify-content:center;font-size:14px}
.logo-txt{font-size:.9rem;font-weight:700;color:#EDEDED}
.sync-badge{font-size:.68rem;color:#9CA3AF;background:#1c1c1c;
            padding:3px 8px;border-radius:20px;border:1px solid rgba(255,255,255,.08)}
.sync-badge.ok{color:#34d472;border-color:rgba(52,212,114,.25)}
.logout{font-size:.75rem;color:#6b7280;text-decoration:none;padding:4px 8px;
        border-radius:6px;transition:color .2s}
.logout:hover{color:#f87171}

/* container */
.container{padding:14px}

/* cards de totais */
.cards{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}
.card{background:#141414;border:1px solid rgba(255,255,255,.08);
      border-radius:12px;padding:14px 16px}
.card .lbl{font-size:.65rem;color:#9CA3AF;text-transform:uppercase;
           letter-spacing:.6px;font-weight:600;margin-bottom:6px}
.card .val{font-size:1.25rem;font-weight:700;letter-spacing:-.3px}
.card.amarelo{border-color:rgba(255,212,0,.2)}
.card.amarelo .val{color:#FFD400}
.card.verde .val{color:#34d472}
.card.vermelho .val{color:#f87171}
.card.azul .val{color:#60a5fa}

/* seções */
.section{background:#141414;border:1px solid rgba(255,255,255,.08);
         border-radius:12px;padding:14px 16px;margin-bottom:12px}
.section h2{font-size:.7rem;font-weight:700;color:#6b7280;text-transform:uppercase;
            letter-spacing:.6px;margin-bottom:12px;display:flex;align-items:center;gap:6px}

/* itens */
.item{padding:10px 0;border-bottom:1px solid rgba(255,255,255,.06);
      display:flex;justify-content:space-between;align-items:center;gap:10px}
.item:last-child{border-bottom:none;padding-bottom:0}
.item-info{flex:1;min-width:0}
.item-nome{font-size:.85rem;font-weight:500;color:#EDEDED;
           white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item-sub{font-size:.7rem;color:#6b7280;margin-top:2px;
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item-right{display:flex;flex-direction:column;align-items:flex-end;gap:4px}
.item-val{font-size:.88rem;font-weight:700;white-space:nowrap}
.badge{font-size:.6rem;padding:2px 7px;border-radius:20px;font-weight:700;
       white-space:nowrap;text-transform:uppercase;letter-spacing:.3px}
.badge.vencido{background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.25)}
.badge.pendente{background:rgba(96,165,250,.12);color:#60a5fa;border:1px solid rgba(96,165,250,.2)}
.badge.alta{background:rgba(248,113,113,.12);color:#f87171}
.badge.media{background:rgba(255,212,0,.1);color:#FFD400}
.badge.baixa{background:rgba(52,212,114,.1);color:#34d472}
.prioridade-alta{border-left:3px solid #f87171;padding-left:10px}
.prioridade-media{border-left:3px solid #FFD400;padding-left:10px}
.prioridade-baixa{border-left:3px solid #34d472;padding-left:10px}

.empty{color:#6b7280;font-size:.82rem;text-align:center;padding:20px 0}
.loading{text-align:center;padding:64px 20px;color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">🏭</div>
    <span class="logo-txt">Cerâmica Visconde</span>
  </div>
  <span class="sync-badge" id="sync-badge">sem dados</span>
  <a href="/painel/logout" class="logout">Sair</a>
</header>

<div class="container" id="conteudo">
  <div class="loading">Carregando...</div>
</div>

<script>
function fmtBRL(v){
  return Number(v||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
}
function fmtData(iso){
  if(!iso) return '—';
  const p=iso.slice(0,10).split('-');
  return p[2]+'/'+p[1]+'/'+p[0];
}

async function carregar(){
  try{
    const r=await fetch('/painel/dados');
    if(r.status===401){location.href='/painel/login';return;}
    renderizar(await r.json());
  }catch(e){
    document.getElementById('conteudo').innerHTML=
      '<div class="loading">Erro ao carregar. Tente novamente.</div>';
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

  const t=new Date(d.recebido_em);
  badge.textContent='Sync '+t.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
  badge.className='sync-badge ok';

  const tot=d.totais||{};
  const rec=d.a_receber||[];
  const pag=d.a_pagar||[];
  const tar=d.tarefas||[];

  document.getElementById('conteudo').innerHTML=\`
    <div class="cards">
      <div class="card verde">
        <div class="lbl">A Receber</div>
        <div class="val">\${fmtBRL(tot.a_receber)}</div>
      </div>
      <div class="card vermelho">
        <div class="lbl">A Pagar</div>
        <div class="val">\${fmtBRL(tot.a_pagar)}</div>
      </div>
      <div class="card amarelo">
        <div class="lbl">Vencido</div>
        <div class="val">\${fmtBRL(tot.vencido)}</div>
      </div>
      <div class="card azul">
        <div class="lbl">Saldo do Mês</div>
        <div class="val">\${fmtBRL(tot.saldo_mes)}</div>
      </div>
    </div>

    <div class="section">
      <h2>📥 Contas a Receber</h2>
      \${rec.length===0
        ?'<p class="empty">Nenhuma conta pendente</p>'
        :rec.map(c=>\`
          <div class="item">
            <div class="item-info">
              <div class="item-nome">\${c.descricao||'—'}</div>
              <div class="item-sub">\${c.cliente_nome||''}\${c.cliente_nome&&c.vencimento?' · ':''}\${fmtData(c.vencimento)}</div>
            </div>
            <div class="item-right">
              <span class="item-val" style="color:#34d472">\${fmtBRL(c.valor)}</span>
              <span class="badge \${c.status}">\${c.status}</span>
            </div>
          </div>\`).join('')}
    </div>

    <div class="section">
      <h2>📤 Contas a Pagar</h2>
      \${pag.length===0
        ?'<p class="empty">Nenhuma conta pendente</p>'
        :pag.map(c=>\`
          <div class="item">
            <div class="item-info">
              <div class="item-nome">\${c.descricao||'—'}</div>
              <div class="item-sub">\${c.cliente_nome||''}\${c.cliente_nome&&c.vencimento?' · ':''}\${fmtData(c.vencimento)}</div>
            </div>
            <div class="item-right">
              <span class="item-val" style="color:#f87171">\${fmtBRL(c.valor)}</span>
              <span class="badge \${c.status}">\${c.status}</span>
            </div>
          </div>\`).join('')}
    </div>

    <div class="section">
      <h2>✅ Tarefas Ativas</h2>
      \${tar.length===0
        ?'<p class="empty">Nenhuma tarefa ativa</p>'
        :tar.map(t=>\`
          <div class="item prioridade-\${t.prioridade||'baixa'}">
            <div class="item-info">
              <div class="item-nome">\${t.titulo||'—'}</div>
              <div class="item-sub">\${fmtData(t.data)}</div>
            </div>
            <span class="badge \${t.prioridade||'baixa'}">\${t.prioridade||'baixa'}</span>
          </div>\`).join('')}
    </div>
  \`;
}

carregar();
setInterval(carregar, 5*60*1000);
</script>
</body>
</html>`;
}
