import { escapeHtml } from "./render.js";

const CSS = `
:root{
  --bg:#fbfbfa; --fg:#1c1c1c; --muted:#6b6b6b; --line:#e4e4e1;
  --card:#ffffff; --accent:#1a5fb4;
  --ok:#1a7f37; --info:#1a5fb4; --warn:#9a6700; --crit:#b62324; --unknown:#6b6b6b;
  --ok-bg:#eaf6ec; --info-bg:#e9f0fb; --warn-bg:#fbf3e2; --crit-bg:#fbeaea; --unknown-bg:#f0f0f0;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#161616; --fg:#e9e9e7; --muted:#9a9a97; --line:#2e2e2c;
    --card:#1f1f1e; --accent:#6aa6ff;
    --ok:#5bd67d; --info:#8fb8ff; --warn:#e5b567; --crit:#f2807f; --unknown:#9a9a97;
    --ok-bg:#132a19; --info-bg:#152238; --warn-bg:#2c2412; --crit-bg:#301717; --unknown-bg:#242423;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
.wrap{max-width:760px;margin:0 auto;padding:48px 20px 80px;}
header h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em;}
header p{color:var(--muted);margin:0 0 28px;}
form.check{display:flex;gap:8px;flex-wrap:wrap;}
form.check input[type=text]{flex:1;min-width:220px;padding:11px 13px;font-size:15px;
  border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);}
form.check button{padding:11px 18px;font-size:15px;font-weight:600;border:0;border-radius:8px;
  background:var(--accent);color:#fff;cursor:pointer;}
form.check button:hover{filter:brightness(1.05);}
.error{margin:20px 0 0;padding:12px 14px;border-radius:8px;background:var(--crit-bg);color:var(--crit);}
.report{margin-top:32px;}
.scorecard{display:flex;align-items:center;gap:18px;padding:18px 20px;border-radius:12px;
  border:1px solid var(--line);background:var(--card);}
.scorecard .grade{font-size:44px;font-weight:800;line-height:1;width:64px;text-align:center;}
.scorecard.ready .grade{color:var(--ok);}
.scorecard.at-risk .grade{color:var(--warn);}
.scorecard.not-ready .grade{color:var(--crit);}
.score-meta .score{font-size:20px;font-weight:700;}
.score-meta .score span{color:var(--muted);font-weight:400;font-size:14px;}
.score-meta .readiness{text-transform:capitalize;color:var(--muted);}
.score-meta .domain{color:var(--muted);font-size:13px;margin-top:2px;}
.findings{margin-top:16px;display:flex;flex-direction:column;gap:8px;}
.finding{display:flex;gap:12px;padding:12px 14px;border-radius:10px;border:1px solid var(--line);
  background:var(--card);}
.finding .pill{flex:none;font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 7px;
  border-radius:5px;height:fit-content;}
.sev-ok .pill{background:var(--ok-bg);color:var(--ok);}
.sev-info .pill{background:var(--info-bg);color:var(--info);}
.sev-warn .pill{background:var(--warn-bg);color:var(--warn);}
.sev-crit .pill{background:var(--crit-bg);color:var(--crit);}
.sev-unknown .pill{background:var(--unknown-bg);color:var(--unknown);}
.finding-title .check{font-weight:700;margin-right:6px;}
.finding-detail{color:var(--muted);font-size:13.5px;margin-top:3px;}
.finding-fix{font-size:13.5px;margin-top:4px;}
.checked-at{color:var(--muted);font-size:12.5px;margin-top:16px;}
.cta{margin-top:40px;padding:20px;border-radius:12px;border:1px solid var(--line);background:var(--card);}
.cta h2{font-size:16px;margin:0 0 6px;}
.cta p{color:var(--muted);margin:0 0 14px;font-size:14px;}
.cta form{display:flex;gap:8px;flex-wrap:wrap;}
.cta input{flex:1;min-width:200px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;
  background:var(--bg);color:var(--fg);}
.cta button,.cta a.btn{padding:10px 16px;font-weight:600;border:0;border-radius:8px;background:var(--accent);
  color:#fff;cursor:pointer;text-decoration:none;display:inline-block;}
.note{margin-top:12px;font-size:12.5px;color:var(--muted);}
footer{margin-top:48px;color:var(--muted);font-size:12.5px;}
footer a{color:var(--accent);}
`;

export interface PageOptions {
  domain?: string | undefined;
  reportHtml?: string | undefined;
  error?: string | undefined;
  waitlistUrl: string;
  waitlistEnabled: boolean;
  waitlistMessage?: string | undefined;
}

export function renderPage(o: PageOptions): string {
  const value = o.domain ? ` value="${escapeHtml(o.domain)}"` : "";

  const cta = o.waitlistEnabled
    ? `<form method="POST" action="/api/waitlist">
         <input type="email" name="email" required placeholder="you@company.com" />
         <button type="submit">Notify me</button>
       </form>
       ${o.waitlistMessage ? `<p class="note">${escapeHtml(o.waitlistMessage)}</p>` : ""}`
    : o.waitlistUrl
      ? `<a class="btn" href="${escapeHtml(o.waitlistUrl)}">Join the waitlist</a>`
      : `<p class="note">Continuous monitoring is in development.</p>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>coldwatch — cold-email domain health check</title>
<meta name="description" content="Check SPF, DKIM, DMARC and MX for a cold-email sending domain. Free, live DNS, nothing stored." />
<style>${CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Cold-email domain health check</h1>
    <p>SPF, DKIM, DMARC and MX for one sending domain. Live DNS, nothing stored.</p>
  </header>

  <form class="check" method="GET" action="/">
    <input type="text" name="domain" autocomplete="off" autocapitalize="off"
      spellcheck="false" placeholder="acme.com"${value} autofocus />
    <button type="submit">Check</button>
  </form>

  ${o.error ? `<div class="error">${escapeHtml(o.error)}</div>` : ""}
  ${o.reportHtml ?? ""}

  <div class="cta">
    <h2>Running this across every domain, by hand, every day?</h2>
    <p>coldwatch is becoming continuous monitoring: scheduled checks across all your
       sending domains, with an alert the moment SPF breaks or a record drifts.</p>
    ${cta}
  </div>

  <footer>
    Open source · MIT · checks run against public DNS over HTTPS ·
    no blacklist data in this free check.
  </footer>
</div>
</body>
</html>`;
}
