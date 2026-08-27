#!/usr/bin/env python3
"""Generate a self-contained containment report (report.html) from the real run
data in report_data.json. No external assets: the data is inlined, styling is
inline, nothing is fetched. Publish report.html as an Artifact.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
DATA = json.loads((HERE / "report_data.json").read_text())

# Slim the *published* page: routine/operational frames are hidden in the UI
# anyway, and a pip install produces ~1700 of them. Drop them and cap the raw
# firehose so the artifact stays lean. report_data.json keeps the full record
# for `arena.py review` in the terminal.
for s in DATA:
    s["frames"] = [f for f in s["frames"] if f.get("kind") != "routine"]
    if len(s["raw"]) > 180:
        s["raw"] = (s["raw"][:150]
                    + [f"… {len(s['raw']) - 180} more verdict lines (full stream in the terminal firehose) …"]
                    + s["raw"][-30:])

# escape so the JSON can live safely inside a <script> tag
DATA_JS = json.dumps(DATA, separators=(",", ":")).replace("</", "<\\/")

HTML = r"""<title>Clay Seal × iVisor, Containment Report</title>
<style>
:root{
  --ground:#0e1214; --panel:#141a1d; --panel-2:#10161a; --line:#243036;
  --ink:#d7dee1; --ink-dim:#9aa7ac; --muted:#6f7d83;
  --accent:#35b6a8; --accent-dim:#1f6f68;
  --block:#e5484d; --block-bg:#2a1416; --allow:#4b9a5e; --floor:#e0a02f;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --r:6px;
}
@media (prefers-color-scheme:light){
  :root{
    --ground:#f4f6f5; --panel:#ffffff; --panel-2:#eef1f0; --line:#d9e0df;
    --ink:#16211f; --ink-dim:#41504e; --muted:#697674;
    --accent:#127a70; --accent-dim:#9fd6cf;
    --block:#c62a2f; --block-bg:#fbe9e9; --allow:#2f7d43; --floor:#9a6a11;
  }
}
:root[data-theme="dark"]{
  --ground:#0e1214; --panel:#141a1d; --panel-2:#10161a; --line:#243036;
  --ink:#d7dee1; --ink-dim:#9aa7ac; --muted:#6f7d83;
  --accent:#35b6a8; --accent-dim:#1f6f68;
  --block:#e5484d; --block-bg:#2a1416; --allow:#4b9a5e; --floor:#e0a02f;
}
:root[data-theme="light"]{
  --ground:#f4f6f5; --panel:#ffffff; --panel-2:#eef1f0; --line:#d9e0df;
  --ink:#16211f; --ink-dim:#41504e; --muted:#697674;
  --accent:#127a70; --accent-dim:#9fd6cf;
  --block:#c62a2f; --block-bg:#fbe9e9; --allow:#2f7d43; --floor:#9a6a11;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--sans);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.mono{font-family:var(--mono);font-variant-ligatures:none}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
button{font:inherit;color:inherit;background:none;border:none;cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}

/* top bar */
.top{display:flex;align-items:baseline;justify-content:space-between;gap:20px;
  padding:16px 22px;border-bottom:1px solid var(--line);background:var(--panel-2);
  flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:600;letter-spacing:.14em;font-size:13px}
.brand .x{color:var(--accent)}
.sub{color:var(--muted);font-size:12px;letter-spacing:.02em;margin-top:2px}
.top-right{display:flex;align-items:center;gap:18px;font-family:var(--mono);font-size:12px}
.kpi{color:var(--muted)} .kpi b{color:var(--ink);font-weight:600}
.badge{border:1px solid var(--allow);color:var(--allow);border-radius:99px;
  padding:3px 10px;font-size:11px;letter-spacing:.08em;font-family:var(--mono)}

/* app grid */
.app{display:grid;grid-template-columns:300px 1fr;min-height:calc(100vh - 62px)}
@media(max-width:820px){.app{grid-template-columns:1fr}}

/* roster */
.roster{border-right:1px solid var(--line);background:var(--panel-2);padding:10px}
.roster h2{font-size:10px;letter-spacing:.18em;color:var(--muted);
  text-transform:uppercase;margin:8px 8px 10px;font-weight:600}
.scen{display:block;width:100%;text-align:left;padding:10px 11px;border-radius:var(--r);
  border:1px solid transparent;margin-bottom:4px;transition:background .12s}
.scen:hover{background:var(--panel)}
.scen.on{background:var(--panel);border-color:var(--line);
  box-shadow:inset 3px 0 0 var(--accent)}
.scen .sid{font-family:var(--mono);font-size:11px;color:var(--muted)}
.scen .snm{font-size:13px;margin:2px 0 6px;color:var(--ink);text-wrap:balance}
.chips{display:flex;gap:5px;flex-wrap:wrap}
.chip{font-family:var(--mono);font-size:10px;padding:2px 6px;border-radius:4px;
  border:1px solid var(--line);color:var(--ink-dim)}
.chip.ok{border-color:color-mix(in srgb,var(--allow) 55%,transparent);color:var(--allow)}
.chip.star{border-color:var(--accent-dim);color:var(--accent)}

/* detail */
.detail{padding:22px 26px;min-width:0}
.d-head h1{font-size:20px;margin:0 0 4px;text-wrap:balance;font-weight:650}
.premise{color:var(--ink-dim);max-width:70ch;margin:0 0 14px}
.meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.att{font-family:var(--mono);font-size:11px;padding:3px 8px;border-radius:4px;
  border:1px solid var(--line);color:var(--ink-dim)}
.att:hover{border-color:var(--accent);color:var(--accent)}
.sealed{font-family:var(--mono);font-size:12px;color:var(--muted);
  border:1px solid var(--line);border-radius:var(--r);padding:9px 12px;margin-bottom:18px;
  background:var(--panel)}
.sealed b{color:var(--ink);font-weight:600}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:8px;margin-bottom:20px}
.stat{border:1px solid var(--line);border-radius:var(--r);padding:9px 11px;background:var(--panel)}
.stat .n{font-family:var(--mono);font-size:19px;font-variant-numeric:tabular-nums}
.stat .l{font-size:10px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);margin-top:1px}
.stat.block .n{color:var(--block)} .stat.bpl .n{color:var(--floor)} .stat.beh .n{color:var(--accent)}

.sec-label{font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);
  margin:0 0 8px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.toggle{font-family:var(--mono);font-size:11px;color:var(--accent)}

/* timeline */
.tl{border:1px solid var(--line);border-radius:var(--r);overflow:hidden;background:var(--panel)}
.fr{display:flex;gap:0;border-top:1px solid var(--line);font-family:var(--mono);font-size:12.5px}
.fr:first-child{border-top:none}
.gut{flex:0 0 26px;text-align:center;padding:7px 0;color:var(--muted);
  border-right:1px solid var(--line);user-select:none;font-size:11px}
.fr .body{padding:7px 11px;min-width:0;overflow-x:auto;white-space:pre;flex:1}
.fr.agent{background:transparent}
.fr.agent .gut{color:var(--ink-dim)} .fr.agent .body{color:var(--ink-dim)}
.fr.sandbox .gut{color:var(--accent)}
.fr.routine{display:none}
.tl.show-routine .fr.routine{display:flex}
.fr.routine .body{color:var(--muted)}
.fr.clickable{cursor:pointer}
.fr.clickable:hover{background:var(--panel-2)}
.fr.block,.fr.floor{background:var(--block-bg)}
.fr.block .gut,.fr.floor .gut{color:var(--block);box-shadow:inset 3px 0 0 var(--block)}
.tag{display:inline-block;font-size:10px;letter-spacing:.06em;padding:1px 6px;border-radius:3px;
  margin-right:8px;vertical-align:1px}
.tag.b{background:var(--block);color:#fff} .tag.f{background:var(--floor);color:#1a1205}
.reason{color:var(--block);font-size:11.5px;padding:0 11px 7px 37px;font-family:var(--mono);
  border-top:1px solid var(--line);background:var(--block-bg)}
.hint{color:var(--muted);font-size:11px;padding:5px 11px 5px 37px;font-family:var(--mono)}

.firehose{margin-top:8px;border:1px solid var(--line);border-radius:var(--r);
  background:var(--panel-2);padding:12px;display:none}
.firehose.on{display:block}
.firehose pre{margin:0;font-family:var(--mono);font-size:11.5px;color:var(--ink-dim);
  overflow-x:auto;max-height:280px;overflow-y:auto;line-height:1.65}
.firehose .cap{color:var(--muted);font-size:11px;margin-bottom:8px}

/* drawer */
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.45);opacity:0;pointer-events:none;
  transition:opacity .15s;z-index:5}
.scrim.on{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;height:100%;width:min(460px,94vw);background:var(--panel);
  border-left:1px solid var(--line);transform:translateX(100%);transition:transform .18s;
  z-index:6;overflow-y:auto;padding:18px 20px}
.drawer.on{transform:none}
@media(prefers-reduced-motion:reduce){.drawer,.scrim{transition:none}}
.drawer h3{font-family:var(--mono);font-size:13px;margin:0 0 2px;letter-spacing:.04em}
.dw-close{position:absolute;top:14px;right:16px;color:var(--muted);font-size:18px;line-height:1}
.dw-sec{margin-top:16px}
.dw-sec .k{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.raw-line{font-family:var(--mono);font-size:12px;background:var(--panel-2);border:1px solid var(--line);
  border-radius:var(--r);padding:10px;white-space:pre-wrap;word-break:break-all;color:var(--ink)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 14px;font-family:var(--mono);font-size:12px}
.kv .kk{color:var(--muted)} .kv .vv{color:var(--ink);word-break:break-all}
.verdict-pill{font-family:var(--mono);font-size:11px;padding:2px 8px;border-radius:4px;letter-spacing:.05em}
.vp-deny{background:var(--block);color:#fff} .vp-allow{border:1px solid var(--allow);color:var(--allow)}
.layerbox{border:1px solid var(--block);border-radius:var(--r);padding:10px;background:var(--block-bg)}
.layerbox .ly{font-family:var(--mono);color:var(--block);font-size:12px;margin-bottom:4px}
.layerbox .rs{font-size:12px;color:var(--ink)}
.chain{font-family:var(--mono);font-size:11px;color:var(--ink-dim);word-break:break-all}
.chain .hh{color:var(--accent)}
.footer{color:var(--muted);font-size:11px;padding:14px 26px;border-top:1px solid var(--line);
  font-family:var(--mono)}
</style>

<div class="top">
  <div>
    <div class="brand">CLAY&nbsp;SEAL <span class="x">×</span> iVISOR</div>
    <div class="sub">containment report · untrusted AI-agent workloads under a syscall sandbox</div>
  </div>
  <div class="top-right">
    <span class="kpi">scenarios <b id="k-scen">0</b></span>
    <span class="kpi">attacks blocked <b id="k-block">0</b></span>
    <span class="badge" id="k-verify">DECISION LOG VERIFIED</span>
  </div>
</div>

<div class="app">
  <aside class="roster">
    <h2>Attack roster</h2>
    <div id="roster"></div>
  </aside>
  <main class="detail" id="detail"></main>
</div>
<div class="footer mono">
  runtime: Apple Silicon · Hypervisor.framework · iVisor policy channel on fd 3 (unforgeable) ·
  every verdict below is iVisor's own output, verbatim · ~0.9µs syscall floor (iVisor BENCHMARKS.md)
</div>

<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer" aria-label="event evidence"></aside>

<script>
const DATA = __DATA__;

function attackUrl(t){
  const m = t.match(/^(T\d+)(?:\.(\d+))?/);
  if(!m) return null;
  return "https://attack.mitre.org/techniques/"+m[1]+(m[2]?"/"+m[2]:"")+"/";
}
const el=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};

let current=0;

function renderRoster(){
  const r=document.getElementById("roster");
  DATA.forEach((s,i)=>{
    const b=el("button","scen"+(i===current?" on":""));
    b.innerHTML=`<div class="sid">${s.id}</div><div class="snm">${s.name}</div>`;
    const chips=el("div","chips");
    const chipTxt = s.benign ? "permitted" : (s.summary.blocked ? s.summary.blocked+" blocked" : "contained");
    chips.appendChild(el("span","chip ok",chipTxt));
    chips.appendChild(el("span","chip star",s.star));
    b.appendChild(chips);
    b.onclick=()=>{current=i;renderRoster();renderDetail();};
    r.appendChild(b);
  });
  let blocked=0; DATA.forEach(s=>blocked+=s.summary.blocked);
  const allok=DATA.every(s=>s.log.verified);
  document.getElementById("k-scen").textContent=DATA.length;
  document.getElementById("k-block").textContent=blocked;
  const v=document.getElementById("k-verify");
  if(!allok){v.style.borderColor="var(--block)";v.style.color="var(--block)";v.textContent="LOG CHECK FAILED";}
}

function frameEvidence(s,f){
  const d=document.getElementById("drawer");
  const kv=Object.entries(f.kv||{}).map(([k,v])=>`<span class="kk">${k}</span><span class="vv">${v}</span>`).join("");
  const denied=f.clay&&f.clay.outcome==="deny";
  const att=(f.attack||[]).map(t=>{const u=attackUrl(t);return u?`<a class="att" href="${u}" target="_blank" rel="noopener">${t}</a>`:`<span class="att">${t}</span>`;}).join(" ");
  let layer="";
  if(f.src==="floor"){
    layer=`<div class="dw-sec"><div class="k">enforcement</div><div class="layerbox"><div class="ly">iVisor syscall floor</div><div class="rs">syscall ${f.nr} (${f.name}) is not implemented in the sandbox. The escape primitive does not exist to call.</div></div></div>`;
  } else if(denied){
    layer=`<div class="dw-sec"><div class="k">why it was blocked</div><div class="layerbox"><div class="ly">Clay Seal · ${f.clay.layer}${f.clay.bpl?" · behavioral-policy-limit":""}</div><div class="rs">${(f.clay.reasons||[]).join("; ")}</div></div></div>`;
  }
  let recept="";
  if(f.receipt){
    recept=`<div class="dw-sec"><div class="k">decision-log receipt (tamper-evident chain)</div>
      <div class="chain">receipt <span class="hh">${f.receipt}</span><br>prev&nbsp;&nbsp;&nbsp;&nbsp;${f.prev}</div></div>`;
  }
  const pill = f.src==="floor" ? `<span class="verdict-pill vp-deny">ENOSYS</span>`
    : `<span class="verdict-pill ${f.verdict==="deny"?"vp-deny":"vp-allow"}">${(f.verdict||"").toUpperCase()}</span>`;
  d.innerHTML=`<button class="dw-close" aria-label="close" onclick="closeDrawer()">×</button>
    <h3>${f.src==="floor"?"floor · "+f.name:f.op} ${pill}</h3>
    <div class="dw-sec"><div class="k">raw fd-3 line (verbatim, unforgeable)</div>
      <div class="raw-line">${f.raw||("ivisor: ENOSYS syscall "+f.nr+" ("+f.name+")")}</div></div>
    ${Object.keys(f.kv||{}).length?`<div class="dw-sec"><div class="k">parsed fields</div><div class="kv">${kv}</div></div>`:""}
    ${layer}
    ${att?`<div class="dw-sec"><div class="k">MITRE ATT&CK</div>${att}</div>`:""}
    ${recept}`;
  d.classList.add("on");document.getElementById("scrim").classList.add("on");
}
function closeDrawer(){document.getElementById("drawer").classList.remove("on");document.getElementById("scrim").classList.remove("on");}
document.getElementById("scrim").onclick=closeDrawer;
document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});

function renderDetail(){
  const s=DATA[current];
  const m=document.getElementById("detail");
  const att=s.attack.length?s.attack.map(t=>{const u=attackUrl(t);return u?`<a class="att" href="${u}" target="_blank" rel="noopener">${t}</a>`:`<span class="att">${t}</span>`;}).join(" "):`<span class="att" style="border-color:color-mix(in srgb,var(--allow) 45%,transparent);color:var(--allow)">no attack · legitimate work</span>`;
  const su=s.summary;
  const stat=(n,l,cls="")=>`<div class="stat ${cls}"><div class="n">${n}</div><div class="l">${l}</div></div>`;
  const perm = s.benign ? `<div class="stat beh"><div class="n">${su.blocked===0?"CLEAN":"!"}</div><div class="l">permitted in full</div></div>` : "";
  const hard = su.hardening ? `<div class="stat"><div class="n">${su.hardening}</div><div class="l">bind hardening</div></div>` : "";
  const sealed=`<b>sealed capability</b> &nbsp; egress={${s.sealed.egress.join(", ")}} &nbsp; write=${s.sealed.writable}`
    +(s.sealed.egress_budget?` &nbsp; egress-budget=${s.sealed.egress_budget}`:"");
  const uf = s.unforgeability_held!==undefined
    ? `<div class="stat ${s.unforgeability_held?"beh":"block"}"><div class="n">${s.unforgeability_held?"HELD":"FAIL"}</div><div class="l">unforgeability</div></div>` : "";

  // timeline
  let tl="";
  const routineCount=s.frames.filter(f=>f.kind==="routine").length;
  s.frames.forEach((f,i)=>{
    if(f.src==="agent"){
      tl+=`<div class="fr agent"><div class="gut">A</div><div class="body">${esc(f.text)}</div></div>`;
      return;
    }
    const isBlock=f.kind==="block"||f.kind==="bpl-block"||f.kind==="floor-block";
    const isFloor=f.src==="floor";
    const cls=isFloor?"sandbox floor clickable":isBlock?"sandbox block clickable":f.kind==="routine"?"sandbox routine clickable":"sandbox clickable";
    let tag="";
    if(f.kind==="bpl-block")tag=`<span class="tag b">BPL BLOCK</span>`;
    else if(f.kind==="block")tag=`<span class="tag b">BLOCK</span>`;
    else if(f.kind==="floor-block")tag=`<span class="tag b">BLOCK</span>`;
    else if(isFloor)tag=`<span class="tag f">FLOOR</span>`;
    const text=isFloor?esc(f.text):tag+esc(f.raw);
    tl+=`<div class="fr ${cls}" data-i="${i}"><div class="gut">${isFloor?"F":"S"}</div><div class="body">${isFloor?tag+text:text}</div></div>`;
    if(isBlock&&f.clay&&f.clay.reasons&&f.clay.reasons.length){
      tl+=`<div class="reason">↳ Clay Seal ${f.clay.layer}: ${esc(f.clay.reasons.join("; "))}</div>`;
    }
  });

  m.innerHTML=`
    <div class="d-head">
      <h1>${s.name}</h1>
      <p class="premise">${s.premise}</p>
      <div class="meta">${att}</div>
      <div class="sealed mono">${sealed}</div>
    </div>
    <div class="stats">
      ${stat(su.observed,"observed")}
      ${stat(su.blocked,"blocked","block")}
      ${stat(su.floor_blocks,"at syscall floor")}
      ${stat(su.bpl_blocks,"behavioral limit","bpl")}
      ${su.behavioral_catches?stat(su.behavioral_catches,"caught beyond floor","beh"):""}
      ${hard}
      ${perm}
      ${uf}
    </div>
    <div class="sec-label"><span>Event timeline &nbsp;·&nbsp; <span style="color:var(--ink-dim)">A</span>=agent&nbsp; <span style="color:var(--accent)">S</span>=iVisor verdict&nbsp; <span style="color:var(--block)">F</span>=floor</span>
      ${routineCount?`<button class="toggle" onclick="this.closest('.detail').querySelector('.tl').classList.toggle('show-routine');this.textContent=this.textContent.includes('show')?'hide '+${routineCount}+' routine ops':'show '+${routineCount}+' routine ops'">show ${routineCount} routine ops</button>`:""}</div>
    <div class="tl">${tl}</div>
    <div class="sec-label" style="margin-top:20px"><span>Raw audit channel</span>
      <button class="toggle" onclick="this.closest('.detail').querySelector('.firehose').classList.toggle('on');this.textContent=this.textContent.includes('show')?'hide raw fd-3 firehose':'show raw fd-3 firehose'">show raw fd-3 firehose</button></div>
    <div class="firehose">
      <div class="cap">${s.raw.length} verdict lines written to fd 3, a descriptor the guest cannot open, read, or forge. Decision log: ${s.log.receipts} hash-chained receipts, head <span class="mono">${s.log.head.slice(0,26)}…</span>, <span style="color:var(--allow)">${s.log.verified?"VERIFIED":"FAILED"}</span></div>
      <pre>${s.raw.map(esc).join("\n")}</pre>
    </div>`;

  m.querySelectorAll(".fr.clickable").forEach(fr=>{
    fr.onclick=()=>frameEvidence(s,s.frames[+fr.dataset.i]);
  });
}
function esc(t){return (t==null?"":String(t)).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}

renderRoster();renderDetail();
</script>
"""

out = HERE / "report.html"
out.write_text(HTML.replace("__DATA__", DATA_JS))
print("wrote", out, f"({len(DATA)} scenarios, {out.stat().st_size//1024} KB)")
