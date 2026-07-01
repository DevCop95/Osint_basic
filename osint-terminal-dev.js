(() => {
  if (window.__osint_terminal__) {
    const x = document.getElementById("__osint_terminal_box");
    if (x) return;
    try { delete window.__osint_terminal__; } catch(e) { window.__osint_terminal__ = false; }
  }
  window.__osint_terminal__ = true;

  // ═══════════════════════════════════════════════════════════
  // CORE STATE
  // ═══════════════════════════════════════════════════════════
  const evidenceStore  = new Map();
  const traffic        = [];
  const wsTraffic      = [];
  const pmTraffic      = [];
  const cmdHistory     = [];
  const setCookieLog   = [];
  const secHeaderLog   = [];   // { url, headers:{}, cors:{} }
  const graphqlOps     = [];   // inferred GraphQL ops from traffic

  // Caps prevent unbounded memory growth during long recon sessions / chatty SPAs.
  const MAX_TRAFFIC    = 500;
  const MAX_WS         = 200;
  const MAX_PM         = 500;
  const MAX_WS_MSGS    = 200;
  const MAX_SETCOOKIE  = 300;
  const MAX_SECHEADERS = 300;
  const MAX_GRAPHQL    = 300;
  const MAX_EVIDENCE   = 5000;
  const pushCapped = (arr, item, max) => {
    arr.push(item);
    if (arr.length > max) arr.splice(0, arr.length - max);
  };

  let nextEvidenceId  = 1;
  let nextTrafficId   = 1;
  let histIdx         = -1;
  let clockTimer      = null;
  let moveHandler     = null;
  let upHandler       = null;
  let resizeActive    = false;
  let netInterceptor  = false;
  let wsInterceptor   = false;
  let pmInterceptor   = false;
  let ownDB           = null;
  let destroyTerminal = () => {};
  let lastScanSnap    = null;   // for diff
  let lastSiteFiles   = [];
  let activeTab       = "scan"; // "scan" | "traffic" | "findings"

  const DB_OWN_NAME   = "osintDB_v2";
  const originalFetch = window.fetch.bind(window);
  const OriginalXHR   = window.XMLHttpRequest;
  const OriginalWS    = window.WebSocket;

  // ═══════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════
  const el = (tag, styles = {}, text = "") => {
    const e = document.createElement(tag);
    Object.assign(e.style, styles);
    if (text) e.textContent = text;
    return e;
  };
  // Always sets textContent (never innerHTML) — safe for untrusted values (URLs, captured secrets, etc).
  const spanEl = (text, styles = {}) => {
    const s = document.createElement("span");
    Object.assign(s.style, styles);
    s.textContent = text==null ? "" : String(text);
    return s;
  };
  const nowIso = () => new Date().toISOString();
  const nowMs  = () => Date.now();

  const normalizeHeaders = (h) => {
    const o = {};
    try {
      if (!h) return o;
      if (h instanceof Headers) { for (const [k,v] of h.entries()) o[k]=v; }
      else if (Array.isArray(h)) h.forEach(([k,v]) => { o[k]=v; });
      else if (typeof h==="object") Object.keys(h).forEach(k => { o[k]=h[k]; });
    } catch(e) {}
    return o;
  };

  const entropy = (s="") => {
    if (!s || s.length<4) return 0;
    const m={}; for(const c of s) m[c]=(m[c]||0)+1;
    const l=s.length; let e=0;
    for(const k in m){const p=m[k]/l; e-=p*Math.log2(p);}
    return e;
  };

  const dedupeStrings = (a) => [...new Set(a.filter(Boolean))];
  const previewVal    = (v,n=60) => { const s=String(v||"").trim().replace(/\s+/g," "); return s.length<=n?s:s.slice(0,n)+"…"; };
  const maskSecret    = (s)      => (s&&s.length>10)?s.slice(0,6)+"…"+s.slice(-4):"***";

  const DUMMY_WORDS = ["example", "placeholder", "changeme", "null", "undefined", "true", "false", "your_", "insert", "replace", "dummy", "test"];
  const isDummyValue = (v) => {
    if (!v) return true;
    const lower = String(v).toLowerCase();
    if (lower === "null" || lower === "undefined" || lower === "true" || lower === "false" || lower === "0" || lower === "1") return true;
    return DUMMY_WORDS.some(w => lower.includes(w));
  };

  const rootHost = location.hostname.replace(/^www\./i,"");

  const getHost = (url) => { try{return new URL(url,location.href).hostname.replace(/^www\./i,"");}catch{return "";} };
  const displayUrl = (url, maxLen=88) => {
    try {
      const p = new URL(url, location.href);
      if (p.origin===location.origin) {
        const q = p.search.length>40 ? p.search.slice(0,38)+"…" : p.search;
        return (p.pathname+q)||"/";
      }
      const f=p.href; return f.length>maxLen?f.slice(0,maxLen)+"…":f;
    } catch {
      const s=String(url||""); return s.length>maxLen?s.slice(0,maxLen)+"…":s;
    }
  };
  const truncUrl = (u,n=70) => { const s=displayUrl(u); return s.length<=n?s:s.slice(0,n)+"…"; };

  const NOISY_HOSTS = [
    "google.com","gstatic.com","googleapis.com","googletagmanager.com",
    "google-analytics.com","googleadservices.com","doubleclick.net",
    "cloudflareinsights.com","cloudflare.com",
    "facebook.net","facebook.com","fbcdn.net",
    "hotjar.com","clarity.ms","segment.io","segment.com",
    "intercom.io","intercom.com","intercomcdn.com",
    "hubspot.com","hs-scripts.com","hsforms.com",
    "mixpanel.com","heap.io","amplitude.com",
    "newrelic.com","nr-data.net","rollbar.com","sentry.io","bugsnag.com",
    "twitter.com","analytics.twitter.com","linkedin.com","snap.com",
    "cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com",
  ];
  const isNoisyHost  = (h) => NOISY_HOSTS.some(n=>h===n||h.endsWith("."+n));
  const isFirstParty = (u) => { const h=getHost(u); return h&&(h===rootHost||h.endsWith("."+rootHost)); };
  const isInteresting= (u) => {
    if(!u||/^(javascript:|mailto:|tel:|#)/i.test(u)) return false;
    return /(api|auth|login|logout|signin|signup|register|oauth|token|session|refresh|reset|forgot|account|user|admin|graphql|upload|download|webhook|callback|redirect|v\d)/i.test(u);
  };

  // ═══════════════════════════════════════════════════════════
  // UI — BOX + RESIZE
  // ═══════════════════════════════════════════════════════════
  const box = el("div", {
    position:"fixed", bottom:"20px", right:"20px",
    width:"640px", height:"460px", minWidth:"400px", minHeight:"280px",
    background:"#08090D", border:"1px solid #1B8A93",
    zIndex:"999999999", display:"flex", flexDirection:"column",
    fontFamily:"'Courier New',monospace", fontSize:"12px", color:"#14B8C4",
    boxShadow:"0 0 30px #22d3d922", borderRadius:"6px",
    boxSizing:"border-box"
  });
  box.id = "__osint_terminal_box";

  // ── Drag ────────────────────────────────────────────────────
  let drag=false, ox=0, oy=0;
  const header = el("div",{
    padding:"5px 10px", borderBottom:"1px solid #123042",
    display:"flex", justifyContent:"space-between", alignItems:"center",
    background:"#070C14", cursor:"move", userSelect:"none", flexShrink:"0"
  });
  header.onmousedown = e => {
    if(e.button!==0) return;
    drag=true; ox=e.clientX-box.offsetLeft; oy=e.clientY-box.offsetTop;
    if(moveHandler) document.removeEventListener("mousemove",moveHandler);
    if(upHandler)   document.removeEventListener("mouseup",  upHandler);
    moveHandler = ev => {
      if(!drag) return;
      box.style.left=  (ev.clientX-ox)+"px";
      box.style.top=   (ev.clientY-oy)+"px";
      box.style.bottom="auto"; box.style.right="auto";
    };
    upHandler = () => {
      drag=false;
      document.removeEventListener("mousemove",moveHandler);
      document.removeEventListener("mouseup",  upHandler);
      moveHandler=upHandler=null;
    };
    document.addEventListener("mousemove",moveHandler);
    document.addEventListener("mouseup",  upHandler);
    e.preventDefault();
  };

  const titleEl  = el("span",{fontWeight:"bold",letterSpacing:"2px",color:"#22D3D9",fontSize:"11px"},"⬡ OSINT Terminal v2.0");
  const controls = el("div", {display:"flex",gap:"6px",alignItems:"center"});
  const minBtn   = el("span",{cursor:"pointer",color:"#ffcc00",fontWeight:"bold",fontSize:"13px"},"─");
  const closeBtn = el("span",{cursor:"pointer",color:"#ff3333",fontWeight:"bold",fontSize:"13px"},"✕");
  let minimized=false;

  minBtn.onclick  = () => {
    minimized=!minimized;
    [tabBar,contentWrap,inputRow].forEach(e=>e.style.display=minimized?"none":e===contentWrap?"flex":"flex");
    statusBar.style.display=minimized?"none":"flex";
    box.style.height=minimized?"30px":"460px";
  };
  closeBtn.onclick = () => destroyTerminal();
  controls.appendChild(minBtn); controls.appendChild(closeBtn);
  header.appendChild(titleEl); header.appendChild(controls);

  // ── Status bar ────────────────────────────────────────────────
  const statusBar   = el("div",{
    padding:"2px 10px", background:"#070C14",
    borderBottom:"1px solid #0C1B26", color:"#5C86A8", fontSize:"11px",
    display:"flex", justifyContent:"space-between", flexShrink:"0"
  });
  const statusLeft  = el("span",{},document.domain||location.hostname);
  const statusRight = el("span",{},new Date().toLocaleTimeString());
  clockTimer = window.setInterval(()=>{ statusRight.textContent=new Date().toLocaleTimeString(); },1000);
  statusBar.appendChild(statusLeft); statusBar.appendChild(statusRight);

  // ── Tabs ──────────────────────────────────────────────────────
  const tabBar = el("div",{
    display:"flex", background:"#070C14",
    borderBottom:"1px solid #123042", flexShrink:"0"
  });

  const makeTab = (id, label) => {
    const t = el("div",{
      padding:"4px 14px", cursor:"pointer", fontSize:"11px",
      fontFamily:"'Courier New',monospace", userSelect:"none",
      borderRight:"1px solid #123042",
      color: id==="scan"?"#22D3D9":"#5C86A8",
      borderBottom: id==="scan"?"2px solid #22D3D9":"2px solid transparent",
      transition:"color 0.1s"
    }, label);
    t.dataset.tab = id;
    t.onclick = () => switchTab(id);
    return t;
  };

  const tabScan     = makeTab("scan",     "SCAN");
  const tabTraffic  = makeTab("traffic",  "TRAFFIC");
  const tabFindings = makeTab("findings", "FINDINGS");
  const tabsMap     = { scan:tabScan, traffic:tabTraffic, findings:tabFindings };
  tabBar.appendChild(tabScan); tabBar.appendChild(tabTraffic); tabBar.appendChild(tabFindings);

  // ── Content panels ────────────────────────────────────────────
  const contentWrap = el("div",{flex:"1",display:"flex",overflow:"hidden",position:"relative"});

  const makePanel = () => el("div",{
    flex:"1", overflowY:"auto", padding:"8px 10px",
    userSelect:"text", lineHeight:"1.65",
    display:"flex", flexDirection:"column",
    position:"absolute", top:"0", left:"0", right:"0", bottom:"0"
  });

  const panelScan     = makePanel();
  const panelTraffic  = makePanel();
  const panelFindings = makePanel();
  panelTraffic.style.display  = "none";
  panelFindings.style.display = "none";
  contentWrap.appendChild(panelScan);
  contentWrap.appendChild(panelTraffic);
  contentWrap.appendChild(panelFindings);

  // Alias for legacy log() calls which always go to SCAN tab
  const out = panelScan;

  const switchTab = (id) => {
    activeTab = id;
    Object.entries(tabsMap).forEach(([tid,tEl])=>{
      const active = tid===id;
      tEl.style.color       = active?"#22D3D9":"#5C86A8";
      tEl.style.borderBottom= active?"2px solid #22D3D9":"2px solid transparent";
    });
    panelScan.style.display     = id==="scan"     ?"flex":"none";
    panelTraffic.style.display  = id==="traffic"  ?"flex":"none";
    panelFindings.style.display = id==="findings" ?"flex":"none";
    if (id==="traffic")  renderTrafficTab();
    if (id==="findings") renderFindingsTab();
  };

  // ── Input row ────────────────────────────────────────────────
  const inputRow = el("div",{
    display:"flex", borderTop:"1px solid #123042",
    padding:"4px 10px", alignItems:"center",
    background:"#070C14", flexShrink:"0"
  });
  const promptEl = el("span",{color:"#14B8C4",marginRight:"6px",fontWeight:"bold"},"❯");
  const input    = el("input",{
    flex:"1", background:"transparent", color:"#22D3D9",
    border:"none", outline:"none",
    fontFamily:"'Courier New',monospace", fontSize:"12px"
  });
  input.setAttribute("placeholder","help | scan | traffic | traffic on | export");
  input.setAttribute("spellcheck","false");
  inputRow.appendChild(promptEl); inputRow.appendChild(input);

  // ── Resize handle (bottom-right corner) ──────────────────────
  const resizeHandle = el("div",{
    position:"absolute", bottom:"0", right:"0",
    width:"14px", height:"14px", cursor:"se-resize",
    background:"transparent", zIndex:"10"
  });
  // draw a small triangle indicator
  resizeHandle.innerHTML = `<svg width="12" height="12" style="position:absolute;bottom:2px;right:2px;opacity:0.35"><polyline points="12,0 12,12 0,12" fill="none" stroke="#22D3D9" stroke-width="1.5"/></svg>`;

  const onResizeMove = e => {
    if (!resizeActive) return;
    const rect = box.getBoundingClientRect();
    const w = Math.max(400, e.clientX - rect.left);
    const h = Math.max(280, e.clientY - rect.top);
    box.style.width  = w+"px";
    box.style.height = h+"px";
  };
  const onResizeUp = () => {
    resizeActive=false;
    document.removeEventListener("mousemove",onResizeMove);
    document.removeEventListener("mouseup",  onResizeUp);
    document.body.style.userSelect="";
  };
  resizeHandle.onmousedown = e => {
    if(e.button!==0) return;
    resizeActive=true;
    document.body.style.userSelect="none";
    document.addEventListener("mousemove",onResizeMove);
    document.addEventListener("mouseup",  onResizeUp);
    e.preventDefault(); e.stopPropagation();
  };

  box.appendChild(header);
  box.appendChild(statusBar);
  box.appendChild(tabBar);
  box.appendChild(contentWrap);
  box.appendChild(inputRow);
  box.appendChild(resizeHandle);
  document.body.appendChild(box);
  input.focus();

  // ═══════════════════════════════════════════════════════════
  // LOG HELPERS  (always write to SCAN panel)
  // ═══════════════════════════════════════════════════════════
  const log = (text, color="#14B8C4") => {
    const d = el("div",{color,wordBreak:"break-all",minHeight:"1em"},text);
    out.appendChild(d);
    out.scrollTop = out.scrollHeight;
  };
  const br  = () => log(" ","#000");
  const sep = (label="") => {
    br();
    const pad  = "─".repeat(Math.max(0,38-label.length));
    const line = el("div",{
      color:"#1a5500", borderTop:"1px solid #0a2200",
      marginTop:"3px", paddingTop:"3px", wordBreak:"break-all"
    },"── "+label+" "+pad);
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  };

  // ── TRAFFIC TAB renderer ──────────────────────────────────────
  const renderTrafficTab = () => {
    panelTraffic.textContent="";

    // filter bar
    const filterRow = el("div",{
      display:"flex",gap:"6px",marginBottom:"6px",flexShrink:"0",flexWrap:"wrap"
    });
    const filters    = ["ALL","AUTH","TOKEN","COOKIE","WS","PM","ERROR"];
    let   activeFilter = "ALL";
    const filterBtns = {};
    filters.forEach(f=>{
      const b = el("div",{
        padding:"2px 8px", cursor:"pointer", fontSize:"10px",
        border:"1px solid #164654", borderRadius:"3px",
        color: f==="ALL"?"#22D3D9":"#5C86A8",
        background:"transparent", fontFamily:"'Courier New',monospace"
      },f);
      b.onclick=()=>{
        activeFilter=f;
        Object.values(filterBtns).forEach(x=>{x.style.color="#5C86A8";x.style.borderColor="#164654";});
        b.style.color="#22D3D9"; b.style.borderColor="#22D3D9";
        renderRows();
      };
      filterBtns[f]=b;
      filterRow.appendChild(b);
    });
    panelTraffic.appendChild(filterRow);

    const tableWrap = el("div",{flex:"1",overflowY:"auto"});
    panelTraffic.appendChild(tableWrap);

    const renderRows = () => {
      tableWrap.textContent="";
      const allItems = [
        ...traffic.map(t=>({...t,_kind:t.kind})),
        ...wsTraffic.map(w=>({...w,_kind:"ws"})),
        ...pmTraffic.map(p=>({...p,_kind:"pm"})),
      ].sort((a,b)=>(a.time||0)-(b.time||0));

      const visible = allItems.filter(item=>{
        if(activeFilter==="ALL") return true;
        const flags = item._kind==="ws"?"WS":item._kind==="pm"?"PM":summarizeTrafficFlags(item).join("|");
        if(activeFilter==="WS")     return item._kind==="ws";
        if(activeFilter==="PM")     return item._kind==="pm";
        if(activeFilter==="AUTH")   return /AUTH|HEADER_AUTH/.test(flags);
        if(activeFilter==="TOKEN")  return /TOKEN/.test(flags);
        if(activeFilter==="COOKIE") return /COOKIE/.test(flags);
        if(activeFilter==="ERROR")  return /ERROR/.test(flags)||item.error;
        return true;
      });

      if(!visible.length){
        const e=el("div",{color:"#5C86A8",padding:"8px"},"No traffic for filter: "+activeFilter);
        tableWrap.appendChild(e); return;
      }

      visible.forEach(item=>{
        const flags  = item._kind==="ws"?"WS":item._kind==="pm"?"PM":summarizeTrafficFlags(item).join(" ");
        const color  = /TOKEN|PRIVATE|JWT|BEARER/.test(flags)?"#f00":/AUTH|HEADER_AUTH|COOKIE/.test(flags)?"#f90":"#0cf";
        const status = item._kind==="ws"?"WS":item._kind==="pm"?"PM":(item.status??"…");
        const method = item.method||(item._kind==="ws"?"WS":item._kind==="pm"?"PM":"");
        const row = el("div",{
          padding:"3px 4px", cursor:"pointer",
          borderBottom:"1px solid #0C1B26",
          fontFamily:"'Courier New',monospace", fontSize:"11px"
        });
        row.appendChild(spanEl(`[${item.id}]`, {color:"#555", marginRight:"4px"}));
        row.appendChild(spanEl(status, {color, marginRight:"5px"}));
        row.appendChild(spanEl(method, {color:"#2a6a2a", marginRight:"5px"}));
        row.appendChild(spanEl(previewVal(displayUrl(item.url||item.origin||"?"),62), {color}));
        if(flags) row.appendChild(spanEl(flags, {color:"#2a4a2a", fontSize:"10px", marginLeft:"6px"}));

        // expand on click
        let expanded=false;
        row.onclick=()=>{
          expanded=!expanded;
          detail.style.display=expanded?"block":"none";
        };
        const detail = el("div",{
          display:"none",
          background:"#070C14", padding:"6px 8px",
          borderBottom:"1px solid #0C1B26",
          color:"#0cf", fontSize:"11px", wordBreak:"break-all"
        });
        if(item._kind==="ws"||item._kind==="pm"){
          detail.textContent = `Origin: ${item.origin||"?"}\nData: ${previewVal(item.data,300)}`;
        } else {
          const hdrs = Object.entries(item.headers||{}).map(([k,v])=>`  ${k}: ${String(v).slice(0,120)}`).join("\n");
          detail.textContent =
            `URL: ${item.url}\nMethod: ${item.method}  Status: ${item.status}  Time: ${item.durationMs??"-"}ms\n`+
            (hdrs?`Headers:\n${hdrs}\n`:"")+
            (item.body?`Body: ${previewVal(String(item.body),200)}\n`:"")+
            (item.response?`Response: ${previewVal(item.response,400)}\n`:"")+
            (item.error?`Error: ${item.error}`:"");
        }
        tableWrap.appendChild(row);
        tableWrap.appendChild(detail);
      });
    };
    renderRows();
  };

  // ── FINDINGS TAB renderer ────────────────────────────────────
  const renderFindingsTab = (filterType=null) => {
    panelFindings.textContent="";

    const all = [...evidenceStore.values()];
    if(!all.length){
      const e=el("div",{color:"#5C86A8",padding:"12px"},"No findings yet. Run scan or enable traffic on.");
      panelFindings.appendChild(e); return;
    }

    // filter row — "HIGH_SEV" is a synthetic filter (severity>=4), not a real evidence type
    const typeList = [...new Set(all.map(e=>e.type))];
    const filterOptions = ["ALL","HIGH_SEV",...typeList];
    let   activeF  = filterType||"ALL";
    const filterRow= el("div",{display:"flex",gap:"5px",marginBottom:"6px",flexWrap:"wrap",flexShrink:"0"});
    const ftBtns   = {};
    const filterLabel = (t) => t==="HIGH_SEV" ? "HIGH" : t;
    const makeFilterBtn = (t) => {
      const b=el("div",{
        padding:"2px 7px",cursor:"pointer",fontSize:"10px",
        border:`1px solid ${t==="ALL"?"#22D3D9":"#164654"}`,borderRadius:"3px",
        color: t===activeF?"#22D3D9":"#5C86A8",
        background:"transparent",fontFamily:"'Courier New',monospace"
      },filterLabel(t));
      b.onclick=()=>{
        activeF=t;
        Object.values(ftBtns).forEach(x=>{x.style.color="#5C86A8";x.style.borderColor="#164654";});
        b.style.color="#22D3D9"; b.style.borderColor="#22D3D9";
        renderFRows();
      };
      ftBtns[t]=b; return b;
    };
    filterOptions.slice(0,11).forEach(t=>filterRow.appendChild(makeFilterBtn(t)));
    panelFindings.appendChild(filterRow);

    // summary counts
    const hi = all.filter(e=>e.severity>=4).length;
    const me = all.filter(e=>e.severity===3).length;
    const lo = all.filter(e=>e.severity<=2).length;
    const summary = el("div",{
      color:"#555",fontSize:"11px",marginBottom:"4px",flexShrink:"0"
    },`${all.length} total  ⚠${hi} HIGH  ${me} MED  ${lo} LOW  — click row to expand`);
    panelFindings.appendChild(summary);

    const tableWrap=el("div",{flex:"1",overflowY:"auto"});
    panelFindings.appendChild(tableWrap);

    const renderFRows = () => {
      tableWrap.textContent="";
      const visible = activeF==="ALL" ? all
                    : activeF==="HIGH_SEV" ? all.filter(e=>e.severity>=4)
                    : all.filter(e=>e.type===activeF);
      // sort by severity desc
      visible.sort((a,b)=>b.severity-a.severity).forEach(e=>{
        const sevColor = e.severity>=5?"#ff3333":e.severity===4?"#ff6600":e.severity===3?"#f90":"#555";
        const sevLabel = ["","LOW","LOW","MED","HIGH","CRIT"][Math.min(e.severity,5)]||"?";
        const row = el("div",{
          padding:"3px 4px", borderBottom:"1px solid #0C1B26",
          cursor:"pointer", fontFamily:"'Courier New',monospace", fontSize:"11px"
        });
        row.appendChild(spanEl(sevLabel, {color:sevColor, minWidth:"38px", display:"inline-block"}));
        row.appendChild(spanEl(e.type, {color:"#0cf", marginRight:"5px"}));
        row.appendChild(spanEl(previewVal(e.sample,52), {color:"#2a6a2a"}));

        let expanded=false;
        const detail=el("div",{
          display:"none",background:"#070C14",padding:"6px 8px",
          borderBottom:"1px solid #0C1B26",
          color:"#0cf",fontSize:"11px",wordBreak:"break-all"
        });
        detail.textContent =
          `Label:    ${e.label}\n`+
          `Location: ${e.location}\n`+
          `Source:   ${e.source}\n`+
          `Sample:   ${e.sample.slice(0,160)}\n`+
          `Count:    ${e.count}  firstSeen: ${new Date(e.firstSeen).toLocaleTimeString()}\n`+
          (e.requestIds?.length?`Requests: ${e.requestIds.slice(0,5).join(", ")}\n`:"")+
          (e.jwt?
            `JWT alg:${e.jwt.header?.alg||"?"}  sub:${e.jwt.payload?.sub||"-"}  `+
            `${e.jwt.expired===true?"EXPIRED ⚠":e.jwt.expired===false?`valid ~${Math.floor(e.jwt.expiresInSec/60)}m`:"no-exp"}\n`:"")+
          (e.jwt?.algNone?"⚠⚠ alg:none — signature bypassed\n":"");

        row.onclick=()=>{ expanded=!expanded; detail.style.display=expanded?"block":"none"; };
        tableWrap.appendChild(row);
        tableWrap.appendChild(detail);
      });
    };
    renderFRows();
  };

  // ═══════════════════════════════════════════════════════════
  // EVIDENCE STORE
  // ═══════════════════════════════════════════════════════════
  const addEvidence = ({type,label,severity,source,location,field,sample,requestId=null}) => {
    const key = `${type}::${String(sample||"").slice(0,40)}`;
    const now = nowMs();
    if (evidenceStore.has(key)) {
      const e=evidenceStore.get(key);
      e.lastSeen=now; e.count++;
      if(requestId&&!e.requestIds.includes(requestId)) e.requestIds.push(requestId);
      return e;
    }
    const id   = `E${nextEvidenceId++}`;
    const item = {
      id,type,label,severity,
      source:String(source||""), location:String(location||""), field:String(field||""),
      sample:String(sample||"").slice(0,200),
      firstSeen:now, lastSeen:now, count:1,
      requestId, requestIds:requestId?[requestId]:[],
      jwt:null
    };
    evidenceStore.set(key,item);
    // evict oldest (Map preserves insertion order) once over the cap
    if(evidenceStore.size>MAX_EVIDENCE) evidenceStore.delete(evidenceStore.keys().next().value);
    // refresh findings tab badge
    updateTabBadge();
    return item;
  };

  const allEvidence    = ()     => [...evidenceStore.values()];
  const evidenceByType = (type) => allEvidence().filter(e=>e.type===type);

  const updateTabBadge = () => {
    const n=evidenceStore.size;
    tabFindings.textContent = n ? `FINDINGS (${n})` : "FINDINGS";
  };

  // ═══════════════════════════════════════════════════════════
  // JWT INTELLIGENCE
  // ═══════════════════════════════════════════════════════════
  const decodeJWT = (token) => {
    try {
      const parts=token.split(".");
      if(parts.length!==3) return null;
      const decode=str=>{
        const p=str.replace(/-/g,"+").replace(/_/g,"/");
        return JSON.parse(atob(p+"=".repeat((4-p.length%4)%4)));
      };
      const header =decode(parts[0]);
      const payload=decode(parts[1]);
      const nowSec =Math.floor(Date.now()/1000);
      const expired      =(typeof payload.exp==="number")?payload.exp<nowSec:null;
      const notYetValid  =(typeof payload.nbf==="number")?payload.nbf>nowSec:false;
      const expiresInSec =(typeof payload.exp==="number")?payload.exp-nowSec:null;
      const algNone      = /^none$/i.test(header.alg||"");
      const algConfusion = header.alg==="HS256"&&typeof payload.iss==="string";
      return {header,payload,expired,notYetValid,expiresInSec,algNone,algConfusion};
    } catch { return null; }
  };

  const formatJwtTime = (value) => {
    if(typeof value!=="number") return "-";
    try { return new Date(value*1000).toLocaleString(); } catch { return String(value); }
  };

  const formatJwtField = (value, maxLen=22) => {
    if(Array.isArray(value)) return previewVal(value.join(","), maxLen);
    if(value===undefined || value===null || value==="") return "-";
    return previewVal(String(value), maxLen);
  };

  const jwtSummaryLines = (jwt) => {
    if(!jwt) return [];
    const {header,payload,expired,notYetValid,expiresInSec,algNone,algConfusion}=jwt;
    const ttl = typeof expiresInSec==="number" ? Math.max(0, Math.floor(expiresInSec/60)) : null;
    const expState = expired===true ? "EXPIRED" : expired===false ? `valid ~${ttl}m` : "no-exp";
    const lines = [
      { text:`alg:${header.alg||"?"} typ:${header.typ||"?"} kid:${formatJwtField(header.kid,18)} ${expState}`, color:algNone||expired?"#f00":"#f90" },
      { text:`sub:${formatJwtField(payload.sub,20)} iss:${formatJwtField(payload.iss,18)} aud:${formatJwtField(payload.aud,18)}`, color:"#f90" },
      { text:`exp:${formatJwtTime(payload.exp)} iat:${formatJwtTime(payload.iat)} nbf:${formatJwtTime(payload.nbf)}`, color:"#555" },
    ];
    if(notYetValid) lines.push({ text:"not-yet-valid (nbf in future)", color:"#f90" });
    if(algNone) lines.push({ text:"alg:none detected", color:"#f00" });
    if(algConfusion) lines.push({ text:"HS256 token with issuer present - review algorithm assumptions", color:"#f00" });
    return lines;
  };

  // ═══════════════════════════════════════════════════════════
  // RULE ENGINE  (TruffleHog-inspired)
  // ═══════════════════════════════════════════════════════════
  const RULES = [
    { id:"JWT",          label:"JWT Token",         keywords:["eyJ"],                               severity:4, isJWT:true,
      regex:/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g },
    { id:"BEARER",       label:"Bearer Token",      keywords:["bearer","Bearer"],                    severity:4,
      regex:/[Bb]earer\s+([A-Za-z0-9\-_.~+/]+=*)/g, cap:1 },
    { id:"AWS_ACCESS",   label:"AWS Access Key",    keywords:["AKIA","ASIA","AROA","AIDA"],          severity:5,
      regex:/(?:AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}/g },
    { id:"AWS_SECRET",   label:"AWS Secret Key",    keywords:["aws","AWS","secret"],                 severity:5, entropyMin:4.5,
      regex:/(?:aws)[_\-. ]?(?:secret)[_\-. ]?(?:key)["'\s:=]+["']?([A-Za-z0-9+/]{40})/gi, cap:1 },
    { id:"GCP_KEY",      label:"GCP API Key",       keywords:["AIza"],                              severity:4,
      regex:/AIza[0-9A-Za-z\-_]{35}/g },
    { id:"GITHUB_TOKEN", label:"GitHub Token",      keywords:["ghp_","gho_","ghu_","ghs_"],         severity:5,
      regex:/gh[pousr]_[A-Za-z0-9_]{36,}/g },
    { id:"SLACK_TOKEN",  label:"Slack Token",       keywords:["xox"],                               severity:4,
      regex:/xox[baprs]-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{23,24}/g },
    { id:"STRIPE_KEY",   label:"Stripe Key",        keywords:["sk_live","pk_live","sk_test"],        severity:5,
      regex:/(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{24,}/g },
    { id:"SENDGRID",     label:"SendGrid Key",      keywords:["SG."],                               severity:4,
      regex:/SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g },
    { id:"TWILIO_KEY",   label:"Twilio Key",        keywords:["SK","AC"],                           severity:5,
      regex:/(?:SK|AC)[0-9a-fA-F]{32}/g },
    { id:"MAILCHIMP_KEY",label:"MailChimp Key",     keywords:["-us"],                               severity:4,
      regex:/[0-9a-f]{32}-us[0-9]{1,2}/g },
    { id:"TELEGRAM_BOT", label:"Telegram Bot Token",keywords:["bot"],                               severity:4,
      regex:/[0-9]{9,10}:[a-zA-Z0-9_-]{35}/g },
    { id:"GOOGLE_OAUTH", label:"Google OAuth ID",   keywords:["apps.googleusercontent.com"],        severity:4,
      regex:/[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com/g },
    { id:"PRIVATE_KEY",  label:"Private Key",       keywords:["BEGIN","PRIVATE KEY"],               severity:5,
      regex:/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
    { id:"CSRF_TOKEN",   label:"CSRF Token",        keywords:["csrf","xsrf","_token"],              severity:3,
      regex:/(?:csrf|xsrf)[_\-]?token["'\s:=]+["']?([A-Za-z0-9\-_]{16,})/gi, cap:1 },
    { id:"SESSION_ID",   label:"Session ID",        keywords:["PHPSESSID","JSESSIONID","session_id"],severity:3,
      regex:/(?:PHPSESSID|JSESSIONID|session[_\-]?id)["'\s:=]+["']?([A-Za-z0-9\-_]{16,})/gi, cap:1 },
    { id:"API_KEY",      label:"API Key",           keywords:["api_key","apikey","api-key","x-api-key"],severity:3,
      regex:/(?:api[_\-. ]?(?:key|token)|x[_\-]api[_\-]key)["'\s:=]+["']?([A-Za-z0-9\-_]{20,})/gi,
      cap:1, entropyMin:3.5,
      excludeWords:["example","placeholder","your_","todo","xxxx","1234","abcd","changeme","insert","replace","dummy","test123"] },
    { id:"OAUTH_TOKEN",  label:"OAuth Token",       keywords:["access_token","refresh_token","id_token"],severity:4,
      regex:/(?:access_token|refresh_token|id_token)["'\s:=]+["']?([A-Za-z0-9\-_.]{20,})/gi, cap:1, entropyMin:3.5 },
  ];

  const HE_CONTEXT_RE  = /(?:token|key|secret|auth|password|credential|api|jwt|bearer|session|access|refresh|private|sign)/i;
  const HE_FP_PATTERNS = [/^[0-9a-f]{32,64}$/i, /^[A-Z][A-Za-z]{20,}$/, /^[a-z]{24,}$/, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i];

  const keywordPreflight = (text,keywords) => {
    const l=text.toLowerCase();
    return keywords.some(kw=>l.includes(kw.toLowerCase()));
  };

  const analyzeText = (text,source,locationCtx="body",requestId=null) => {
    if(!text||typeof text!=="string"||text.length<4) return [];
    const results=[];
    const isHeader=locationCtx.startsWith("header");

    RULES.forEach(rule=>{
      if(!keywordPreflight(text,rule.keywords)) return;
      let m;
      rule.regex.lastIndex=0;
      try {
        while((m=rule.regex.exec(text))!==null){
          const raw=m[0], value=rule.cap?(m[rule.cap]||raw):raw;
          if(!value||value.length<8) continue;
          if(rule.excludeWords&&rule.excludeWords.some(w=>value.toLowerCase().includes(w))) continue;
          if(isDummyValue(value)) continue;
          if(rule.entropyMin&&entropy(value)<rule.entropyMin) continue;
          const ev=addEvidence({
            type:rule.id, label:rule.label, severity:rule.severity,
            source, location:`${locationCtx}:${source}`, field:rule.id,
            sample:value, requestId
          });
          if(rule.isJWT){ const j=decodeJWT(value); if(j) ev.jwt=j; }
          results.push(ev);
        }
      } catch(e) {}
      rule.regex.lastIndex=0;
    });

    // High-entropy generic (body only, with mandatory context window)
    if(!isHeader&&text.length>60){
      const tokens=text.match(/[A-Za-z0-9+/\-_]{24,}/g)||[];
      tokens.forEach(w=>{
        if(HE_FP_PATTERNS.some(p=>p.test(w))) return;
        const ent=entropy(w);
        if(ent<4.6) return;
        const idx=text.indexOf(w);
        const ctx=text.slice(Math.max(0,idx-80),idx);
        if(!HE_CONTEXT_RE.test(ctx)) return;
        addEvidence({
          type:"HIGH_ENTROPY", label:"High-Entropy String", severity:2,
          source, location:`body:${source}`, field:"entropy", sample:w, requestId
        });
      });
    }
    return results;
  };

  // ═══════════════════════════════════════════════════════════
  // SECURITY HEADERS AUDIT  (Level B — new)
  // ═══════════════════════════════════════════════════════════
  const SEC_HEADERS = [
    "content-security-policy","strict-transport-security",
    "x-frame-options","x-content-type-options",
    "referrer-policy","permissions-policy","cross-origin-opener-policy",
    "cross-origin-resource-policy","cross-origin-embedder-policy"
  ];

  const auditSecurityHeaders = (respHeaders, url, requestId) => {
    const found={}, missing=[];
    SEC_HEADERS.forEach(h=>{
      const v=respHeaders[h]||respHeaders[h.split("-").map((w,i)=>i===0?w:w[0].toUpperCase()+w.slice(1)).join("")];
      if(v) found[h]=v; else missing.push(h);
    });

    // CORS misconfiguration detection
    const acao = respHeaders["access-control-allow-origin"]||"";
    const acac = (respHeaders["access-control-allow-credentials"]||"").toLowerCase();
    const corsRisks=[];
    if(acao==="*") corsRisks.push("ACAO:* (wildcard)");
    if(acao==="*"&&acac==="true") corsRisks.push("ACAO:* + ACAC:true (credentials leak)");
    if(acao&&acao!=="*"&&acac==="true") corsRisks.push(`ACAO:${acao} + ACAC:true (reflect+creds)`);

    if(corsRisks.length){
      corsRisks.forEach(r=>addEvidence({
        type:"CORS_MISCFG", label:"CORS Misconfiguration", severity:4,
        source:url, location:"header:CORS", field:"access-control-allow-origin",
        sample:r, requestId
      }));
    }

    // Note missing critical headers
    const critical=["content-security-policy","strict-transport-security","x-frame-options"];
    critical.filter(h=>missing.includes(h)).forEach(h=>addEvidence({
      type:"MISSING_HEADER", label:`Missing ${h}`, severity:2,
      source:url, location:"header:security", field:h,
      sample:`${h} not present`, requestId
    }));

    // CSP is recon gold — parse it
    const csp=found["content-security-policy"]||"";
    if(csp){
      // Extract all domains from CSP as trusted hosts
      const cspHosts=[...csp.matchAll(/https?:\/\/([a-zA-Z0-9.\-]+)/g)].map(m=>m[1]);
      const interesting=cspHosts.filter(h=>!isNoisyHost(h)&&h!==rootHost&&!h.endsWith("."+rootHost));
      if(interesting.length){
        addEvidence({
          type:"CSP_TRUSTED_HOST", label:"CSP Trusted External Host", severity:2,
          source:url, location:"header:CSP", field:"content-security-policy",
          sample:interesting.slice(0,5).join(", "), requestId
        });
      }
    }

    const entry={url,found,missing:missing.filter(h=>critical.includes(h)),corsRisks};
    if(!secHeaderLog.some(e=>e.url===url)) pushCapped(secHeaderLog,entry,MAX_SECHEADERS);
    return entry;
  };

  // ═══════════════════════════════════════════════════════════
  // GRAPHQL INFERENCE  (Level D — new)
  // ═══════════════════════════════════════════════════════════
  const inferGraphQL = (body, url, requestId) => {
    if(!body||typeof body!=="string") return;
    try {
      const parsed = JSON.parse(body);
      const extract = (obj) => {
        if(!obj||typeof obj!=="object") return;
        const q = obj.query||obj.mutation||obj.subscription;
        const op= obj.operationName;
        if(typeof q==="string"&&q.length>4){
          const type = /^\s*mutation/i.test(q)?"mutation":/^\s*subscription/i.test(q)?"subscription":"query";
          const entry={type,operationName:op||"(anonymous)",query:q.slice(0,300),url,requestId,time:nowMs()};
          if(!graphqlOps.some(e=>e.operationName===entry.operationName&&e.type===type)){
            pushCapped(graphqlOps,entry,MAX_GRAPHQL);
            addEvidence({
              type:"GRAPHQL_OP", label:`GraphQL ${type}`, severity:2,
              source:url, location:"body:request", field:op||type,
              sample:`${type} ${op||"(anon)"}: ${q.slice(0,80)}`, requestId
            });
          }
        }
        // handle batched operations
        if(Array.isArray(obj)) obj.forEach(extract);
      };
      extract(parsed);
    } catch(e) {}
  };

  // ═══════════════════════════════════════════════════════════
  // COOKIE + STORAGE AUDIT
  // ═══════════════════════════════════════════════════════════
  const INTERESTING_KEY_RE = /(token|auth|jwt|session|bearer|secret|csrf|refresh|key|password|credential|api|access)/i;

  const containsSecretValue = (v) => {
    const t=String(v||"");
    return /Bearer\s+[A-Za-z0-9\-._]+/i.test(t)
        || /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/.test(t)
        || /AKIA[0-9A-Z]{16}/.test(t)
        || /(?:token|secret|session|jwt|auth|csrf|refresh)['":\s=]+[A-Za-z0-9\-_.]{16,}/i.test(t);
  };

  const auditCookies = () => {
    const cookies=[];
    (document.cookie||"").split(";").forEach(raw=>{
      const tr=raw.trim(); if(!tr) return;
      const eqIdx=tr.indexOf("=");
      const name= eqIdx===-1?tr:tr.slice(0,eqIdx);
      const value=eqIdx===-1?"":tr.slice(eqIdx+1);
      if (isDummyValue(value) && value.length > 0) return;
      const risks=[];
      risks.push({flag:"HttpOnly",status:"MISSING",detail:"Visible in document.cookie → XSS stealable"});
      if(location.protocol==="http:") risks.push({flag:"Secure",status:"LIKELY_MISSING",detail:"HTTP page"});
      const notes=[];
      if(name.startsWith("__Host-"))   notes.push("__Host- prefix ✓");
      else if(name.startsWith("__Secure-")) notes.push("__Secure- prefix ✓");
      else notes.push("No cookie prefix");
      const sensitive=/session|token|jwt|auth|csrf|refresh|sid|user|id/i.test(name);
      const jwtData=value?decodeJWT(value):null;
      const severity=sensitive?"HIGH":(value.length>20&&entropy(value)>3.5)?"MEDIUM":"LOW";
      cookies.push({name,value:previewVal(value,60),risks,notes,severity,isJWT:!!jwtData,jwtData});
      addEvidence({
        type:"COOKIE", label:"JS-Accessible Cookie (no HttpOnly)",
        severity:sensitive?4:2,
        source:"document.cookie", location:"cookie:client", field:name,
        sample:`${name}=${value.slice(0,40)}`
      });
    });
    return cookies;
  };

  const parseSetCookieHeader = (header, url, requestId) => {
    if(!header) return null;
    const parts=header.split(";").map(p=>p.trim());
    const [nv,...attrParts]=parts;
    const eqIdx=nv.indexOf("=");
    const name =eqIdx===-1?nv:nv.slice(0,eqIdx);
    const value=eqIdx===-1?"":nv.slice(eqIdx+1);
    const attrs={};
    attrParts.forEach(attr=>{
      const lower=attr.toLowerCase();
      if(lower==="secure")              attrs.secure=true;
      else if(lower==="httponly")       attrs.httpOnly=true;
      else if(lower.startsWith("samesite=")) attrs.sameSite=attr.split("=")[1];
      else if(lower.startsWith("path="))    attrs.path=attr.split("=").slice(1).join("=");
      else if(lower.startsWith("domain="))  attrs.domain=attr.split("=")[1];
      else if(lower.startsWith("max-age=")) attrs.maxAge=parseInt(attr.split("=")[1]);
    });
    const risks=[];
    if(!attrs.httpOnly)  risks.push("HttpOnly missing");
    if(!attrs.secure)    risks.push("Secure missing");
    if(!attrs.sameSite)  risks.push("SameSite missing");
    else if(attrs.sameSite.toLowerCase()==="none"&&!attrs.secure) risks.push("SameSite=None without Secure");
    if(attrs.maxAge>86400*30) risks.push(`Long Max-Age (${Math.floor(attrs.maxAge/86400)}d)`);
    if(attrs.domain&&attrs.domain.startsWith(".")) risks.push(`Broad Domain=.${attrs.domain}`);
    const sensitive=/session|token|jwt|auth|csrf|refresh|sid/i.test(name);
    const sev=sensitive&&risks.length?4:risks.length?3:1;
    addEvidence({
      type:"SET_COOKIE", label:"Set-Cookie Header",
      severity:sev, source:url, location:"header:Set-Cookie", field:name,
      sample:`${name}=…; ${Object.keys(attrs).join("; ")}`, requestId
    });
    return {name,value:value.slice(0,60),...attrs,risks,sensitive,url,requestId};
  };

  const scanStorage = () => {
    const rows=[];
    [["localStorage",window.localStorage],["sessionStorage",window.sessionStorage]].forEach(([storeName,store])=>{
      try {
        for(let i=0;i<store.length;i++){
          const key=store.key(i), value=store.getItem(key)||"";
          if (isDummyValue(value)) continue;
          if(!INTERESTING_KEY_RE.test(key)&&!containsSecretValue(value)) continue;
          const jwtData=decodeJWT(value), ent=entropy(value);
          analyzeText(value,`${storeName}.${key}`,"storage:value");
          addEvidence({
            type:"STORAGE_TOKEN", label:`${storeName} sensitive key`,
            severity:jwtData?4:(ent>4.0?3:2),
            source:storeName, location:`storage:${storeName}`, field:key, sample:value.slice(0,100)
          });
          rows.push({store:storeName,key,value:previewVal(value,80),isJWT:!!jwtData,jwtData,entropy:ent.toFixed(2)});
        }
      } catch(e) {}
    });
    return rows;
  };

  // ═══════════════════════════════════════════════════════════
  // INDEXEDDB + WINDOW GLOBALS
  // ═══════════════════════════════════════════════════════════
  const scanIndexedDB = async () => {
    const results=[];
    try {
      const dbs=await indexedDB.databases();
      for(const dbInfo of dbs){
        if(dbInfo.name===DB_OWN_NAME) continue;
        const entry={db:dbInfo.name,version:dbInfo.version,stores:[],sensitive:[],error:null};
        results.push(entry);
        await new Promise(resolve=>{
          try {
            const req=indexedDB.open(dbInfo.name);
            req.onsuccess=e=>{
              const db=e.target.result;
              entry.stores=Array.from(db.objectStoreNames);
              let pending=entry.stores.length;
              if(!pending){db.close();resolve();return;}
              entry.stores.forEach(storeName=>{
                try {
                  const tx=db.transaction(storeName,"readonly");
                  const gr=tx.objectStore(storeName).getAll();
                  gr.onsuccess=ev=>{
                    (ev.target.result||[]).slice(0,20).forEach(item=>{
                      try {
                        const str=JSON.stringify(item);
                        if(INTERESTING_KEY_RE.test(str)||containsSecretValue(str)){
                          entry.sensitive.push({store:storeName,preview:str.slice(0,120)});
                          addEvidence({type:"INDEXEDDB",label:"IndexedDB Sensitive Data",severity:3,
                            source:dbInfo.name,location:`indexedDB:${dbInfo.name}.${storeName}`,
                            field:storeName,sample:str.slice(0,80)});
                        }
                        if(item&&item.type==="secret"&&item.extractable===true)
                          addEvidence({type:"CRYPTOKEY",label:"Extractable CryptoKey",severity:4,
                            source:dbInfo.name,location:`indexedDB:${dbInfo.name}.${storeName}`,
                            field:storeName,sample:`CryptoKey extractable:true alg:${item.algorithm?.name||"?"}`});
                      } catch(e) {}
                    });
                    pending--; if(pending===0){db.close();resolve();}
                  };
                  gr.onerror=()=>{pending--;if(pending===0){db.close();resolve();}};
                } catch(e){pending--;if(pending===0){db.close();resolve();}}
              });
            };
            req.onerror=()=>{entry.error="open error";resolve();};
          } catch(e){entry.error=String(e);resolve();}
        });
      }
    } catch(e){
      results.push({db:"N/A",stores:[],sensitive:[],error:"indexedDB.databases() not supported"});
    }
    return results;
  };

  const WINDOW_GLOBAL_DENYLIST = new Set([
    "__cfBeacon","__cf_chl_opt","__cfduid",
    "IS_KEY","FuncKeys","DEFAULT_OPEN_HOTKEY","HOTKEY",
    "Drupal","drupalSettings","drupalTranslations",
    "jQuery","$","_","__","___",
    "ga","gtag","dataLayer","google_tag_manager",
    "FB","fbq","_fbq","fbAsyncInit",
    "Intercom","intercomSettings","hj","hjSiteSettings","_hjSettings",
    "mixpanel","amplitude","heap","clarity","__uuidv4","__hsVars",
  ]);

  const scanWindowGlobals = () => {
    const results=[];
    try {
      const iframe=document.createElement("iframe");
      iframe.style.cssText="display:none;width:0;height:0;border:0;";
      document.body.appendChild(iframe);
      const cleanProps=new Set(Object.getOwnPropertyNames(iframe.contentWindow));
      const currentKeys=Object.getOwnPropertyNames(window);
      document.body.removeChild(iframe);
      currentKeys.filter(k=>!cleanProps.has(k)&&!WINDOW_GLOBAL_DENYLIST.has(k)).forEach(key=>{
        try {
          const val=window[key];
          if(val===undefined||val===null||typeof val==="function") return;
          let str; try{str=JSON.stringify(val);}catch{return;}
          if(!str||str.length<5||str==="{}"||str==="[]") return;
          if (isDummyValue(str)) return;
          if(!INTERESTING_KEY_RE.test(key)&&!containsSecretValue(str)) return;
          results.push({key,type:typeof val,preview:str.slice(0,120)});
          addEvidence({type:"WINDOW_GLOBAL",label:"Sensitive window global",severity:3,
            source:"window",location:"window:global",field:key,sample:str.slice(0,120)});
        } catch(e) {}
      });
    } catch(e) {}
    return results;
  };

  // ═══════════════════════════════════════════════════════════
  // SERVICE WORKER INSPECTION  (Level A — new)
  // ═══════════════════════════════════════════════════════════
  const scanServiceWorkers = async () => {
    const results=[];
    try {
      if(!navigator.serviceWorker) return results;
      const regs=await navigator.serviceWorker.getRegistrations();
      for(const reg of regs){
        const sw  = reg.active||reg.installing||reg.waiting;
        const entry={
          scope:reg.scope, state:sw?.state||"unknown",
          scriptURL:sw?.scriptURL||"",
          stale:false, sensitive:[]
        };
        // try fetch script content if same-origin
        if(sw?.scriptURL&&isFirstParty(sw.scriptURL)){
          try {
            const res=await originalFetch(sw.scriptURL,{credentials:"omit"});
            if(res.ok){
              const text=await res.text();
              // look for secrets, credentials, tokens cached in SW
              const findings=analyzeText(text.slice(0,60000),sw.scriptURL,"script");
              entry.sensitive=findings.map(f=>f.label);
              // check for long cache TTLs
              if(/cacheFirst|cacheOnly|cache\.put/i.test(text))
                entry.stale=true;
            }
          } catch(e) {}
        }
        results.push(entry);
        addEvidence({
          type:"SERVICE_WORKER", label:"Service Worker registered", severity:entry.sensitive.length?4:2,
          source:reg.scope, location:"serviceWorker:registration", field:sw?.state||"?",
          sample:`scope:${reg.scope} script:${sw?.scriptURL||"?"}`
        });
      }
    } catch(e) {}
    return results;
  };

  // ═══════════════════════════════════════════════════════════
  // SCRIPT CONTENT ANALYSIS  (LinkFinder + SubDomainizer)
  // ═══════════════════════════════════════════════════════════
  const LF_ENDPOINT_RE = /["'`]((?:https?:\/\/[a-zA-Z0-9.\-_/?=&%#:@!$,;~]{8,150}|\/[a-zA-Z0-9_\-/.?=&%#:@]{4,120}))["'`]/g;

  const lf_isFPPath = (p) => {
    if(!p||p.length<4||p.length>150)         return true;
    if(/[{}\\\s<>|^[\]]/.test(p))            return true;
    if(/\.\w{15,}/.test(p))                   return true;
    if(/^\/\d+$/.test(p))                     return true;
    if((p.match(/\//g)||[]).length>8)          return true;
    if(/[A-Za-z0-9]{40,}/.test(p))            return true;
    if(/\.(png|jpg|jpeg|gif|svg|ico|webp|css|woff|woff2|ttf|eot|mp4|webm|mp3|wav)$/i.test(p.split('?')[0])) return true;
    return false;
  };

  const CLOUD_PATTERNS=[
    {name:"AWS S3",         regex:/(?:[a-z0-9][\w\-]{1,61}[a-z0-9])\.s3(?:[\-.][\w\-]+)?\.amazonaws\.com/gi},
    {name:"AWS CloudFront", regex:/[a-z0-9]{13,14}\.cloudfront\.net/gi},
    {name:"Azure Blob",     regex:/[a-z0-9]{3,24}\.blob\.core\.windows\.net/gi},
    {name:"GCP Storage",    regex:/(?:storage\.googleapis\.com\/[a-z0-9][\w\-]{1,61}|[a-z0-9][\w\-]{1,61}\.storage\.googleapis\.com)/gi},
    {name:"DigitalOcean",   regex:/[a-z0-9][\w\-]{1,61}\.(?:[a-z0-9\-]+\.)?digitaloceanspaces\.com/gi},
  ];

  const analyzeScriptContent = (text, srcUrl) => {
    const endpoints=new Set(), cloud=[], subdomains=new Set();
    LF_ENDPOINT_RE.lastIndex=0;
    let m;
    while((m=LF_ENDPOINT_RE.exec(text))!==null){
      const raw=m[1]; if(lf_isFPPath(raw)) continue;
      try{ const abs=new URL(raw,location.href).href; if(isInteresting(abs)) endpoints.add(abs); }
      catch{ if(/^\//.test(raw)&&isInteresting(raw)) endpoints.add(raw); }
    }
    LF_ENDPOINT_RE.lastIndex=0;
    CLOUD_PATTERNS.forEach(({name,regex})=>{
      regex.lastIndex=0; let cm;
      while((cm=regex.exec(text))!==null){
        cloud.push({type:name,host:cm[0],source:srcUrl});
        addEvidence({type:"CLOUD_ASSET",label:`Cloud Asset (${name})`,severity:3,
          source:srcUrl,location:"script:content",field:name,sample:cm[0]});
      }
      regex.lastIndex=0;
    });
    const subRe=new RegExp(`([a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.${rootHost.replace(/\./g,"\\.")})`, "gi");
    let sm;
    while((sm=subRe.exec(text))!==null){
      const sub=sm[1].toLowerCase();
      if(sub===rootHost||sub===`www.${rootHost}`) continue;
      if(/[A-Z]{3,}/.test(sm[1])||/\d{4,}/.test(sub)) continue;
      subdomains.add(sub);
    }
    analyzeText(text,srcUrl,"script");
    return {endpoints:[...endpoints],cloud,subdomains:[...subdomains]};
  };

  const fetchAndAnalyzeScripts = async () => {
    const scripts=[...document.querySelectorAll("script[src]")]
                   .map(s=>s.src).filter(src=>isFirstParty(src)).slice(0,6);
    const allEps=new Set(), allCloud=[], allSubs=new Set();
    await Promise.all(scripts.map(async src=>{
      try {
        const res=await originalFetch(src,{credentials:"omit"});
        if(!res.ok) return;
        const text=await res.text();
        const {endpoints,cloud,subdomains}=analyzeScriptContent(text.slice(0,120000),src);
        endpoints.forEach(e=>allEps.add(e));
        cloud.forEach(c=>allCloud.push(c));
        subdomains.forEach(s=>allSubs.add(s));
      } catch(e) {}
    }));
    return {endpoints:[...allEps],cloud:allCloud,subdomains:[...allSubs]};
  };

  // ═══════════════════════════════════════════════════════════
  // DOM COLLECTORS
  // ═══════════════════════════════════════════════════════════
  const collectFormItems = () =>
    [...document.querySelectorAll("form")].map((form,i)=>{
      const fields=[...form.querySelectorAll("input,select,textarea")].map(f=>({
        name:f.name||f.id||"",type:(f.type||f.tagName||"text").toLowerCase(),placeholder:f.placeholder||""
      }));
      const interesting=fields.filter(f=>
        f.type==="password"||f.type==="email"||
        INTERESTING_KEY_RE.test(f.name)||INTERESTING_KEY_RE.test(f.placeholder)
      );
      if(!interesting.length) return null;
      return{index:i+1,action:form.action||location.href,
        method:(form.method||"GET").toUpperCase(),
        fields:interesting.slice(0,8).map(f=>({name:f.name||"(no-name)",type:f.type}))};
    }).filter(Boolean);

  const collectEndpoints = () => {
    const candidates=dedupeStrings([
      ...[...document.querySelectorAll("a[href]")].map(a=>a.href),
      ...[...document.querySelectorAll("form[action]")].map(f=>f.action),
      ...[...document.querySelectorAll("script[src]")].map(s=>s.src),
      ...traffic.map(t=>t.url),
    ]);
    return {
      firstParty: candidates.filter(u=>isFirstParty(u)&&isInteresting(u)).slice(0,15),
      external:   candidates.filter(u=>{const h=getHost(u);return h&&!isFirstParty(u)&&!isNoisyHost(h)&&isInteresting(u);}).slice(0,10)
    };
  };

  const collectExternals = () => dedupeStrings(
    [...document.querySelectorAll("a[href]")].map(a=>getHost(a.href))
      .filter(h=>h&&h!==rootHost&&!h.endsWith("."+rootHost)&&!isNoisyHost(h))
  ).slice(0,15);

  const collectTech = () => {
    const html=document.documentElement.outerHTML;
    const cookies=(document.cookie||"").toLowerCase();
    return [
      ["React",  ()=>!!(window.React||document.querySelector("[data-reactroot],[data-react-helmet]")||html.includes("react"))],
      ["Vue",    ()=>!!(window.Vue||html.includes("vue.")||html.includes("data-v-"))],
      ["Angular",()=>!!(window.ng||document.querySelector("[ng-app],[ng-version]")||html.includes("angular"))],
      ["Svelte", ()=>!!(window.__svelte||html.includes("__SVELTEKIT")||html.includes("svelte"))],
      ["jQuery", ()=>!!(window.jQuery||window.$?.fn?.jquery)],
      ["Next.js",()=>!!(window.__NEXT_DATA__||html.includes("__NEXT_DATA__"))],
      ["Nuxt",   ()=>!!(window.__NUXT__||html.includes("__NUXT__"))],
      ["Vite",   ()=>html.includes("/@vite/client")||html.includes("__vite")],
      ["Webpack",()=>html.includes("__webpack_require__")||html.includes("webpackJsonp")],
      ["GraphQL",()=>html.includes("graphql")],
      ["WordPress",()=>html.includes("/wp-content/")],
      ["Drupal", ()=>!!(window.Drupal||html.includes("drupalSettings"))],
      ["Joomla", ()=>html.includes("/media/system/js/")||html.includes("joomla")],
      ["Shopify",()=>!!(window.Shopify||cookies.includes("_shopify")||html.includes("cdn.shopify.com"))],
      ["Tailwind",()=>html.includes("tailwind")],
      ["Cloudflare",()=>html.includes("cloudflare")],
      ["GTM", ()=>!!(window.google_tag_manager||html.includes("googletagmanager"))],
      ["reCAPTCHA", ()=>html.includes("recaptcha")||html.includes("g-recaptcha")],
    ].filter(([,fn])=>{try{return fn();}catch{return false;}}).map(([n])=>n);
  };

  const toVersionParts = (value) => String(value||"")
    .replace(/^[^\d]*/,"")
    .split(/[^\d]+/)
    .filter(Boolean)
    .slice(0,4)
    .map(part=>parseInt(part,10)||0);

  const compareVersions = (a, b) => {
    const aa=toVersionParts(a), bb=toVersionParts(b);
    const len=Math.max(aa.length,bb.length);
    for(let i=0;i<len;i++){
      const av=aa[i]||0, bv=bb[i]||0;
      if(av>bv) return 1;
      if(av<bv) return -1;
    }
    return 0;
  };

  const extractVersionFromSrc = (src, name) => {
    const value=String(src||"");
    const patterns=[
      new RegExp(`${name}[.@\\-_]?((?:\\d+\\.){1,3}\\d+)`,"i"),
      /@((?:\d+\.){1,3}\d+)/,
      /\/((?:\d+\.){1,3}\d+)\//,
      /-((?:\d+\.){1,3}\d+)(?:\.min)?\.js/i,
    ];
    for(const pattern of patterns){
      const match=value.match(pattern);
      if(match&&match[1]) return match[1];
    }
    return "";
  };

  const collectLibraries = () => {
    const scripts=[...document.querySelectorAll("script[src]")].map(s=>s.src);
    const libs=[];
    const pushLib = (name, version, source, risk=null) => {
      if(!version && !source) return;
      if(libs.some(item=>item.name===name&&item.version===version&&item.source===source)) return;
      libs.push({name,version:version||"unknown",source:source||"runtime",risk});
    };

    try {
      if(window.jQuery?.fn?.jquery){
        const version=window.jQuery.fn.jquery;
        const risk=compareVersions(version,"3.5.0")<0?"Potentially vulnerable (< 3.5.0)":"";
        pushLib("jQuery",version,"runtime",risk);
      }
    } catch(e) {}
    try {
      const version=window.angular?.version?.full;
      if(version){
        const risk=compareVersions(version,"1.8.3")<0?"Potentially vulnerable (< 1.8.3)":"";
        pushLib("AngularJS",version,"runtime",risk);
      }
    } catch(e) {}
    try {
      const version=window.Vue?.version;
      if(version) pushLib("Vue",version,"runtime","");
    } catch(e) {}
    try {
      const version=window.React?.version;
      if(version) pushLib("React",version,"runtime","");
    } catch(e) {}
    try {
      const version=window.bootstrap?.Tooltip?.VERSION || window.bootstrap?.Modal?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION;
      if(version){
        const risk=(compareVersions(version,"3.4.1")<0 || (compareVersions(version,"4.0.0")>=0&&compareVersions(version,"4.6.2")<0))
          ?"Review Bootstrap version for known issues":"";
        pushLib("Bootstrap",version,"runtime",risk);
      }
    } catch(e) {}

    scripts.forEach(src=>{
      if(/jquery/i.test(src)) pushLib("jQuery",extractVersionFromSrc(src,"jquery"),src,"");
      if(/bootstrap/i.test(src)) pushLib("Bootstrap",extractVersionFromSrc(src,"bootstrap"),src,"");
      if(/vue/i.test(src)) pushLib("Vue",extractVersionFromSrc(src,"vue"),src,"");
      if(/react/i.test(src)) pushLib("React",extractVersionFromSrc(src,"react"),src,"");
      if(/angular/i.test(src)) pushLib("Angular",extractVersionFromSrc(src,"angular"),src,"");
    });

    return libs.slice(0,20);
  };

  const collectIocs = () => {
    const sources=[
      document.body?.innerText||"",
      ...[...document.querySelectorAll("a[href]")].map(a=>a.href),
      ...[...document.querySelectorAll("script[src]")].map(s=>s.src),
      ...traffic.map(t=>`${t.url}\n${String(t.body||"")}\n${String(t.response||"")}`),
    ].join("\n");
    const ipv4=[...new Set((sources.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g)||[]).filter(ip=>!/^10\.|^127\.|^169\.254\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)))].slice(0,20);
    const hashes=[...new Set([
      ...(sources.match(/\b[a-fA-F0-9]{32}\b/g)||[]).map(v=>({type:"MD5",value:v})),
      ...(sources.match(/\b[a-fA-F0-9]{40}\b/g)||[]).map(v=>({type:"SHA1",value:v})),
      ...(sources.match(/\b[a-fA-F0-9]{64}\b/g)||[]).map(v=>({type:"SHA256",value:v})),
    ].map(item=>`${item.type}:${item.value}`))].map(entry=>{
      const idx=entry.indexOf(":");
      return {type:entry.slice(0,idx),value:entry.slice(idx+1)};
    }).slice(0,20);
    const domains=dedupeStrings([
      ...collectExternals(),
      ...collectSocialProfiles().map(profile=>profile.host),
      ...[...document.querySelectorAll("a[href]")].map(a=>getHost(a.href)),
    ].filter(Boolean)).slice(0,20);
    return {ipv4,hashes,domains};
  };

  const sha256Hex = async (text) => {
    try {
      const encoded=new TextEncoder().encode(String(text||""));
      const digest=await crypto.subtle.digest("SHA-256", encoded);
      return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
    } catch(e) {
      return "";
    }
  };

  const parseSiteFilePreview = (path, text) => {
    const raw=String(text||"");
    const lines=raw.split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
    if(path.endsWith("robots.txt")) return lines.filter(line=>/^(user-agent|allow|disallow|sitemap|host):/i.test(line)).slice(0,6);
    if(path.endsWith("security.txt")) return lines.filter(line=>/^(contact|expires|encryption|acknowledgments|policy|canonical|preferred-languages):/i.test(line)).slice(0,6);
    if(path.endsWith("sitemap.xml")) return [...raw.matchAll(/<loc>([^<]+)/gi)].map(match=>match[1]).slice(0,5);
    if(path.endsWith("manifest.webmanifest")) {
      try {
        const json=JSON.parse(raw);
        return [
          json.name?`name:${json.name}`:"",
          json.short_name?`short_name:${json.short_name}`:"",
          json.start_url?`start_url:${json.start_url}`:"",
          json.scope?`scope:${json.scope}`:"",
        ].filter(Boolean);
      } catch(e) {}
    }
    return lines.slice(0,5);
  };

  const probeSiteFiles = async () => {
    const paths=[
      "/robots.txt",
      "/sitemap.xml",
      "/ads.txt",
      "/humans.txt",
      "/manifest.webmanifest",
      "/.well-known/security.txt",
    ];
    const results=[];
    await Promise.all(paths.map(async path=>{
      try {
        const url=new URL(path, location.origin).href;
        const res=await originalFetch(url,{credentials:"same-origin"});
        if(!res.ok) return;
        const text=await res.text();
        results.push({
          path,
          url:res.url,
          status:res.status,
          preview:parseSiteFilePreview(path,text),
        });
      } catch(e) {}
    }));
    return results.sort((a,b)=>a.path.localeCompare(b.path));
  };

  const buildIntelLinks = () => {
    const host=location.hostname;
    return [
      {label:"Wayback", url:`https://web.archive.org/web/*/${host}`},
      {label:"urlscan", url:`https://urlscan.io/search/#domain:${host}`},
      {label:"Shodan", url:`https://www.shodan.io/search?query=${encodeURIComponent(host)}`},
      {label:"BuiltWith", url:`https://builtwith.com/${host}`},
      {label:"DNSDumpster", url:`https://dnsdumpster.com/`},
      {label:"SecurityTrails", url:`https://securitytrails.com/domain/${host}`},
      {label:"GitHub code: host", url:`https://github.com/search?q=${encodeURIComponent(`"${host}"`)}&type=code`},
      {label:"GitHub code: email domain", url:`https://github.com/search?q=${encodeURIComponent(`"@${host}"`)}&type=code`},
      {label:"crt.sh", url:`https://crt.sh/?q=${encodeURIComponent(`%.${host}`)}`},
      {label:"VirusTotal", url:`https://www.virustotal.com/gui/domain/${host}`},
      {label:"ViewDNS", url:`https://viewdns.info/whois/?domain=${encodeURIComponent(host)}`},
      {label:"Web Check", url:`https://web-check.xyz/check/${host}`},
    ];
  };

  const SOCIAL_HOSTS = {
    "twitter.com":"X/Twitter",
    "x.com":"X/Twitter",
    "facebook.com":"Facebook",
    "instagram.com":"Instagram",
    "linkedin.com":"LinkedIn",
    "youtube.com":"YouTube",
    "tiktok.com":"TikTok",
    "github.com":"GitHub",
    "gitlab.com":"GitLab",
    "medium.com":"Medium",
    "discord.gg":"Discord",
    "discord.com":"Discord",
    "telegram.me":"Telegram",
    "t.me":"Telegram",
    "threads.net":"Threads",
    "reddit.com":"Reddit",
    "pinterest.com":"Pinterest",
  };

  const extractSocialHandle = (url, host) => {
    try {
      const parsed=new URL(url, location.href);
      const parts=parsed.pathname.split("/").filter(Boolean);
      if(!parts.length) return "";
      if(host.endsWith("linkedin.com")) {
        if(parts[0]==="company"||parts[0]==="in"||parts[0]==="school") return parts[1]||parts[0];
      }
      if(host==="youtube.com"||host.endsWith(".youtube.com")) {
        if(parts[0]==="channel"||parts[0]==="c"||parts[0]==="user") return parts[1]||parts[0];
        if(parts[0].startsWith("@")) return parts[0];
      }
      if(parts[0].startsWith("@")) return parts[0];
      return parts[parts.length-1];
    } catch(e) {
      return "";
    }
  };

  const collectSocialProfiles = () => {
    const seen=new Set();
    return [...document.querySelectorAll("a[href]")].map(a=>{
      try {
        const url=new URL(a.href, location.href);
        const host=url.hostname.replace(/^www\./i,"").toLowerCase();
        const network=Object.entries(SOCIAL_HOSTS).find(([domain])=>host===domain||host.endsWith(`.${domain}`));
        if(!network) return null;
        const label=(a.textContent||"").trim().replace(/\s+/g," ");
        const handle=extractSocialHandle(url.href, host);
        const key=`${network[1]}::${url.href}`;
        if(seen.has(key)) return null;
        seen.add(key);
        return {
          network:network[1],
          host,
          url:url.href,
          handle:handle||"",
          label:label||"",
        };
      } catch(e) {
        return null;
      }
    }).filter(Boolean).slice(0,20);
  };

  // ═══════════════════════════════════════════════════════════
  // SESSION PERSISTENCE
  // ═══════════════════════════════════════════════════════════
  const SNAP_KEY="__osint_snap_v2";
  const takeSnapshot = () => {
    const snap={_time:nowMs(),_tokens:[]};
    try {
      for(let i=0;i<localStorage.length;i++){
        const k=localStorage.key(i);
        if(INTERESTING_KEY_RE.test(k)) snap[`ls:${k}`]=localStorage.getItem(k);
      }
    } catch(e) {}
    try {
      for(let i=0;i<sessionStorage.length;i++){
        const k=sessionStorage.key(i);
        if(k!==SNAP_KEY&&INTERESTING_KEY_RE.test(k)) snap[`ss:${k}`]=sessionStorage.getItem(k);
      }
    } catch(e) {}
    snap._tokens=allEvidence().map(e=>e.sample.slice(0,32));
    try{sessionStorage.setItem(SNAP_KEY,JSON.stringify(snap));}catch(e){}
    return snap;
  };

  const checkSessionPersistence = () => {
    try {
      const raw=sessionStorage.getItem(SNAP_KEY); if(!raw) return null;
      const snap=JSON.parse(raw), current=takeSnapshot(), persisted=[];
      Object.keys(snap).filter(k=>!k.startsWith("_")).forEach(k=>{
        if(current[k]!==undefined&&current[k]===snap[k])
          persisted.push({key:k,value:snap[k].slice(0,40),ageMs:nowMs()-snap._time});
      });
      return{persisted,snapAge:nowMs()-snap._time};
    } catch(e){return null;}
  };

  // ═══════════════════════════════════════════════════════════
  // NETWORK INTERCEPTOR — fetch + XHR + WebSocket + postMessage
  // ═══════════════════════════════════════════════════════════
  const createTrafficRecord=({kind="fetch",url="",method="GET",headers={},body=null})=>({
    id:nextTrafficId++, kind, url:String(url), method:String(method||"GET").toUpperCase(),
    headers:headers||{}, body:body||null,
    time:nowMs(), startedAt:nowIso(), finishedAt:null, durationMs:null,
    status:null, response:"", error:null
  });

  const finalizeTrafficRecord=(record,updates={})=>{
    if(!record) return;
    if("status"   in updates) record.status  =updates.status;
    if("response" in updates) record.response=String(updates.response||"").slice(0,2000);
    if("error"    in updates) record.error   =updates.error?String(updates.error):null;
    record.durationMs=nowMs()-record.time; record.finishedAt=nowIso();
  };

  const getTrafficRecord=(arg)=>{
    if(!traffic.length) return null;
    const raw=(arg||"").toString().trim().toLowerCase();
    if(!raw||raw==="last") return traffic[traffic.length-1];
    const id=parseInt(raw,10);
    return traffic.find(t=>t.id===id)||null;
  };

  const summarizeTrafficFlags=(item)=>{
    const flags=[];
    try {
      if(item?.url?.toLowerCase().includes("auth"))   flags.push("AUTH");
      if(item?.response?.toLowerCase().includes("token")) flags.push("TOKEN");
      const hdrs=item?.headers||{};
      if(Object.entries(hdrs).some(([k,v])=>/auth/i.test(k)||/bearer/i.test(String(v)))) flags.push("HEADER_AUTH");
      if(hdrs.cookie||hdrs.Cookie) flags.push("COOKIE");
      if(typeof item?.status==="number"&&item.status>=400) flags.push("HTTP_"+item.status);
      if(item?.error) flags.push("ERROR");
    } catch(e) {}
    return [...new Set(flags)];
  };

  const processTrafficResponse=(record,text,respHeaders={},setCookieHdrs=[])=>{
    analyzeText(text,record.url,"body:response",record.id);
    // Security headers audit on every response
    auditSecurityHeaders(respHeaders,record.url,record.id);
    // GraphQL inference
    if(record.body) inferGraphQL(record.body,record.url,record.id);
    // Set-Cookie
    setCookieHdrs.forEach(hdr=>{
      const parsed=parseSetCookieHeader(hdr,record.url,record.id);
      if(parsed) pushCapped(setCookieLog,parsed,MAX_SETCOOKIE);
    });
    // update traffic tab badge
    tabTraffic.textContent=`TRAFFIC (${traffic.length+wsTraffic.length+pmTraffic.length})`;
  };

  const netOn = async () => {
    if(netInterceptor) return log("  Interceptor already active","#555");
    netInterceptor=true;

    try {
      await new Promise((res,rej)=>{
        const req=indexedDB.open(DB_OWN_NAME,1);
        req.onupgradeneeded=e=>{
          const db=e.target.result;
          if(!db.objectStoreNames.contains("traffic")) db.createObjectStore("traffic",{autoIncrement:true});
        };
        req.onsuccess=e=>{ownDB=e.target.result;res();};
        req.onerror=()=>rej();
      });
    } catch(e) {}

    // ── Fetch override ──────────────────────────────────────
    window.fetch = async (...args) => {
      const [url,opts={}]=args;
      const method=(opts.method||"GET").toUpperCase();
      const headers=normalizeHeaders(opts.headers);
      const record=createTrafficRecord({url:String(url),method,headers,body:opts.body||null,kind:"fetch"});
      pushCapped(traffic,record,MAX_TRAFFIC);
      Object.entries(headers).forEach(([k,v])=>analyzeText(String(v),String(url),"header:request",record.id));
      try {
        const res=await originalFetch(...args);
        const clone=res.clone(), text=await clone.text();
        const respHeaders=normalizeHeaders(res.headers);
        const setCookieHdrs=[]; // forbidden header in Fetch API
        finalizeTrafficRecord(record,{status:res.status,response:text});
        processTrafficResponse(record,text,respHeaders,setCookieHdrs);
        const flags=summarizeTrafficFlags(record);
        const color=flags.includes("HEADER_AUTH")?"#f90":flags.includes("TOKEN")?"#f00":"#0cf";
        log(`  [${record.id}] ${record.method} ${displayUrl(String(url))} → ${res.status}`,color);
        if(flags.length) log("    "+flags.join(" | "),"#2a4a2a");
        return res;
      } catch(e) {
        finalizeTrafficRecord(record,{status:"ERR",error:e});
        log(`  [${record.id}] ${record.method} ${displayUrl(String(url))} → ERROR`,"#f00");
        throw e;
      }
    };

    // ── XHR override ────────────────────────────────────────
    window.XMLHttpRequest = function(){
      const xhr=new OriginalXHR();
      let url="",method="GET",record=null;
      const reqHeaders={};
      xhr.open=function(m,u,...rest){
        try{method=m;url=String(u);}catch(e){}
        return OriginalXHR.prototype.open.apply(this,[m,u,...rest]);
      };
      xhr.setRequestHeader=function(k,v){
        try{reqHeaders[k]=v;analyzeText(String(v),url,"header:request");}catch(e){}
        return OriginalXHR.prototype.setRequestHeader.apply(this,arguments);
      };
      xhr.send=function(body){
        record=createTrafficRecord({url,method,headers:{...reqHeaders},body,kind:"xhr"});
        pushCapped(traffic,record,MAX_TRAFFIC);
        this.addEventListener("load",function(){
          try {
            // responseText throws a DOMException unless responseType is "" or "text" — guard it.
            const isTextual=this.responseType===""||this.responseType==="text";
            const text=isTextual?this.responseText:`[non-text response: ${this.responseType||"?"}]`;
            const respHeaders={};
            (this.getAllResponseHeaders()||"").split(/\r?\n/).forEach(line=>{
              const idx=line.indexOf(":");
              if(idx===-1) return;
              const k=line.slice(0,idx).trim().toLowerCase(), v=line.slice(idx+1).trim();
              if(k) respHeaders[k]=v;
            });
            // Set-Cookie is a forbidden response header — never exposed to JS via fetch or XHR, in any browser.
            finalizeTrafficRecord(record,{status:this.status,response:text});
            processTrafficResponse(record,isTextual?text:"",respHeaders,[]);
            const flags=summarizeTrafficFlags(record);
            const color=flags.includes("HEADER_AUTH")?"#f90":"#0cf";
            log(`  [${record.id}] ${record.method} ${displayUrl(url)} → ${this.status}`,color);
            if(flags.length) log("    "+flags.join(" | "),"#2a4a2a");
          } catch(e) {}
        });
        this.addEventListener("error",function(){
          try{finalizeTrafficRecord(record,{status:"ERR",error:"XHR network error"});}catch(e){}
        });
        return OriginalXHR.prototype.send.apply(this,arguments);
      };
      return xhr;
    };
    // preserve prototype chain so `instanceof XMLHttpRequest` still works on the page
    window.XMLHttpRequest.prototype = OriginalXHR.prototype;
    try{ Object.setPrototypeOf(window.XMLHttpRequest,OriginalXHR); }catch(e){}

    // ── WebSocket override (Level A — new) ──────────────────
    window.WebSocket = function(url,...args){
      const ws=new OriginalWS(url,...args);
      const wsEntry={
        id:nextTrafficId++, kind:"ws", url:String(url), origin:location.origin,
        time:nowMs(), method:"WS", headers:{}, status:"open",
        messages:[], data:"", error:null
      };
      pushCapped(wsTraffic,wsEntry,MAX_WS);
      tabTraffic.textContent=`TRAFFIC (${traffic.length+wsTraffic.length+pmTraffic.length})`;
      log(`  [WS:${wsEntry.id}] WebSocket → ${previewVal(String(url),60)}`,"#0cf");

      ws.addEventListener("message",ev=>{
        try {
          const data=typeof ev.data==="string"?ev.data:JSON.stringify(ev.data);
          pushCapped(wsEntry.messages,{t:nowMs(),data:data.slice(0,500)},MAX_WS_MSGS);
          wsEntry.data=data.slice(0,500);
          analyzeText(data,String(url),"ws:message",wsEntry.id);
          if(data.includes("token")||data.includes("jwt")||data.includes("Bearer"))
            log(`  [WS:${wsEntry.id}] ⚠ auth data in WS message`,"#f90");
        } catch(e) {}
      });
      ws.addEventListener("close",()=>{ wsEntry.status="closed"; });
      ws.addEventListener("error",()=>{ wsEntry.status="error"; wsEntry.error="WS error"; });
      return ws;
    };
    // preserve prototype chain (instanceof WebSocket) + static properties (CONNECTING, OPEN, ...)
    window.WebSocket.prototype = OriginalWS.prototype;
    try{ Object.setPrototypeOf(window.WebSocket,OriginalWS); }catch(e){}

    // ── postMessage monitor (Level A — new) ─────────────────
    if(!pmInterceptor){
      pmInterceptor=true;
      window.addEventListener("message",ev=>{
        try {
          const data=typeof ev.data==="string"?ev.data:JSON.stringify(ev.data||"");
          const pmEntry={
            id:nextTrafficId++, kind:"pm", url:ev.origin||"null",
            origin:ev.origin||"null", data:data.slice(0,400),
            time:nowMs(), method:"PM", headers:{}, status:"received"
          };
          pushCapped(pmTraffic,pmEntry,MAX_PM);
          tabTraffic.textContent=`TRAFFIC (${traffic.length+wsTraffic.length+pmTraffic.length})`;
          analyzeText(data,ev.origin||"null","postMessage:data",pmEntry.id);
          if(containsSecretValue(data)||INTERESTING_KEY_RE.test(data)){
            log(`  [PM:${pmEntry.id}] postMessage from ${previewVal(ev.origin||"null",40)} — contains auth data`,"#f90");
            addEvidence({
              type:"POSTMESSAGE", label:"Sensitive postMessage", severity:3,
              source:ev.origin||"null", location:"postMessage:data", field:"data",
              sample:previewVal(data,100), requestId:pmEntry.id
            });
          }
        } catch(e) {}
      },true);
    }

    takeSnapshot();
    log("🔥 Interceptor ON — fetch · XHR · WebSocket · postMessage","#22D3D9");
    log("  Note: Set-Cookie is a forbidden header — not readable via fetch or XHR, only in DevTools ▸ Network","#5C86A8");
  };

  const netOff = () => {
    try{window.fetch=originalFetch;}catch(e){}
    try{window.XMLHttpRequest=OriginalXHR;}catch(e){}
    try{window.WebSocket=OriginalWS;}catch(e){}
    netInterceptor=false;
    log("  Interceptor OFF","#ffcc00");
  };

  // ═══════════════════════════════════════════════════════════
  // SCAN SURFACE  (async, progressive, with diff)
  // ═══════════════════════════════════════════════════════════
  const scanSurface = async (opts={}) => {
    switchTab("scan");
    const isDiff = !!lastScanSnap;

    sep("PAGE");
    log(`  ${previewVal(location.href,80)}`,"#0cf");
    log(`  ${previewVal(document.title,65)||"(no title)"}`,"#0ff");
    log(`  Forms:${document.querySelectorAll("form").length}  Scripts:${document.scripts.length}  Links:${document.links.length}  Iframes:${document.querySelectorAll("iframe").length}`,"#2a4a2a");

    // AUTH unified
    sep("AUTH");
    const storageRows  = scanStorage();
    const cookieAudit  = auditCookies();
    const windowGlobals= scanWindowGlobals();
    const trafficTokens= allEvidence().filter(e=>e.requestId&&["BEARER","JWT","API_KEY","SESSION_ID","CSRF_TOKEN","OAUTH_TOKEN"].includes(e.type));
    const jwtEv        = evidenceByType("JWT");
    const bearerEv     = evidenceByType("BEARER");

    log(`  Cookies(no HttpOnly):${cookieAudit.length}  StorageTokens:${storageRows.length}  WindowGlobals:${windowGlobals.length}  TrafficTokens:${trafficTokens.length}`,"#0ff");

    if(jwtEv.length){
      log(`  JWTs: ${jwtEv.length}`,"#f90");
      jwtEv.slice(0,3).forEach(e=>{
        if(!e.jwt) return;
        jwtSummaryLines(e.jwt).forEach(line=>log(`    ${line.text}`,line.color));
        log(`    @ ${previewVal(e.location,50)}`,"#5C86A8");
      });
    }
    bearerEv.slice(0,2).forEach(e=>{
      log(`  Bearer  ${previewVal(e.sample,50)}`,"#f90");
      log(`          @ ${previewVal(e.location,50)}`,"#5C86A8");
    });
    if(!cookieAudit.length&&!storageRows.length&&!jwtEv.length&&!trafficTokens.length&&!windowGlobals.length)
      log("  No auth tokens — 'traffic on' then browse to capture live data","#555");

    // COOKIE AUDIT
    sep("COOKIE AUDIT");
    if(!cookieAudit.length){
      log("  No JS-accessible cookies (all HttpOnly or none set)","#555");
      log("  'traffic on' → Set-Cookie headers reveal Secure/SameSite/Path","#5C86A8");
    } else {
      const HIGH=cookieAudit.filter(c=>c.severity==="HIGH");
      const MED =cookieAudit.filter(c=>c.severity==="MEDIUM");
      const LOW =cookieAudit.filter(c=>c.severity==="LOW");
      if(HIGH.length){ log(`  HIGH (${HIGH.length}): ${HIGH.map(c=>c.name+(c.isJWT?"[JWT]":"")).join(", ")}`,"#f00"); HIGH.forEach(c=>log(`    ${c.name} → ${c.risks.map(r=>r.flag+":"+r.status).join(" | ")}`,"#f90")); }
      if(MED.length)   log(`  MED  (${MED.length}): ${MED.map(c=>c.name).join(", ")} — HttpOnly missing`,"#f90");
      if(LOW.length)   log(`  LOW  (${LOW.length}): ${LOW.map(c=>c.name).join(", ")}`,"#555");
      log("  All visible cookies lack HttpOnly","#5C86A8");
    }
    if(setCookieLog.length){
      log(`  Set-Cookie from traffic (${setCookieLog.length}):`, "#0cf");
      setCookieLog.slice(-3).forEach(c=>log(`    ${c.name}: ${c.risks.join(", ")||"✓ ok"} ← ${truncUrl(c.url,50)}`,c.risks.length?"#f90":"#0f0"));
    }

    // STORAGE
    sep("STORAGE");
    if(!storageRows.length){ log("  No sensitive keys in localStorage / sessionStorage","#555"); }
    else {
      storageRows.forEach(r=>{
        log(`  ${r.store} :: ${r.key}${r.isJWT?" [JWT]":""}  entropy:${r.entropy}`,"#0ff");
        log(`    ${r.value}`,"#555");
        if(r.isJWT&&r.jwtData) jwtSummaryLines(r.jwtData).forEach(line=>log(`    ${line.text}`,line.color));
        br();
      });
    }

    // WINDOW GLOBALS
    sep("WINDOW GLOBALS");
    if(!windowGlobals.length){ log("  No sensitive window globals detected","#555"); }
    else { windowGlobals.slice(0,6).forEach(g=>{ log(`  window.${g.key}  (${g.type})`,"#f90"); log(`    ${previewVal(g.preview,70)}`,"#555"); }); }

    // FORMS
    sep("FORMS");
    const forms=collectFormItems();
    if(!forms.length){ log("  No auth/sensitive forms detected","#555"); }
    else { forms.forEach(f=>{ log(`  Form #${f.index} ${f.method} ${truncUrl(f.action,55)}`,"#f90"); f.fields.forEach(field=>log(`    ${field.type} → ${field.name}`,"#0cf")); }); }

    // ENDPOINTS DOM
    const domEps=collectEndpoints();
    sep("ENDPOINTS");
    if(!domEps.firstParty.length){ log("  No first-party auth endpoints in DOM","#555"); }
    else { domEps.firstParty.slice(0,8).forEach(u=>log("  "+truncUrl(u,70),"#0ff")); }
    if(domEps.external.length){ log("  External (non-noisy):","#555"); domEps.external.slice(0,4).forEach(u=>log("  "+truncUrl(u,70),"#0cf")); }

    // JS ANALYSIS (async)
    sep("JS ANALYSIS");
    try {
      const{endpoints:jsEps,cloud,subdomains}=await fetchAndAnalyzeScripts();
      log(`  Endpoints:${jsEps.length}  Cloud:${cloud.length}  Subs:${subdomains.length}`,"#0ff");
      jsEps.filter(u=>{try{return new URL(u,location.href).pathname.length<80;}catch{return u.length<80;}}).slice(0,5).forEach(u=>log("  ep  "+truncUrl(u,68),"#0ff"));
      subdomains.slice(0,5).forEach(s=>log("  sub "+s,"#0cf"));
      cloud.slice(0,4).forEach(c=>log(`  cld [${c.type}] ${previewVal(c.host,50)}`,"#f90"));
      if(!jsEps.length&&!cloud.length&&!subdomains.length) log("  No findings in first-party scripts","#555");
    } catch(e){ log("  Script analysis error: "+String(e).slice(0,60),"#555"); }

    // SITE FILES
    sep("SITE FILES");
    try {
      lastSiteFiles=await probeSiteFiles();
      if(!lastSiteFiles.length){
        log("  No standard site files discovered","#555");
      } else {
        lastSiteFiles.forEach(file=>{
          log(`  ${file.path} [${file.status}]`,"#0cf");
          if(file.preview.length) file.preview.slice(0,4).forEach(line=>log(`    ${previewVal(line,90)}`,"#555"));
        });
      }
    } catch(e){ log("  Site files probe error","#555"); }

    // INDEXEDDB
    sep("INDEXEDDB");
    try {
      const idbResults=await scanIndexedDB();
      if(!idbResults.length){ log("  No external IndexedDB found","#555"); }
      else { idbResults.forEach(db=>{ if(db.error){log(`  ${previewVal(db.error,70)}`,"#555");return;} const storeList=db.stores.slice(0,4).join(", ")+(db.stores.length>4?"…":""); log(`  ${previewVal(db.db,40)} :: ${storeList||"(empty)"}`,db.sensitive.length?"#f90":"#0ff"); db.sensitive.slice(0,2).forEach(s=>{log("    ⚠ SENSITIVE","#f00");log(`    ${previewVal(s.preview,70)}`,"#555");}); }); }
    } catch(e){ log("  IndexedDB scan error","#555"); }

    // SERVICE WORKERS (Level A — new)
    sep("SERVICE WORKERS");
    try {
      const swResults=await scanServiceWorkers();
      if(!swResults.length){ log("  No service workers registered","#555"); }
      else { swResults.forEach(sw=>{ log(`  scope: ${previewVal(sw.scope,55)}  state: ${sw.state}`,sw.sensitive.length?"#f90":"#0ff"); if(sw.stale) log("    ⚠ cacheFirst/cacheOnly detected — tokens may be cached","#f90"); if(sw.sensitive.length) log(`    findings: ${sw.sensitive.slice(0,3).join(", ")}`,"#f00"); }); }
    } catch(e){ log("  Service worker scan error","#555"); }

    // SECURITY HEADERS (Level B — new)
    sep("SECURITY HEADERS");
    if(!secHeaderLog.length){
      log("  No responses captured yet — 'traffic on' populates this","#555");
    } else {
      const latest=secHeaderLog[secHeaderLog.length-1];
      const corsIssues=secHeaderLog.flatMap(e=>e.corsRisks).filter(Boolean);
      if(latest.missing.length) log(`  Missing critical: ${latest.missing.join("  ")}`,"#f90");
      else log("  ✓ Critical security headers present in last response","#0f0");
      if(corsIssues.length) log(`  CORS issues (${corsIssues.length}): ${[...new Set(corsIssues)].slice(0,3).join("  ")}`,"#f00");
      const cspEntry=secHeaderLog.find(e=>e.found["content-security-policy"]);
      if(cspEntry) log(`  CSP: ${previewVal(cspEntry.found["content-security-policy"],65)}`,"#0cf");
    }

    // GRAPHQL (Level D — new)
    if(graphqlOps.length){
      sep("GRAPHQL OPS");
      const types={query:0,mutation:0,subscription:0};
      graphqlOps.forEach(o=>types[o.type]=(types[o.type]||0)+1);
      log(`  Operations: ${graphqlOps.length} | queries:${types.query} mutations:${types.mutation} subs:${types.subscription}`,"#0ff");
      graphqlOps.slice(-5).forEach(o=>log(`  ${o.type} ${previewVal(o.operationName,35)} → ${truncUrl(o.url,40)}`,"#0cf"));
    }

    // SESSION
    sep("SESSION");
    const persistence=checkSessionPersistence();
    if(!persistence){ log("  No snapshot — 'traffic on' starts session tracking","#555"); }
    else if(!persistence.persisted.length){ log("  ✓ No tokens persisted from baseline","#0f0"); }
    else { log(`  ⚠ ${persistence.persisted.length} tokens alive after ${Math.round(persistence.snapAge/60000)}m`,"#f90"); persistence.persisted.slice(0,3).forEach(p=>log(`    ${previewVal(p.key,30)} = ${previewVal(p.value,40)}`,"#f90")); }

    // EXTERNALS
    sep("EXTERNALS");
    const externals=collectExternals();
    if(!externals.length){ log("  No notable external hosts","#555"); }
    else { externals.slice(0,8).forEach(h=>log("  "+h,"#0cf")); }
    const scripts=[...document.querySelectorAll("script[src]")].map(s=>s.src);
    const noisyCount=scripts.filter(u=>{const h=getHost(u);return h&&!isFirstParty(u)&&isNoisyHost(h);}).length;
    if(noisyCount) log(`  + ${noisyCount} analytics/tracking scripts hidden`,"#2a4a2a");

    // SOCIAL PROFILES
    sep("SOCIAL PROFILES");
    const socialProfiles=collectSocialProfiles();
    if(!socialProfiles.length){
      log("  No visible social profile links detected","#555");
    } else {
      socialProfiles.slice(0,10).forEach(profile=>{
        const tail=profile.handle ? ` @ ${profile.handle}` : profile.label ? ` :: ${previewVal(profile.label,30)}` : "";
        log(`  ${profile.network}${tail}`,"#0cf");
        log(`    ${profile.url}`,"#555");
      });
    }

    // OSINT LINKS
    sep("OSINT LINKS");
    buildIntelLinks().forEach(link=>log(`  ${link.label}: ${link.url}`,"#0cf"));

    // TECH
    sep("TECH");
    const tech=collectTech();
    if(!tech.length) log("  No obvious framework fingerprint","#555");
    else log("  "+tech.join("  "),"#0f0");

    // LIBRARIES
    sep("LIBRARIES");
    const libraries=collectLibraries();
    if(!libraries.length){
      log("  No library versions detected from runtime or script URLs","#555");
    } else {
      libraries.slice(0,8).forEach(lib=>{
        log(`  ${lib.name} ${lib.version}`,(lib.risk?"#f90":"#0cf"));
        log(`    ${previewVal(lib.source,80)}`,"#555");
        if(lib.risk) log(`    ${lib.risk}`,"#f90");
      });
    }

    // IOCS
    sep("IOCS");
    const iocs=collectIocs();
    if(!iocs.ipv4.length&&!iocs.hashes.length&&!iocs.domains.length){
      log("  No visible IOCs extracted from page/traffic","#555");
    } else {
      if(iocs.ipv4.length) log(`  IPv4: ${iocs.ipv4.slice(0,6).join("  ")}`,"#0cf");
      if(iocs.hashes.length) iocs.hashes.slice(0,4).forEach(item=>log(`  ${item.type}: ${item.value}`,"#f90"));
      if(iocs.domains.length) log(`  Domains: ${iocs.domains.slice(0,6).join("  ")}`,"#0cf");
    }

    // EMAILS
    const emails=dedupeStrings((document.body.innerText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g)||[])).slice(0,8);
    if(emails.length){sep("EMAILS");emails.forEach(e=>log("  "+e,"#0f0"));}

    // DIFF (Level D — new)
    if(isDiff&&lastScanSnap){
      sep("DIFF vs LAST SCAN");
      const prev=lastScanSnap;
      const newEv=allEvidence().filter(e=>e.firstSeen>=prev._scanTime);
      const newEps=[...collectEndpoints().firstParty,...domEps.firstParty].filter(u=>!prev._endpoints.includes(u));
      if(newEv.length) log(`  New findings since last scan: ${newEv.length}`,"#f90");
      newEv.slice(0,4).forEach(e=>log(`    + [${e.type}] ${previewVal(e.sample,50)}`,"#f90"));
      if(newEps.length) log(`  New endpoints: ${newEps.slice(0,4).join("  ")}`,"#0ff");
      if(!newEv.length&&!newEps.length) log("  No changes detected","#0f0");
    }

    // SUMMARY
    sep("SUMMARY");
    const all=allEvidence();
    const high=all.filter(e=>e.severity>=4), med=all.filter(e=>e.severity===3);
    if(!all.length){
      log("  No findings yet","#555");
      log("  → 'traffic on' and browse the app to capture live data","#5C86A8");
    } else {
      log(`  ${all.length} findings  ${high.length} HIGH  ${med.length} MED  ${all.length-high.length-med.length} LOW`,high.length?"#f00":"#f90");
      br();
      high.slice(0,4).forEach(e=>{ log(`  ⚠ ${e.label}`,"#f90"); log(`    ${previewVal(e.sample,55)}`,"#f00"); log(`    @ ${previewVal(e.location,55)}`,"#5C86A8"); });
      br();
      if(netInterceptor) log("  Interceptor ACTIVE — data grows as you browse","#5C86A8");
      else               log("  'traffic on' → live capture  |  TRAFFIC tab → full view  |  FINDINGS tab → filter","#5C86A8");
    }

    // save snapshot for next diff
    lastScanSnap={
      _scanTime:nowMs(),
      _evidenceCount:all.length,
      _endpoints:[...collectEndpoints().firstParty]
    };

    updateTabBadge();
  };

  // ═══════════════════════════════════════════════════════════
  // TRAFFIC COMMAND
  // ═══════════════════════════════════════════════════════════
  const showTrafficList = () => {
    sep("TRAFFIC");
    const total=traffic.length+wsTraffic.length+pmTraffic.length;
    if(!total) return log("  No traffic captured — 'traffic on' first","#555");
    traffic.slice(-12).reverse().forEach(item=>{
      const flags=summarizeTrafficFlags(item);
      const color=flags.includes("HEADER_AUTH")?"#f90":flags.includes("ERROR")?"#f00":"#0cf";
      log(`  [${item.id}] ${item.status??"…"} ${item.method} ${truncUrl(item.url,60)}`,color);
      if(flags.length) log("    "+flags.join(" | "),"#2a4a2a");
    });
    if(wsTraffic.length) log(`  WebSocket sessions: ${wsTraffic.length}`,"#0cf");
    if(pmTraffic.length) log(`  postMessage events: ${pmTraffic.length}`,"#0cf");
    log(`  Total: ${total} | → TRAFFIC tab for live view | 'traffic auth' | 'traffic <id>'`,"#5C86A8");
  };

  const showTrafficAuth = () => {
    sep("TRAFFIC — AUTH");
    const withBearer=traffic.filter(t=>Object.entries(t.headers||{}).some(([k,v])=>/^authorization$/i.test(k)||/bearer/i.test(String(v))));
    if(withBearer.length){
      log(`  Requests with Authorization/Bearer (${withBearer.length}):`, "#f90");
      withBearer.slice(0,5).forEach(t=>log(`    [${t.id}] ${t.method} ${truncUrl(t.url,55)} → ${t.status}`,"#f90"));
    }
    const withCookie=traffic.filter(t=>Object.keys(t.headers||{}).some(k=>/^cookie$/i.test(k)));
    if(withCookie.length){
      log(`  Requests with Cookie header (${withCookie.length}):`, "#0cf");
      withCookie.slice(0,5).forEach(t=>log(`    [${t.id}] ${t.method} ${truncUrl(t.url,55)} → ${t.status}`,"#0cf"));
    }
    if(setCookieLog.length){
      log(`  Set-Cookie responses (${setCookieLog.length}):`, "#f90");
      setCookieLog.slice(-4).forEach(c=>log(`    ${c.name}: ${c.risks.join(", ")||"✓"} ← ${truncUrl(c.url,45)}`,c.risks.length?"#f90":"#0f0"));
    }
    const correlated=allEvidence().filter(e=>e.requestIds?.length>0&&e.severity>=3);
    if(correlated.length){
      log(`  Token → endpoint correlation (${correlated.length}):`, "#0ff");
      correlated.slice(0,5).forEach(e=>{
        const urls=e.requestIds.map(rid=>traffic.find(t=>t.id===rid)).filter(Boolean).map(t=>truncUrl(t.url,35));
        log(`    [${e.label}] ${previewVal(e.sample,30)}… → ${urls.slice(0,2).join(" + ")}`,"#0ff");
      });
    }
    if(!withBearer.length&&!withCookie.length&&!setCookieLog.length&&!correlated.length)
      log("  No auth traffic captured yet — browse the app with 'traffic on' active","#555");
  };

  const showTrafficSummary = () => {
    switchTab("scan");
    sep("TRAFFIC SUMMARY");
    const total=traffic.length+wsTraffic.length+pmTraffic.length;
    if(!total) return log("  No traffic captured - use 'traffic on' and browse the app","#555");

    const tokenBodies=traffic.filter(t=>/(token|jwt|access_token|refresh_token|id_token)/i.test(`${String(t.body||"")} ${String(t.response||"")}`));
    const errors=traffic.filter(t=>t.error||(typeof t.status==="number"&&t.status>=400));

    log(`  Requests:${traffic.length}  WS:${wsTraffic.length}  PM:${pmTraffic.length}  Findings:${allEvidence().length}`,"#0ff");
    showTrafficList();
    br();
    showTrafficAuth();
    if(tokenBodies.length){
      br();
      log(`  BODY TOKENS (${tokenBodies.length})`,"#f00");
      tokenBodies.slice(0,4).forEach(t=>log(`    [${t.id}] ${t.method} ${truncUrl(t.url,55)} -> ${t.status}`,"#f00"));
    }
    if(errors.length){
      br();
      log(`  ERRORS (${errors.length})`,"#f00");
      errors.slice(0,4).forEach(t=>log(`    [${t.id}] ${t.method} ${truncUrl(t.url,55)} -> ${t.status??"ERR"}`,"#f00"));
    }
    br();
    log("  Use 'traffic last' or 'traffic <id>' for full request detail","#5C86A8");
    renderTrafficTab();
  };

  const showTrafficDetail = (arg) => {
    sep("TRAFFIC DETAIL");
    const item=getTrafficRecord(arg);
    if(!item) return log("  uso: traffic last | traffic <id>","#f00");
    log(`  [${item.id}] ${item.kind?.toUpperCase()} | ${item.method} | ${item.status??"pending"} | ${item.durationMs!=null?item.durationMs+"ms":"open"}`,"#0ff");
    log(`  ${item.url}`,"#0cf");
    if(Object.keys(item.headers||{}).length){ log("  HEADERS:","#f90"); Object.entries(item.headers).forEach(([k,v])=>log(`    ${k}: ${String(v).slice(0,180)}`,"#0cf")); }
    if(item.body){ log("  BODY:","#f90"); log("  "+String(item.body).slice(0,500),"#0cf"); }
    if(item.response){ log("  RESPONSE:","#f90"); log("  "+String(item.response).slice(0,600),"#0cf"); }
    if(item.error) log("  ERROR: "+String(item.error).slice(0,180),"#f00");
    const related=allEvidence().filter(e=>e.requestId===item.id||(e.requestIds||[]).includes(item.id));
    if(related.length){ log(`  FINDINGS (${related.length}):`, "#f90"); related.forEach(e=>log(`    [${e.label}] ${previewVal(e.sample,60)}`,e.severity>=4?"#f00":"#f90")); }
  };

  const trafficCommand = (arg="") => {
    const raw=String(arg||"").trim().toLowerCase();
    if(!raw)               { return showTrafficSummary(); }
    if(raw==="on")           return netOn();
    if(raw==="off")          return netOff();
    if(raw==="auth"||raw==="list") return showTrafficSummary();
    if(raw==="last")         return showTrafficDetail("last");
    if(/^\d+$/.test(raw))   return showTrafficDetail(raw);
    log("  traffic | traffic on | traffic off | traffic last | traffic <id>","#f00");
  };

  // ═══════════════════════════════════════════════════════════
  // FINDINGS COMMAND  (Level C — new)
  // ═══════════════════════════════════════════════════════════
  const findingsCommand = (arg="") => {
    const raw=String(arg||"").trim().toLowerCase();
    const all=allEvidence();
    if(!all.length){ log("  No findings yet","#555"); return; }
    if(!raw||raw==="all"){
      switchTab("findings"); renderFindingsTab(); return;
    }
    // filter by severity keyword
    if(raw==="high"||raw==="crit"){
      switchTab("findings"); renderFindingsTab("HIGH_SEV"); // switch to tab, filter by severity>=4
      const high=all.filter(e=>e.severity>=4);
      sep("FINDINGS — HIGH");
      if(!high.length){ log("  No HIGH findings","#555"); return; }
      high.forEach(e=>{ log(`  ⚠ ${e.label}`,"#f90"); log(`    ${previewVal(e.sample,60)}`,"#f00"); log(`    @ ${previewVal(e.location,60)}`,"#5C86A8"); br(); });
      return;
    }
    // filter by type keyword
    const byType=all.filter(e=>e.type.toLowerCase().includes(raw)||e.label.toLowerCase().includes(raw));
    if(!byType.length){ log(`  No findings matching "${raw}"  — try: high | jwt | cookie | bearer | cors | csp | ws | graphql`,"#555"); return; }
    sep(`FINDINGS — ${raw.toUpperCase()}`);
    byType.forEach(e=>{ log(`  [${e.type}] ${previewVal(e.sample,60)}`,e.severity>=4?"#f00":"#f90"); log(`    @ ${previewVal(e.location,60)}`,"#5C86A8"); });
  };

  // ═══════════════════════════════════════════════════════════
  // EXPORT FORENSIC
  // ═══════════════════════════════════════════════════════════
  const exportForensic = async () => {
    const all=allEvidence();
    const baseReport={
      meta:{generatedAt:new Date().toISOString(),url:location.href,title:document.title,
        interceptorActive:netInterceptor,trafficCaptured:traffic.length,
        wsCaptured:wsTraffic.length,pmCaptured:pmTraffic.length,tool:"OSINT Terminal v2.0"},
      summary:{total:all.length,high:all.filter(e=>e.severity>=4).length,
        medium:all.filter(e=>e.severity===3).length,low:all.filter(e=>e.severity<=2).length,
        types:[...new Set(all.map(e=>e.type))]},
      auth:{
        jwt:     evidenceByType("JWT").map(e=>({location:e.location,sample:maskSecret(e.sample),header:e.jwt?.header,payload:e.jwt?.payload,expired:e.jwt?.expired,expiresInSec:e.jwt?.expiresInSec,algNone:e.jwt?.algNone,algConfusion:e.jwt?.algConfusion,requestIds:e.requestIds})),
        bearers: evidenceByType("BEARER").map(e=>({location:e.location,sample:maskSecret(e.sample),requestIds:e.requestIds})),
        apiKeys: evidenceByType("API_KEY").map(e=>({location:e.location,sample:maskSecret(e.sample)})),
        sessions:evidenceByType("SESSION_ID").map(e=>({location:e.location,sample:maskSecret(e.sample)})),
        csrf:    evidenceByType("CSRF_TOKEN").map(e=>({location:e.location,sample:maskSecret(e.sample)})),
        oauth:   evidenceByType("OAUTH_TOKEN").map(e=>({location:e.location,sample:maskSecret(e.sample)})),
      },
      cookieAudit: auditCookies().map(c=>({name:c.name,severity:c.severity,risks:c.risks,notes:c.notes,isJWT:c.isJWT})),
      setCookieFromTraffic: setCookieLog,
      securityHeaders: secHeaderLog,
      corsIssues: evidenceByType("CORS_MISCFG").map(e=>({url:e.source,finding:e.sample})),
      missingHeaders: evidenceByType("MISSING_HEADER").map(e=>({url:e.source,header:e.field})),
      cspTrustedHosts: evidenceByType("CSP_TRUSTED_HOST").map(e=>({url:e.source,hosts:e.sample})),
      storage: scanStorage().map(s=>({store:s.store,key:s.key,isJWT:s.isJWT,entropy:s.entropy,value:maskSecret(s.value)})),
      indexedDB: evidenceByType("INDEXEDDB").map(e=>({db:e.source,store:e.field,preview:maskSecret(e.sample)})),
      windowGlobals: evidenceByType("WINDOW_GLOBAL").map(e=>({key:e.field,preview:maskSecret(e.sample)})),
      serviceWorkers: evidenceByType("SERVICE_WORKER").map(e=>({scope:e.source,state:e.field,finding:e.sample})),
      cloudAssets: evidenceByType("CLOUD_ASSET").map(e=>({type:e.field,host:e.sample,source:e.source})),
      graphqlOps: graphqlOps.map(o=>({type:o.type,operationName:o.operationName,query:o.query.slice(0,200),url:o.url})),
      websockets: wsTraffic.map(w=>({id:w.id,url:w.url,status:w.status,messageCount:w.messages.length})),
      postMessages: pmTraffic.map(p=>({id:p.id,origin:p.origin,preview:maskSecret(p.data)})),
      endpoints:{dom:collectEndpoints().firstParty.slice(0,30),traffic:[...new Set(traffic.map(t=>t.url))].slice(0,40)},
      socialProfiles: collectSocialProfiles(),
      siteFiles: lastSiteFiles,
      osintLinks: buildIntelLinks(),
      externals: collectExternals(),
      tech: collectTech(),
      libraries: collectLibraries(),
      iocs: collectIocs(),
      trafficSummary: traffic.slice(-30).map(t=>({id:t.id,method:t.method,url:t.url,status:t.status,durationMs:t.durationMs,flags:summarizeTrafficFlags(t)})),
      evidence: all.map(e=>({id:e.id,type:e.type,label:e.label,severity:e.severity,source:e.source,location:e.location,field:e.field,sample:maskSecret(e.sample),firstSeen:new Date(e.firstSeen).toISOString(),lastSeen:new Date(e.lastSeen).toISOString(),count:e.count,requestIds:e.requestIds}))
    };
    const serialized=JSON.stringify(baseReport,null,2);
    const report={
      ...baseReport,
      integrity:{
        algorithm:"SHA-256",
        contentHashExcludingIntegrity:await sha256Hex(serialized),
        byteLength:serialized.length
      }
    };
    const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
    const a=document.createElement("a");
    a.href=URL.createObjectURL(blob); a.download=`osint_${location.hostname}_${Date.now()}.json`; a.click();
    log(`  Exported ${all.length} findings | traffic:${traffic.length} | ws:${wsTraffic.length} | pm:${pmTraffic.length} | secrets masked`,"#0f0");
    if(report.integrity.contentHashExcludingIntegrity) log(`  SHA-256: ${report.integrity.contentHashExcludingIntegrity}`,"#0cf");
  };

  // ═══════════════════════════════════════════════════════════
  // DESTROY
  // ═══════════════════════════════════════════════════════════
  destroyTerminal = () => {
    try{netOff();}catch(e){}
    if(moveHandler) document.removeEventListener("mousemove",moveHandler);
    if(upHandler)   document.removeEventListener("mouseup",  upHandler);
    document.removeEventListener("mousemove",onResizeMove);
    document.removeEventListener("mouseup",  onResizeUp);
    if(clockTimer)  clearInterval(clockTimer);
    moveHandler=upHandler=null;
    try{input.blur();}catch(e){}
    try{box.remove();}catch(e){}
    try{delete window.__osint_terminal__;}catch(e){window.__osint_terminal__=false;}
  };

  // ═══════════════════════════════════════════════════════════
  // COMMANDS
  // ═══════════════════════════════════════════════════════════
  const commands = {
    help: () => {
      sep("COMMANDS");
      [
        ["scan",             "Static recon: auth, cookies, JWT, storage, endpoints, social, site files"],
        ["traffic",          "Dynamic recon summary: auth, cookies, WS, correlation"],
        ["traffic on",       "Activate fetch, XHR, WebSocket and postMessage capture"],
        ["traffic off",      "Deactivate interceptor"],
        ["traffic last",     "Detail of last request"],
        ["traffic <id>",     "Detail by request ID"],
        ["findings",         "Open filterable findings tab"],
        ["findings high",    "Show HIGH severity findings"],
        ["findings <tipo>",  "Filter: jwt | bearer | cookie | cors | csp | ws | graphql"],
        ["export",           "Forensic JSON: auth, traffic and masked evidence"],
        ["clear",            "Clear SCAN tab output"],
        ["exit",             "Close terminal"],
      ].forEach(([cmd,desc])=>{
        const row=el("div",{display:"flex",gap:"10px",marginBottom:"2px"});
        row.appendChild(el("span",{color:"#22D3D9",minWidth:"155px",fontWeight:"bold"},cmd));
        row.appendChild(el("span",{color:"#5C86A8"},desc));
        out.appendChild(row);
      });
    },
    scan:     () => { scanSurface().catch(e=>log("  Scan error: "+String(e).slice(0,100),"#f00")); },
    traffic:  trafficCommand,
    findings: findingsCommand,
    export:   () => { exportForensic().catch(e=>log("  Export error: "+String(e).slice(0,100),"#f00")); },
    clear:    () => { out.textContent=""; },
    exit:     () => destroyTerminal()
  };

  // ═══════════════════════════════════════════════════════════
  // INPUT HANDLING
  // ═══════════════════════════════════════════════════════════
  input.addEventListener("keydown", e => {
    if(e.key==="ArrowUp"){ if(histIdx<cmdHistory.length-1) histIdx++; input.value=cmdHistory[histIdx]||""; e.preventDefault(); return; }
    if(e.key==="ArrowDown"){ if(histIdx>0) histIdx--; else{histIdx=-1;input.value="";return;} input.value=cmdHistory[histIdx]||""; e.preventDefault(); return; }
    if(e.key!=="Enter") return;
    const raw=input.value.trim(); if(!raw) return;
    cmdHistory.unshift(raw); if(cmdHistory.length>200) cmdHistory.pop(); histIdx=-1;
    const parts=raw.split(" "), command=parts[0].toLowerCase(), arg=parts.slice(1).join(" ");
    log("❯ "+raw,"#123042");
    if(commands[command]){ try{commands[command](arg);}catch(err){log("  Error: "+String(err),"#f00");} }
    else log(`  Unknown: "${command}" — type help`,"#f00");
    input.value="";
    out.scrollTop=out.scrollHeight;
  });

  // ═══════════════════════════════════════════════════════════
  // BOOT
  // ═══════════════════════════════════════════════════════════
  log("OSINT TERMINAL v2.0","#22D3D9");
  log("help | scan | traffic | traffic on | export","#164654");
  log(location.hostname,"#5C86A8");
})();
