(() => {
  if (window.__osint_terminal__) return;
  window.__osint_terminal__ = true;

  // ===== HELPERS =====
  const el = (tag, styles = {}, text = "") => {
    const e = document.createElement(tag);
    Object.assign(e.style, styles);
    if (text) e.textContent = text;
    return e;
  };

  // ===== STATE / STORAGE =====
  const findings = {
    tokens: new Set(),
    endpoints: new Set(),
    headers: [],
    jwt: []
  };
  const traffic = [];
  const history = []; // command history (strings)
  let histIdx = -1;

  // ===== UI (container) =====
  const box = el("div", {
    position: "fixed", bottom: "20px", right: "20px",
    width: "580px", height: "420px", background: "#0a0a0a",
    border: "1px solid #00ff00", zIndex: "999999999",
    display: "flex", flexDirection: "column",
    fontFamily: "monospace", fontSize: "12px", color: "#00ff00",
    boxShadow: "0 0 24px #00ff0044", borderRadius: "6px",
    transition: "all 0.2s"
  });

  // Header (draggable)
  let drag = false, ox = 0, oy = 0;
  const header = el("div", {
    padding: "6px 10px", borderBottom: "1px solid #00ff00",
    display: "flex", justifyContent: "space-between", alignItems: "center",
    background: "#001a00", cursor: "move", userSelect: "none"
  });
  header.onmousedown = e => {
    drag = true;
    ox = e.clientX - box.offsetLeft;
    oy = e.clientY - box.offsetTop;
  };
  document.onmousemove = e => {
    if (!drag) return;
    box.style.left = (e.clientX - ox) + "px";
    box.style.top  = (e.clientY - oy) + "px";
    box.style.bottom = "auto"; box.style.right = "auto";
  };
  document.onmouseup = () => drag = false;

  const titleEl = el("span", { fontWeight: "bold", letterSpacing: "2px", color: "#0f0" }, "⬡ OSINT Terminal v2");
  const controls = el("div", { display: "flex", gap: "8px" });

  const minBtn = el("span", { cursor: "pointer", color: "#ff0", fontWeight: "bold", fontSize: "14px" }, "─");
  const closeBtn = el("span", { cursor: "pointer", color: "#f00", fontWeight: "bold", fontSize: "14px" }, "✕");
  let minimized = false;
  minBtn.onclick = () => {
    minimized = !minimized;
    out.style.display = minimized ? "none" : "flex";
    inputRow.style.display = minimized ? "none" : "flex";
    box.style.height = minimized ? "34px" : "420px";
  };
  closeBtn.onclick = () => box.remove();
  controls.appendChild(minBtn);
  controls.appendChild(closeBtn);
  header.appendChild(titleEl);
  header.appendChild(controls);

  // Status bar
  const statusBar = el("div", {
    padding: "2px 10px", background: "#001a00",
    borderBottom: "1px solid #003300", color: "#555", fontSize: "11px",
    display: "flex", justifyContent: "space-between"
  });
  const statusLeft  = el("span", {}, document.domain || location.hostname);
  const statusRight = el("span", {}, new Date().toLocaleTimeString());
  setInterval(() => statusRight.textContent = new Date().toLocaleTimeString(), 1000);
  statusBar.appendChild(statusLeft);
  statusBar.appendChild(statusRight);

  // Output area
  const out = el("div", {
    flex: "1", overflowY: "auto", padding: "8px",
    userSelect: "text", lineHeight: "1.7", display: "flex",
    flexDirection: "column"
  });

  // Input row
  const inputRow = el("div", {
    display: "flex", borderTop: "1px solid #00ff00",
    padding: "5px 10px", alignItems: "center", background: "#001a00"
  });
  const promptEl = el("span", { color: "#0f0", marginRight: "6px" }, "❯");
  const input = el("input", {
    flex: "1", background: "transparent", color: "#0f0",
    border: "none", outline: "none", fontFamily: "monospace", fontSize: "12px"
  });
  input.setAttribute("placeholder", "help para ver comandos...");
  input.setAttribute("spellcheck", "false");
  inputRow.appendChild(promptEl);
  inputRow.appendChild(input);

  box.appendChild(header);
  box.appendChild(statusBar);
  box.appendChild(out);
  box.appendChild(inputRow);
  document.body.appendChild(box);
  input.focus();

  // ===== LOG helpers =====
  const log = (text, color = "#00ff00") => {
    const line = el("div", { color, wordBreak: "break-all" }, text);
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  };
  const sep = (label = "") => log("── " + label + " " + "─".repeat(Math.max(0, 36 - label.length)), "#1a3300");

  // ===== NETWORK / INTERCEPTOR STATE =====
  let netInterceptor = false;
  const originalFetch = window.fetch.bind(window);
  const originalXHR = window.XMLHttpRequest;

  // ===== UTILITIES =====
  const normalizeHeaders = (h) => {
    const out = {};
    try {
      if (!h) return out;
      if (h instanceof Headers) {
        for (const [k, v] of h.entries()) out[k] = v;
      } else if (Array.isArray(h)) {
        h.forEach(([k, v]) => { out[k] = v; });
      } else if (typeof h === "object") {
        Object.keys(h).forEach(k => { out[k] = h[k]; });
      }
    } catch (e) {}
    return out;
  };

  const decodeJWT = (token) => {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      const decode = (str) => JSON.parse(atob(str.replace(/-/g, "+").replace(/_/g, "/")));
      const payload = decode(parts[1]);
      findings.jwt.push(payload);
      return payload;
    } catch {
      return null;
    }
  };

  // Entropy (Shannon)
  const entropy = (str = "") => {
    if (!str) return 0;
    const map = {};
    for (let c of str) map[c] = (map[c] || 0) + 1;
    let ent = 0;
    const len = str.length;
    for (let k in map) {
      const p = map[k] / len;
      ent -= p * Math.log2(p);
    }
    return ent;
  };

  // ===== Rule Engine (simple) =====
  const rules = [
    { id: "R_JWT", name: "JWT", regex: /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g, severity: 3, note: "Likely JWT" },
    { id: "R_APIKEY_GENERIC", name: "API_KEY", regex: /api[_-]?key["'\s:=]+([A-Za-z0-9_\-]{16,})/gi, severity: 3, note: "Common API key literal" },
    { id: "R_AWS_ACCESS", name: "AWS_ACCESS_KEY", regex: /AKIA[0-9A-Z]{16}/g, severity: 4, note: "AWS access key pattern" },
    { id: "R_BEARER_HDR", name: "BEARER_IN_HEADER", regex: /Bearer\s+([A-Za-z0-9\-_\.]+)/i, severity: 3, note: "Bearer token in header" }
  ];

  const analyzeText = (text = "", source = "unknown") => {
    if (!text) return [];
    const results = [];

    rules.forEach(r => {
      let m;
      try {
        while ((m = r.regex.exec(text)) !== null) {
          const value = m[1] || m[0];
          const ent = entropy(value || "");
          // score: base severity + entropy bonus
          const score = r.severity + (ent > 4.0 ? 1 : 0);

          const res = {
            id: `${r.id}_${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
            type: r.name,
            value,
            entropy: ent,
            score,
            source,
            note: r.note,
            timestamp: Date.now()
          };

          // persist in findings
          try {
            findings.tokens.add(value);
            if (r.name === "JWT") decodeJWT(value);
          } catch (e) {}

          results.push(res);
        }
      } catch (e) {}
    });

    // generic high-entropy token detection: long strings of >=20 chars
    const words = (text.match(/[A-Za-z0-9\-_]{20,}/g) || []);
    words.forEach(w => {
      const ent = entropy(w);
      if (ent > 4.2) {
        const res = {
          id: `HE_${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
          type: "HIGH_ENTROPY",
          value: w,
          entropy: ent,
          score: 2 + (ent > 5 ? 1 : 0),
          source,
          note: "High entropy candidate",
          timestamp: Date.now()
        };
        findings.tokens.add(w);
        results.push(res);
      }
    });

    // log & persist findings into IndexedDB (if available)
    try {
      results.forEach(r => {
        try { saveDB("findings", r); } catch (e) {}
        log(`  [${r.type}] (${r.score}) ${String(r.value).slice(0,80)}`, r.score >= 4 ? "#f00" : "#f90");
      });
    } catch (e) {}

    return results;
  };

  // ===== IndexedDB (persistence) =====
  const DB_NAME = "osintDB_v2";
  let db = null;
  const initDB = () => {
    return new Promise((resolve, reject) => {
      try {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = e => {
          db = e.target.result;
          if (!db.objectStoreNames.contains("traffic")) db.createObjectStore("traffic", { autoIncrement: true });
          if (!db.objectStoreNames.contains("findings")) db.createObjectStore("findings", { autoIncrement: true });
        };
        req.onsuccess = e => {
          db = e.target.result;
          resolve();
        };
        req.onerror = () => reject(new Error("indexedDB open error"));
      } catch (e) {
        reject(e);
      }
    });
  };

  const saveDB = (store, data) => {
    try {
      if (!db) return;
      const tx = db.transaction(store, "readwrite");
      tx.objectStore(store).add(data);
    } catch (e) {}
  };

  // ===== netOn (unified) =====
  const netOn = async () => {
    if (netInterceptor) return log("  Ya activo", "#555");
    netInterceptor = true;

    // try to init DB (best-effort)
    try { await initDB(); } catch (e) {}

    // override fetch
    window.fetch = async (...args) => {
      const [url, opts = {}] = args;
      const method = opts.method || "GET";
      const headers = normalizeHeaders(opts.headers);
      const body = opts.body || null;

      findings.endpoints.add(url);

      const record = { url, method, headers, body, time: Date.now() };

      sep("FETCH → " + method);
      log("  URL: " + url, "#0ff");

      // analyze headers for tokens
      try {
        Object.entries(headers).forEach(([k, v]) => {
          if (!k) return;
          log(`  ${k}: ${String(v).slice(0,200)}`, (k && k.toLowerCase().includes("auth")) ? "#f00" : "#0cf");
          if (typeof v === "string" && v.length > 20) {
            findings.tokens.add(v);
            findings.headers.push({ url, k, v });
          }
          // run rules on header values
          try { analyzeText(String(v), url); } catch (e) {}
        });
      } catch (e) {}

      // perform original fetch
      const res = await originalFetch(...args);

      // response clone + analysis
      try {
        const clone = res.clone();
        const text = await clone.text();
        record.response = (typeof text === "string") ? text.slice(0, 2000) : "";

        // save traffic / analyze
        traffic.push(record);
        try { saveDB("traffic", record); } catch (e) {}
        try { analyzeText(text, url); } catch (e) {}

        if (text && (text.includes("token") || text.includes("auth") || text.includes("key"))) {
          log("  ⚠ posible data sensible en response", "#f90");
          const matches = text.match(/(token|api[_-]?key|secret)[^"]{0,40}/gi) || [];
          matches.slice(0,3).forEach(m => log("    " + m, "#f00"));
        }

        const jwtMatches = text && text.match(/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g);
        if (jwtMatches) {
          jwtMatches.forEach(t => {
            findings.tokens.add(t);
            const decoded = decodeJWT(t);
            if (decoded) log("  JWT → " + JSON.stringify(decoded).slice(0,120), "#f90");
          });
        }
      } catch (e) {}

      return res;
    };

    // override XHR
    window.XMLHttpRequest = function () {
      const xhr = new originalXHR();

      let url = "";
      let method = "GET";

      const open = xhr.open;
      xhr.open = function (m, u) {
        try { method = m; url = u; findings.endpoints.add(u); } catch (e) {}
        return open.apply(this, arguments);
      };

      const send = xhr.send;
      xhr.send = function (body) {
        sep("XHR → " + method);
        log("  URL: " + url, "#0ff");

        // store minimal record, response will be added on load
        const recIndex = traffic.push({ url, method, body, time: Date.now() }) - 1;

        if (body && typeof body === "string" && body.length > 20) {
          log("  BODY: " + body.slice(0, 200), "#0cf");
          try { analyzeText(body, url); } catch (e) {}
        }

        this.addEventListener("load", function () {
          try {
            const text = this.responseText;
            try { traffic[recIndex].response = (text || "").slice(0,2000); } catch (e) {}
            try { saveDB("traffic", traffic[recIndex]); } catch (e) {}
            if (text && (text.includes("token") || text.includes("auth"))) {
              log("  ⚠ XHR response interesante", "#f90");
            }
            try { analyzeText(text, url); } catch (e) {}

            const jwtMatches = text && text.match(/eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g);
            if (jwtMatches) {
              jwtMatches.forEach(t => {
                findings.tokens.add(t);
                const decoded = decodeJWT(t);
                if (decoded) log("  JWT → " + JSON.stringify(decoded).slice(0,120), "#f90");
              });
            }
          } catch (e) {}
        });

        return send.apply(this, arguments);
      };

      const setHeader = xhr.setRequestHeader;
      xhr.setRequestHeader = function (k, v) {
        try {
          log(`  ${k}: ${v}`, (k && k.toLowerCase().includes("auth")) ? "#f00" : "#0cf");
          if (typeof v === "string" && v.length > 20) {
            findings.tokens.add(v);
            findings.headers.push({ url, k, v });
          }
        } catch (e) {}
        return setHeader.apply(this, arguments);
      };

      return xhr;
    };

    log("🔥 NET INTERCEPTOR + ANALYSIS ACTIVADO", "#0f0");
  };

  // ===== netOff =====
  const netOff = () => {
    try { window.fetch = originalFetch; } catch (e) {}
    try { window.XMLHttpRequest = originalXHR; } catch (e) {}
    netInterceptor = false;
    log("  Interceptor de red DESACTIVADO", "#ff0");
  };

  // ===== deep scan (scripts) =====
  const deepScan = async () => {
    sep("DEEP SCAN (scripts)");
    const scripts = [...document.querySelectorAll("script[src]")];
    for (const s of scripts) {
      try {
        const res = await originalFetch(s.src);
        const text = await res.text();
        const matches = text.match(/(api[_-]?key|token|secret)[^\n]{0,40}/gi) || [];
        if (matches.length) {
          log("  " + s.src, "#f90");
          matches.slice(0,3).forEach(m => log("    " + m.trim(), "#f00"));
        }
      } catch (e) {}
    }
    log("  Deep scan terminado", "#0f0");
  };

  // ===== traffic viewer, history, inspect, correlate, replay =====
  const showTraffic = () => {
    sep("TRAFFIC");
    if (!traffic.length) return log("  No traffic captured", "#555");
    traffic.slice(-15).forEach((t, i) => {
      log(`  [${i}] ${t.method} ${t.url}`, "#0ff");
      if (t.headers && Object.keys(t.headers).length) {
        log(`    headers: ${JSON.stringify(t.headers).slice(0,200)}`, "#333");
      }
      if (t.response) log(`    response(trunc): ${String(t.response).slice(0,120).replace(/\n/g, " ")}`, "#333");
    });
  };

  const showHistory = () => {
    sep("COMMAND HISTORY");
    if (!history.length) return log("  vacío", "#555");
    history.slice(-20).forEach((cmd, i) => {
      log(`  ${i} → ${cmd}`, "#0ff");
    });
  };

  const inspect = (arg) => {
    sep("INSPECT");
    const idx = parseInt((arg||"").toString().trim(), 10);
    if (isNaN(idx)) return log("  usage: inspect <index>", "#f00");
    const item = traffic[idx];
    if (!item) return log("  no encontrado", "#f00");
    log(`  URL: ${item.url}`, "#0ff");
    log(`  METHOD: ${item.method}`, "#0ff");
    if (item.headers && Object.keys(item.headers).length) {
      log("  HEADERS:", "#f90");
      Object.entries(item.headers).forEach(([k, v]) => log(`    ${k}: ${String(v).slice(0,300)}`, "#0cf"));
    }
    if (item.body) {
      log("  BODY:", "#f90");
      try { log(String(item.body).slice(0,1000), "#0cf"); } catch (e) {}
    }
    if (item.response) {
      log("  RESPONSE:", "#f90");
      try { log(String(item.response).slice(0,1000), "#0cf"); } catch (e) {}
    }
  };

  const replay = async () => {
    sep("REPLAY");
    const last = traffic[traffic.length - 1];
    if (!last) return log("  No hay tráfico", "#555");
    try {
      const headers = last.headers || {};
      const res = await originalFetch(last.url, { method: last.method, headers, body: last.body });
      const text = await res.text();
      log("  STATUS: " + res.status, "#0ff");
      log(String(text).slice(0,400), "#0cf");
    } catch (e) {
      log("  Error en replay: " + String(e), "#f00");
    }
  };

  const correlate = () => {
    sep("CORRELATION ENGINE");
    if (!traffic.length) return log("  no hay tráfico", "#555");
    traffic.slice(-30).forEach((t, i) => {
      const flags = [];
      try {
        if (t.url && t.url.toLowerCase().includes("auth")) flags.push("AUTH");
        if (t.response && t.response.toString().toLowerCase().includes("token")) flags.push("TOKEN");
        if (t.headers && Object.keys(t.headers).some(k => k.toLowerCase().includes("auth") || String(t.headers[k]).toLowerCase().includes("bearer"))) flags.push("HEADER_AUTH");
      } catch (e) {}
      const color = flags.includes("TOKEN") ? "#f00" : flags.includes("AUTH") ? "#f90" : "#0ff";
      log(`  [${i}] ${t.method} ${t.url}`, color);
      if (flags.length) log(`    ⚠ ${flags.join(" | ")}`, "#f00");
    });
  };

  // ===== export all (traffic + findings) =====
  const exportAll = () => {
    const data = {
      tokens: [...findings.tokens],
      endpoints: [...findings.endpoints],
      headers: findings.headers,
      jwt: findings.jwt,
      traffic: traffic.slice(-500)
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "osint_pro.json";
    a.click();
    log("  Export PRO listo", "#0f0");
  };

  // ===== page analysis functions (info, meta, links, etc) =====
  const pageInfo = () => {
    sep("INFO");
    log(`  URL:       ${location.href}`, "#0ff");
    log(`  Title:     ${document.title}`, "#0ff");
    log(`  Lang:      ${document.documentElement.lang || "—"}`, "#0ff");
    log(`  Charset:   ${document.characterSet}`, "#0ff");
    log(`  Scripts:   ${document.scripts.length}`, "#0ff");
    log(`  Links:     ${document.links.length}`, "#0ff");
    log(`  Images:    ${document.images.length}`, "#0ff");
    log(`  Iframes:   ${document.querySelectorAll("iframe").length}`, "#0ff");
  };

  const scanMeta = () => {
    sep("META TAGS");
    document.querySelectorAll("meta").forEach(m => {
      const name = m.getAttribute("name") || m.getAttribute("property") || m.getAttribute("http-equiv") || "—";
      const content = m.getAttribute("content") || "—";
      log(`  ${name}: ${content}`, "#0ff");
    });
  };

  const scanLinks = () => {
    sep("LINKS EXTERNOS");
    const seen = new Set();
    document.querySelectorAll("a[href]").forEach(a => {
      const href = a.href;
      if (href.startsWith("http") && !href.includes(location.hostname) && !seen.has(href)) {
        seen.add(href);
        log("  " + href, "#0cf");
      }
    });
    log(`  Total externos: ${seen.size}`, "#555");
  };

  const scanImages = () => {
    sep("IMÁGENES");
    document.querySelectorAll("img").forEach(img => {
      log(`  [${img.naturalWidth}x${img.naturalHeight}] ${img.src.slice(0, 120)} — "${img.alt || "sin alt"}"`, "#0ff");
    });
  };

  const scanScripts = () => {
    sep("SCRIPTS");
    document.querySelectorAll("script[src]").forEach(s => log("  " + s.src, "#f0f"));
    log(`  Inline: ${document.querySelectorAll("script:not([src])").length}`, "#555");
  };

  const scanHeadings = () => {
    sep("ENCABEZADOS");
    document.querySelectorAll("h1,h2,h3,h4,h5,h6").forEach(h => {
      const level = parseInt(h.tagName[1] || "1", 10);
      const indent = "  ".repeat(Math.max(0, level - 1));
      log(`${indent}[${h.tagName}] ${h.textContent.trim().slice(0, 80)}`, "#0ff");
    });
  };

  const scanForms = () => {
    sep("FORMULARIOS");
    const forms = document.querySelectorAll("form");
    if (!forms.length) { log("  No se encontraron formularios", "#555"); return; }
    forms.forEach((f, i) => {
      log(`  ┌ Form #${i + 1}  action="${f.action}"  method="${f.method || "get"}"`, "#f90");
      f.querySelectorAll("input,select,textarea,button").forEach(inp => {
        log(`  │  [${inp.tagName.toLowerCase()}] name="${inp.name}"  type="${inp.type || "—"}"  placeholder="${inp.placeholder || "—"}"`, "#0ff");
      });
      log(`  └─`, "#333");
    });
  };

  const scanEmails = () => {
    sep("EMAILS");
    const raw = document.body.innerText + document.body.innerHTML;
    const matches = raw.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
    const unique = [...new Set(matches)];
    unique.length ? unique.forEach(e => log("  " + e, "#0f0")) : log("  No encontrados", "#555");
  };

  const scanTech = () => {
    sep("TECNOLOGÍAS DETECTADAS");
    const html = document.documentElement.outerHTML;
    const techs = [
      ["React",       () => !!(window.React || html.includes("react"))],
      ["Vue",         () => !!(window.Vue || html.includes("vue."))],
      ["Angular",     () => !!(window.ng || html.includes("angular"))],
      ["jQuery",      () => !!(window.jQuery || window.$?.fn?.jquery)],
      ["Bootstrap",   () => html.includes("bootstrap")],
      ["Tailwind",    () => html.includes("tailwind")],
      ["WordPress",   () => html.includes("/wp-content/")],
      ["Next.js",     () => html.includes("__NEXT_DATA__")],
      ["Nuxt",        () => html.includes("__NUXT__")],
      ["GTM",         () => html.includes("gtm.js") || html.includes("GTM-")],
      ["GA",          () => html.includes("gtag") || html.includes("ga.js")],
      ["Cloudflare",  () => html.includes("cloudflare")],
      ["GraphQL",     () => html.includes("graphql")],
    ];
    techs.forEach(([name, fn]) => {
      try { log(`  ${fn() ? "✓" : "✗"} ${name}`, fn() ? "#0f0" : "#333"); } catch (e) { log(`  ? ${name}`, "#555"); }
    });
  };

  const scanAccessibility = () => {
    sep("ACCESIBILIDAD");
    const imgs = document.querySelectorAll("img");
    const noAlt = [...imgs].filter(i => !i.alt).length;
    log(`  Imágenes sin alt: ${noAlt}/${imgs.length}`, noAlt > 0 ? "#f90" : "#0f0");
    const inputs = document.querySelectorAll("input,textarea,select");
    const noLabel = [...inputs].filter(i => !i.labels?.length && !i.getAttribute("aria-label")).length;
    log(`  Inputs sin label: ${noLabel}/${inputs.length}`, noLabel > 0 ? "#f90" : "#0f0");
    const h1s = document.querySelectorAll("h1").length;
    log(`  H1 en página: ${h1s}`, h1s === 1 ? "#0f0" : "#f90");
    const lang = document.documentElement.lang;
    log(`  Lang definido: ${lang || "NO"}`, lang ? "#0f0" : "#f90");
  };

  const exportJSON = () => {
    const data = {
      url: location.href,
      title: document.title,
      meta: [...document.querySelectorAll("meta")].map(m => ({
        name: m.getAttribute("name") || m.getAttribute("property") || "",
        content: m.getAttribute("content") || ""
      })),
      links: [...new Set([...document.querySelectorAll("a[href]")].map(a => a.href).filter(h => h.startsWith("http") && !h.includes(location.hostname)))],
      scripts: [...document.querySelectorAll("script[src]")].map(s => s.src),
      images: [...document.querySelectorAll("img")].map(i => ({ src: i.src, alt: i.alt })),
      emails: [...new Set((document.body.innerText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []))]
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "osint_" + location.hostname + ".json";
    a.click();
    log("  Exportado: osint_" + location.hostname + ".json", "#0f0");
  };

  const fullScan = () => {
    pageInfo(); scanMeta(); scanHeadings();
    scanForms(); scanLinks(); scanImages();
    scanScripts(); scanEmails(); scanTech();
    scanAccessibility();
  };

  // ===== COMMANDS object (defined after all functions) =====
  const commands = {
    help: () => {
      sep("COMANDOS");
      [
        ["info", "Info general de la página"],
        ["meta", "Meta tags y SEO"],
        ["links", "Links externos"],
        ["imgs", "Imágenes con dimensiones"],
        ["scripts", "Scripts cargados"],
        ["headings","Estructura de encabezados"],
        ["forms", "Formularios y campos"],
        ["emails", "Emails visibles"],
        ["tech", "Tecnologías detectadas"],
        ["a11y", "Análisis de accesibilidad"],
        ["scan", "Escaneo completo"],
        ["export", "Exportar resultados a JSON"],
        ["cookies", "Mostrar cookies"],
        ["show-deep", "Buscar tokens en DOM/storage"],
        ["net-on", "Interceptar red"],
        ["net-off", "Detener interceptor"],
        ["deep", "Scan profundo de scripts"],
        ["traffic", "Ver tráfico capturado"],
        ["inspect <i>", "Ver request/response por índice"],
        ["replay", "Repetir último request"],
        ["history", "Historial de comandos"],
        ["correlate", "Cruza tráfico + tokens + auth"],
        ["findings", "Resumen de hallazgos"],
        ["export-all", "Exportar todo (traffic + findings)"],
        ["clear", "Limpiar terminal"],
        ["exit", "Cerrar"],
      ].forEach(([cmd, desc]) => {
        const row = el("div", { display: "flex", gap: "10px", marginBottom: "1px" });
        row.appendChild(el("span", { color: "#0f0", minWidth: "140px" }, cmd));
        row.appendChild(el("span", { color: "#555" }, desc));
        out.appendChild(row);
      });
    },

    info: pageInfo,
    meta: scanMeta,
    links: scanLinks,
    imgs: scanImages,
    scripts: scanScripts,
    headings: scanHeadings,
    forms: scanForms,
    emails: scanEmails,
    tech: scanTech,
    a11y: scanAccessibility,
    scan: fullScan,
    export: exportJSON,

    cookies: () => { sep("COOKIES"); (document.cookie ? document.cookie.split(";").forEach(c => log("  " + c.trim(), "#0ff")) : log("  No hay cookies accesibles", "#555")); },

    "show-deep": () => {
      sep("TOKEN HUNTER");
      const sources = [
        document.documentElement.outerHTML,
        (() => { try { return JSON.stringify(localStorage); } catch { return ""; } })(),
        (() => { try { return JSON.stringify(sessionStorage); } catch { return ""; } })()
      ];
      const patterns = [
        /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,
        /Bearer\s+([A-Za-z0-9\-._]+)/gi,
        /api[_-]?key["'\s:=]+([A-Za-z0-9_\-]{16,})/gi
      ];
      sources.forEach(src => {
        patterns.forEach(p => {
          let m;
          while ((m = p.exec(src)) !== null) {
            const token = m[1] || m[0];
            findings.tokens.add(token);
            const decoded = decodeJWT(token);
            log("  " + token.slice(0, 200), decoded ? "#f90" : "#0ff");
          }
        });
      });
      if (!findings.tokens.size) log("  Nada encontrado", "#555");
    },

    "net-on": netOn,
    "net-off": netOff,
    deep: deepScan,
    traffic: showTraffic,
    replay: replay,
    findings: () => {
      sep("RESUMEN");
      log(`  Tokens: ${findings.tokens.size}`, "#f00");
      log(`  Endpoints: ${findings.endpoints.size}`, "#0ff");
      log(`  Headers capturados: ${findings.headers.length}`, "#f90");
      log(`  JWT decodificados: ${findings.jwt.length}`, "#0f0");
    },
    "export-all": exportAll,

    // placeholders (these will be replaced/extended below)
    clear: () => { out.textContent = ""; },
    exit: () => box.remove()
  };

  // attach extra command functions that accept an argument
  commands.history = showHistory;
  commands.inspect = inspect;
  commands.correlate = correlate;

  // ===== INPUT handling (single replace) =====
  input.addEventListener("keydown", e => {
    if (e.key !== "Enter") return;

    const raw = input.value.trim();
    if (!raw) return;

    // store raw command in history
    history.unshift(raw);
    if (history.length > 200) history.pop(); // cap
    histIdx = -1;

    // parse command + arguments
    const parts = raw.split(" ");
    const command = parts[0].toLowerCase();
    const arg = parts.slice(1).join(" ");

    log("❯ " + raw, "#333");

    if (commands[command]) {
      try { commands[command](arg); } catch (err) { log("  Command error: " + String(err), "#f00"); }
    } else {
      log(`Comando desconocido: "${command}" — escribe help`, "#f00");
    }

    input.value = "";
    out.scrollTop = out.scrollHeight;
  });

  // allow arrow navigation through history in input
  input.addEventListener("keydown", e => {
    if (e.key === "ArrowUp") {
      if (histIdx < history.length - 1) histIdx++;
      input.value = history[histIdx] || "";
      e.preventDefault();
    } else if (e.key === "ArrowDown") {
      if (histIdx > 0) histIdx--;
      else { histIdx = -1; input.value = ""; return; }
      input.value = history[histIdx] || "";
      e.preventDefault();
    }
  });

  // initial messages
  log("OSINT TERMINAL v2 READY", "#0f0");
  log("Type 'help' to show commands", "#555");
})();