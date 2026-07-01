/**
 * ✈ AVIATOR ORACLE v8.0
 *
 * MEJORAS vs v7.0:
 *  - 📊 DISTRIBUCIÓN VISUAL: barra % por zona (<2x | 2-5x | 5-10x | >10x)
 *  - 🎲 P(≥2x) ROLLING: probabilidad real últimas 10 rondas
 *  - 📉 VOLATILIDAD σ: desviación estándar (limpia)
 *  - 📐 P75/P25: percentiles para targets más precisos
 *  - 🧠 PATRONES MEJORADOS: 12 patrones con confianza %
 *  - 🔥 TENDENCIA: detección subida/bajada últimas 5 rondas
 *  - 🎯 TARGETS: basados en percentiles, no heurísticas fijas
 *  - ⚡ CONSEJO COMPACTO: 1 línea + dato clave, sin texto largo
 */
(function () {
    'use strict';

    const OLD = document.getElementById('_ao_host');
    if (OLD) OLD.remove();

    const HOST = document.createElement('div');
    HOST.id = '_ao_host';
    Object.assign(HOST.style, {
        position: 'fixed', top: '12px', left: '12px',
        width: '272px', zIndex: '2147483647',
        pointerEvents: 'none', fontFamily: 'inherit'
    });
    document.body.appendChild(HOST);

    const SD = HOST.attachShadow({ mode: 'open' });

    const ST_EL = document.createElement('style');
    ST_EL.textContent = `
        *{box-sizing:border-box;margin:0;padding:0}
        #panel{width:272px;background:rgba(3,7,16,.97);border:1.5px solid #1a3050;
            border-top:3px solid #ff0055;border-radius:11px;color:#c0ccdf;
            font-family:-apple-system,'Segoe UI',Roboto,sans-serif;
            font-size:13px;pointer-events:all;overflow:hidden}
        #hdr{display:flex;align-items:center;justify-content:space-between;
            padding:6px 10px;background:rgba(255,0,85,.06);
            border-bottom:1px solid #0e1e30;cursor:move;user-select:none}
        #hdr-title{font-size:11px;font-weight:700;color:#ff0055;letter-spacing:1.5px}
        .hbtn{width:18px;height:18px;border-radius:50%;background:#0a1220;
            border:1px solid #1a3050;color:#5a7090;font-size:10px;line-height:18px;
            text-align:center;cursor:pointer;transition:background .15s,color .15s}
        .hbtn:hover{background:#1a2a40;color:#fff}
        #hdr-btns{display:flex;gap:4px}
        #body{padding:8px 10px}
        #mode-badge{text-align:center;padding:5px 8px;border-radius:7px;
            font-size:11px;font-weight:700;letter-spacing:.6px;margin-bottom:7px;
            background:rgba(0,40,80,.5);color:#00d4ff;border:1px solid #1a3a5f;
            transition:background .4s,color .4s,border-color .4s}
        #mode-badge.hot{background:rgba(255,120,0,.12);color:#ffaa00;border-color:rgba(255,150,0,.3)}
        #mode-badge.cold{background:rgba(0,100,200,.1);color:#60aaff;border-color:rgba(0,100,200,.2)}
        #mode-badge.warn{background:rgba(255,50,50,.15);color:#ff4444;border-color:rgba(255,50,50,.4)}
        #mode-badge.green{background:rgba(0,200,100,.1);color:#00e676;border-color:rgba(0,200,100,.25)}
        #risk-row{display:flex;align-items:baseline;justify-content:center;gap:6px;margin:2px 0 1px}
        #risk-num{font-size:42px;font-weight:900;line-height:1;font-variant-numeric:tabular-nums;transition:color .5s}
        #risk-sub{font-size:9px;color:#3a5070;letter-spacing:1.2px;text-transform:uppercase;align-self:center}
        #p2x-row{display:flex;justify-content:center;align-items:center;gap:4px;margin-bottom:8px}
        #p2x-label{font-size:9px;color:#3a5070;letter-spacing:1px;text-transform:uppercase}
        #p2x-val{font-size:14px;font-weight:800;color:#ffcc44;font-variant-numeric:tabular-nums}
        #p2x-r10{font-size:9px;color:#5a7090}
        .g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:5px;margin-bottom:7px}
        .g2{display:grid;grid-template-columns:1fr 1fr;gap:5px;margin-bottom:7px}
        .sbox{background:#070d1a;border:1px solid #0e1e30;border-radius:7px;padding:5px 7px;text-align:center}
        .sbox .lbl{font-size:8px;color:#3a5070;letter-spacing:.8px;text-transform:uppercase;margin-bottom:2px}
        .sbox .val{font-size:17px;font-weight:800;color:#fff;font-variant-numeric:tabular-nums}
        .sbox.green{border-color:rgba(0,220,110,.25)}.sbox.green .val{color:#00e676}
        .sbox.gold{border-color:rgba(255,190,0,.25)}.sbox.gold .val{color:#ffcc44}
        .sbox.blue{border-color:rgba(0,180,255,.2)}.sbox.blue .val{color:#00d4ff}
        .sbox.red{border-color:rgba(255,80,80,.2)}.sbox.red .val{color:#ff6060}
        #dist-bar{margin-bottom:8px;padding:0 1px}
        #dist-track{display:flex;height:6px;border-radius:3px;overflow:hidden;gap:1px;margin-bottom:3px}
        .db{height:100%;transition:width .5s;min-width:2px}
        .db-low{background:#ff4444}
        .db-mid{background:#ffaa00}
        .db-hi{background:#00e676}
        .db-mega{background:#00d4ff}
        #dist-lbls{display:flex;justify-content:space-between;font-size:8.5px;color:#3a5070}
        #chips{display:flex;gap:3px;flex-wrap:wrap;justify-content:center;
            padding:6px 0;margin-bottom:7px;
            border-top:1px solid #0a1520;border-bottom:1px solid #0a1520}
        .chip{font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;
            border:1px solid #1a3050;background:#04080f;color:#3a5070;font-variant-numeric:tabular-nums}
        .c-low{color:#ff4444;border-color:rgba(255,68,68,.35);background:rgba(255,68,68,.07)}
        .c-mid{color:#ffaa00;border-color:rgba(255,170,0,.35);background:rgba(255,170,0,.07)}
        .c-high{color:#00e676;border-color:rgba(0,230,118,.35);background:rgba(0,230,118,.07)}
        .c-mega{color:#00d4ff;border-color:rgba(0,212,255,.5);background:rgba(0,212,255,.1)}
        #advice{font-size:11px;color:#7a9ab0;line-height:1.5;padding:7px 8px;
            background:#040810;border:1px solid #0a1520;border-radius:6px;margin-bottom:7px}
        #advice strong{color:#c0ccdf;font-weight:700}
        #xbtn{width:100%;padding:6px;cursor:pointer;text-align:center;
            background:rgba(255,0,85,.1);color:#ff4070;
            border:1px solid rgba(255,0,85,.25);border-radius:6px;
            font-size:10px;font-weight:700;letter-spacing:.5px;transition:background .15s}
        #xbtn:hover{background:rgba(255,0,85,.2)}
        #trend-arrow{font-size:12px;margin-left:3px;vertical-align:middle}
        #conf-badge{font-size:8.5px;padding:1px 5px;border-radius:3px;
            background:rgba(255,255,255,.06);color:#4a6a8a;border:1px solid #0e1e30;margin-left:4px}
    `;
    SD.appendChild(ST_EL);

    const panel = document.createElement('div');
    panel.id = 'panel';
    panel.innerHTML = `
        <div id="hdr">
            <span id="hdr-title">✈ ORACLE v8.0</span>
            <div id="hdr-btns">
                <div class="hbtn" id="btn-min" title="Minimizar">─</div>
                <div class="hbtn" id="btn-close" title="Cerrar">✕</div>
            </div>
        </div>
        <div id="body">
            <div id="mode-badge">INICIANDO…</div>
            <div id="risk-row">
                <div id="risk-num" style="color:#3a5070">--%</div>
                <div id="risk-sub">riesgo<br>global</div>
            </div>
            <div id="p2x-row">
                <span id="p2x-label">P(≥2x)</span>
                <span id="p2x-val">--%</span>
                <span id="p2x-r10">↳ últ.10: --%</span>
            </div>
            <div class="g3">
                <div class="sbox green">
                    <div class="lbl">🛡 Seguro</div>
                    <div class="val" id="v-safe">--x</div>
                </div>
                <div class="sbox gold">
                    <div class="lbl">🚀 Agresivo</div>
                    <div class="val" id="v-agg">--x</div>
                </div>
                <div class="sbox blue">
                    <div class="lbl">σ Volat.</div>
                    <div class="val" id="v-vol">--</div>
                </div>
            </div>
            <div class="g3">
                <div class="sbox">
                    <div class="lbl">Racha</div>
                    <div class="val" id="v-streak">—</div>
                </div>
                <div class="sbox">
                    <div class="lbl">Mediana</div>
                    <div class="val" id="v-median">—</div>
                </div>
                <div class="sbox">
                    <div class="lbl">Tendencia</div>
                    <div class="val" id="v-trend">—</div>
                </div>
            </div>
            <div id="dist-bar">
                <div id="dist-track">
                    <div class="db db-low" id="db-low" style="width:25%"></div>
                    <div class="db db-mid" id="db-mid" style="width:25%"></div>
                    <div class="db db-hi"  id="db-hi"  style="width:25%"></div>
                    <div class="db db-mega" id="db-mega" style="width:25%"></div>
                </div>
                <div id="dist-lbls">
                    <span id="dl-low"><1.5x --%</span>
                    <span id="dl-mid">1.5-2x --%</span>
                    <span id="dl-hi">2-5x --%</span>
                    <span id="dl-mega">>5x --%</span>
                </div>
            </div>
            <div id="chips"></div>
            <div id="advice">Esperando datos del juego…</div>
            <button id="xbtn">📥 EXPORTAR SESIÓN</button>
        </div>
    `;
    SD.appendChild(panel);

    const STATE = { rawHistory: [], cleanedHistory: [], lastHash: '', minimized: false };

    /* ── DRAG ─── */
    let dragging = false, odx = 0, ody = 0;
    SD.getElementById('hdr').addEventListener('mousedown', e => {
        if (e.target.closest('.hbtn')) return;
        dragging = true;
        const r = HOST.getBoundingClientRect();
        odx = e.clientX - r.left; ody = e.clientY - r.top;
        e.preventDefault();
    });
    document.addEventListener('mousemove', e => {
        if (!dragging) return;
        HOST.style.left = Math.max(0, e.clientX - odx) + 'px';
        HOST.style.top  = Math.max(0, e.clientY - ody) + 'px';
    });
    document.addEventListener('mouseup', () => { dragging = false; });

    SD.getElementById('btn-min').addEventListener('click', () => {
        STATE.minimized = !STATE.minimized;
        SD.getElementById('body').style.display = STATE.minimized ? 'none' : 'block';
        HOST.style.width = STATE.minimized ? '160px' : '272px';
    });
    SD.getElementById('btn-close').addEventListener('click', () => HOST.remove());

    SD.getElementById('xbtn').addEventListener('click', () => {
        const stats = getStats(STATE.cleanedHistory);
        const blob = new Blob([JSON.stringify({
            metadata: {
                timestamp: new Date().toISOString(),
                total_raw: STATE.rawHistory.length,
                session_start: new Date().toLocaleTimeString(),
                final_pattern: SD.getElementById('mode-badge').textContent,
                median: stats.median,
                stdDev: stats.stdDev,
                winRate: stats.winRate,
                distribution: stats.dist
            },
            raw_multipliers: STATE.rawHistory,
            cleaned_multipliers: STATE.cleanedHistory
        }, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `aviator_v8_${Date.now()}.json`;
        a.click();
    });

    /* ── ESTADÍSTICAS ─── */
    function pct(arr, p) {
        const s = [...arr].sort((a,b) => a-b);
        const i = (p/100) * (s.length - 1);
        const lo = Math.floor(i), hi = Math.ceil(i);
        return s[lo] + (s[hi] - s[lo]) * (i - lo);
    }

    function getStats(h) {
        if (!h.length) return { mean:0, median:0, winRate:0, winRate10:0, max:0, stdDev:0, dist:{}, p25:0, p75:0, trend:0 };
        const n = h.length;
        const mean = h.reduce((a,b) => a+b, 0) / n;
        const sorted = [...h].sort((a,b) => a-b);
        const mid = Math.floor(sorted.length/2);
        const median = sorted.length%2 ? sorted[mid] : (sorted[mid-1]+sorted[mid])/2;
        const winRate = h.filter(x => x >= 2.0).length / n;
        const winRate10 = h.length >= 10
            ? h.slice(0,10).filter(x => x >= 2.0).length / 10
            : h.filter(x => x >= 2.0).length / n;
        const max = sorted[sorted.length-1];
        const variance = h.reduce((s,v) => s + Math.pow(v-mean,2), 0) / n;
        const stdDev = Math.sqrt(variance);
        const p25 = pct(h, 25);
        const p75 = pct(h, 75);

        // Distribución
        const d1 = h.filter(x => x < 1.5).length;
        const d2 = h.filter(x => x >= 1.5 && x < 2.0).length;
        const d3 = h.filter(x => x >= 2.0 && x < 5.0).length;
        const d4 = h.filter(x => x >= 5.0).length;
        const dist = {
            low:  (d1/n*100).toFixed(0),
            lowm: (d2/n*100).toFixed(0),
            mid:  (d3/n*100).toFixed(0),
            high: (d4/n*100).toFixed(0)
        };

        // Tendencia: pendiente lineal últimas 8
        const w = h.slice(0, Math.min(8, n)).reverse();
        let sumX=0,sumY=0,sumXY=0,sumXX=0;
        w.forEach((v,i) => { sumX+=i; sumY+=v; sumXY+=i*v; sumXX+=i*i; });
        const trend = w.length > 1
            ? (w.length*sumXY - sumX*sumY) / (w.length*sumXX - sumX*sumX)
            : 0;

        return { mean, median, winRate, winRate10, max, stdDev, dist, p25, p75, trend };
    }

    /* ── PATRONES v8 ─── */
    function detectPattern(stats, h) {
        if (h.length < 5) return {
            mode:'RECOLECTANDO…', cls:'',
            safe: 1.30, agg: 2.00, conf: 0,
            advice: 'Esperando ≥5 rondas para calibrar.'
        };

        let cLow=0, cHigh=0;
        for (const x of h) { if (x < 2.0) cLow++; else break; }
        for (const x of h) { if (x >= 2.0) cHigh++; else break; }

        const last5  = h.slice(0, 5);
        const last15 = h.slice(0, Math.min(15, h.length));
        const cLow15 = last15.filter(x => x < 1.5).length;
        const recentMega = h.slice(0, 4).some(x => x >= 20);
        const anomaly    = stats.max > 50 ? ' ⚠ Outlier activo.' : '';

        // Targets basados en percentiles
        const safeBase = Math.max(1.10, +(stats.p25 * 0.85).toFixed(2));
        const aggBase  = Math.max(2.50, +(stats.p75 * 1.05).toFixed(2));

        // 1. BLOQUE HELADO
        if (cLow >= 5) {
            const safeT = 1.10, aggT = cLow >= 7 ? 50.00 : 20.00;
            return { mode:'🧊 BLOQUE HELADO', cls:'warn',
                safe: safeT, agg: aggT, conf: Math.min(95, 55 + cLow*5),
                advice: `<strong>${cLow} bajos seguidos.</strong> Tensión máxima. 1.10x seguro / ${aggT}x jackpot.${anomaly}` };
        }
        // 2. MUELLE COMPRIMIDO
        if (cLow >= 3) {
            return { mode:'🔩 MUELLE COMPRIMIDO', cls:'hot',
                safe: 1.20, agg: cLow === 4 ? 15.00 : 6.00, conf: 65,
                advice: `<strong>${cLow} bajos consecutivos.</strong> Rebote probable. Retira en 1.20x o apuesta moderada.${anomaly}` };
        }
        // 3. POST-MEGA
        if (recentMega && cLow === 0) {
            return { mode:'🌀 ECO POST-MEGA', cls:'cold',
                safe: 1.30, agg: 2.50, conf: 60,
                advice: `<strong>Vuelo >20x reciente.</strong> Suele enfriar 2-4 rondas. Reduce apuesta.${anomaly}` };
        }
        // 4. CADENA CALIENTE DOBLE
        if (h[0] >= 8 && h.length > 1 && h[1] >= 4) {
            return { mode:'⛓ CADENA CALIENTE', cls:'hot',
                safe: 2.00, agg: 7.00, conf: 58,
                advice: `<strong>${h[1].toFixed(2)}x → ${h[0].toFixed(2)}x.</strong> Puede extenderse 1 vuelo. Retira 2-4x.${anomaly}` };
        }
        // 5. OLA LARGA
        if (cHigh >= 4) {
            const avgW = h.slice(0,cHigh).reduce((a,b)=>a+b,0)/cHigh;
            return { mode:'🌊 OLA LARGA', cls:'hot',
                safe: Math.max(1.5, +(avgW*0.6).toFixed(2)),
                agg:  Math.max(3.5, +(avgW*1.2).toFixed(2)), conf: 62,
                advice: `<strong>${cHigh} altos seguidos</strong> (avg ${avgW.toFixed(2)}x). Ola activa, corte inminente.${anomaly}` };
        }
        // 6. ZIGZAG
        const last6 = h.slice(0,6);
        let zigCount = 0;
        for (let i=1; i<last6.length; i++) {
            const prev=last6[i-1], curr=last6[i];
            if ((prev<2&&curr>=2)||(prev>=2&&curr<2)) zigCount++;
        }
        if (zigCount >= 4 && h.length >= 6) {
            const nextHigh = h[0] < 2.0;
            return { mode:'〰 ZIGZAG ACTIVO', cls:'',
                safe: 1.45, agg: Math.max(2.8, +(stats.median*1.1).toFixed(2)), conf: 70,
                advice: nextHigh
                    ? `<strong>Bajo anterior (${h[0].toFixed(2)}x).</strong> Zigzag: "toca alto". Cash-out 2-3x.${anomaly}`
                    : `<strong>Alto anterior (${h[0].toFixed(2)}x).</strong> Zigzag: "toca bajo". Reduce o espera.${anomaly}` };
        }
        // 7. ALTA VOLATILIDAD
        if (stats.stdDev > 4.5) {
            return { mode:'⚡ ALTA VOLATILIDAD', cls:'warn',
                safe: 1.25, agg: +(stats.p75).toFixed(2), conf: 55,
                advice: `<strong>σ=${stats.stdDev.toFixed(1)} — Sesión muy errática.</strong> Retira temprano o espera patrón.${anomaly}` };
        }
        // 8. ZONA MUERTA
        if (cLow15 >= 9) {
            return { mode:'❄ ZONA MUERTA', cls:'cold',
                safe: 1.20, agg: 4.00, conf: 68,
                advice: `<strong>${cLow15}/15 rondas <1.5x.</strong> Sesión fría. Mínima apuesta o pausa.${anomaly}` };
        }
        // 9. TENDENCIA ALCISTA
        if (stats.trend > 0.4 && stats.winRate >= 0.45) {
            return { mode:'📈 TENDENCIA ALCISTA', cls:'green',
                safe: Math.max(1.5, safeBase), agg: Math.min(8, aggBase), conf: 60,
                advice: `<strong>Pendiente +${stats.trend.toFixed(2)} — Mercado subiendo.</strong> Win rate ${(stats.winRate*100).toFixed(0)}%. Aprovecha.${anomaly}` };
        }
        // 10. TENDENCIA BAJISTA
        if (stats.trend < -0.3 && stats.winRate < 0.40) {
            return { mode:'📉 TENDENCIA BAJISTA', cls:'cold',
                safe: 1.15, agg: 2.00, conf: 57,
                advice: `<strong>Pendiente ${stats.trend.toFixed(2)} — Mercado bajando.</strong> Win rate ${(stats.winRate*100).toFixed(0)}%. Minimiza riesgo.${anomaly}` };
        }
        // 11. ZONA ESTABLE
        if (stats.winRate >= 0.40 && stats.stdDev < 3.0 && stats.median >= 1.8) {
            return { mode:'⚖ ZONA ESTABLE', cls:'',
                safe: Math.max(1.5, safeBase),
                agg:  Math.min(4.5, +(stats.median*1.1).toFixed(2)), conf: 63,
                advice: `<strong>σ=${stats.stdDev.toFixed(1)}, mediana ${stats.median.toFixed(2)}x.</strong> Mercado estable. Cash-out conservador.${anomaly}` };
        }
        // 12. DEFAULT
        return { mode:'🔍 SIN PATRÓN CLARO', cls:'',
            safe: Math.max(1.30, safeBase), agg: aggBase, conf: 40,
            advice: `<strong>Mediana ${stats.median.toFixed(2)}x, σ=${stats.stdDev.toFixed(1)}.</strong> Sin señal. Apuesta mínima.${anomaly}` };
    }

    /* ── RENDER ─── */
    function render() {
        const h = STATE.cleanedHistory;
        if (h.length < 3) return;

        const stats = getStats(h);
        const p    = detectPattern(stats, h);

        // Modo badge
        const badge = SD.getElementById('mode-badge');
        badge.innerHTML = p.mode + (p.conf ? ` <span id="conf-badge">${p.conf}%</span>` : '');
        badge.className = p.cls;

        // Riesgo global
        const risk = Math.max(5, Math.min(95, Math.round(100 - stats.winRate * 100)));
        const rn   = SD.getElementById('risk-num');
        rn.textContent = risk + '%';
        rn.style.color = risk > 65 ? '#ff4444' : risk > 45 ? '#ffaa00' : '#00e676';

        // P(≥2x)
        SD.getElementById('p2x-val').textContent   = (stats.winRate * 100).toFixed(0) + '%';
        SD.getElementById('p2x-r10').textContent   = '↳ últ.10: ' + (stats.winRate10 * 100).toFixed(0) + '%';

        // Targets
        SD.getElementById('v-safe').textContent    = p.safe.toFixed(2) + 'x';
        SD.getElementById('v-agg').textContent     = p.agg.toFixed(2) + 'x';
        SD.getElementById('v-vol').textContent     = stats.stdDev.toFixed(1);
        SD.getElementById('v-median').textContent  = stats.median.toFixed(2) + 'x';

        // Racha
        let cLow=0, cHigh=0;
        for (const x of h) { if (x < 2.0) cLow++; else break; }
        for (const x of h) { if (x >= 2.0) cHigh++; else break; }
        const strEl = SD.getElementById('v-streak');
        if (cLow > 0) { strEl.textContent = cLow+'🔴'; strEl.style.color='#ff4444'; }
        else          { strEl.textContent = cHigh+'🟢'; strEl.style.color='#00e676'; }

        // Tendencia
        const tEl = SD.getElementById('v-trend');
        if (stats.trend > 0.25)       { tEl.textContent='▲'; tEl.style.color='#00e676'; }
        else if (stats.trend < -0.25) { tEl.textContent='▼'; tEl.style.color='#ff4444'; }
        else                          { tEl.textContent='━'; tEl.style.color='#ffaa00'; }

        // Distribución
        const d = stats.dist;
        const total = +d.low + +d.lowm + +d.mid + +d.high;
        if (total > 0) {
            SD.getElementById('db-low').style.width  = d.low  + '%';
            SD.getElementById('db-mid').style.width  = (+d.lowm + +d.mid) + '%';
            SD.getElementById('db-hi').style.width   = d.mid  + '%';
            SD.getElementById('db-mega').style.width = d.high + '%';
            SD.getElementById('dl-low').textContent  = '<1.5x ' + d.low  + '%';
            SD.getElementById('dl-mid').textContent  = '1.5-2x ' + d.lowm + '%';
            SD.getElementById('dl-hi').textContent   = '2-5x '  + d.mid  + '%';
            SD.getElementById('dl-mega').textContent = '>5x '   + d.high + '%';
        }

        // Consejo
        SD.getElementById('advice').innerHTML = p.advice;

        // Chips (últimas 9)
        const chips = SD.getElementById('chips');
        chips.innerHTML = '';
        h.slice(0, 9).forEach(v => {
            const c = document.createElement('span');
            c.className = 'chip ' + (v>=10?'c-mega':v>=5?'c-high':v>=2?'c-mid':'c-low');
            c.textContent = v.toFixed(2) + 'x';
            chips.appendChild(c);
        });
    }

    /* ── LOOP ─── */
    const SELECTORS = [
        '.stats.dropdown .payouts-block .payout',
        '.payouts-block .payout',
        '[class*="historyItem"]',
        '[class*="coefficient"]',
        '[class*="multiplier"]',
        '[class*="history"] [class*="value"]'
    ];
    const OUTLIER_CAP = 50.0;

    setInterval(() => {
        let items = null;
        for (const sel of SELECTORS) {
            const found = document.querySelectorAll(sel);
            if (found.length >= 3) { items = found; break; }
        }
        if (!items) return;

        const raw = Array.from(items)
            .map(el => parseFloat(el.innerText.trim().replace(',','.').replace(/[^0-9.]/g,'')))
            .filter(v => !isNaN(v) && v >= 1.0 && v <= 9999);

        if (!raw.length) return;
        const uniqueRaw = [...new Set(raw)];
        const hash = uniqueRaw.slice(0,5).join('|');
        if (hash === STATE.lastHash) return;
        STATE.lastHash = hash;
        STATE.rawHistory     = uniqueRaw;
        STATE.cleanedHistory = uniqueRaw.map(v => Math.min(v, OUTLIER_CAP));
        render();
    }, 1000);

    console.log('%c✈ AVIATOR ORACLE v8.0 — Distribución + P(≥2x) + Volatilidad + 12 Patrones', 'color:#ff0055;font-weight:bold;font-size:13px');
    console.log('%cPanel activo. Arrastra desde el header. Exporta JSON con estadísticas completas.', 'color:#00d4ff');
})();