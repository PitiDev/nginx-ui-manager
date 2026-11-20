/* Security Monitor — global threat map.
 *
 *  canvas  : dot-matrix world (attacking countries heat up red, home = cyan)
 *  svg     : origin markers, arcs to "home" with travelling comets, live
 *            one-shot comets + impact ripples for newly seen events
 *
 * Needs d3 (geo) + topojson-client, both vendored under /static/vendor.
 * Every string that came from logs or the GeoIP DB is escaped before it is
 * put into the tooltip.
 */
(function () {
    'use strict';
    const SEV = { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#60a5fa', info: '#8b949e' };
    const HOME = '#22d3ee';
    const SVGNS = 'http://www.w3.org/2000/svg';

    let el, canvas, svg, tip, layers = {};
    let countries = [], bboxes = [], proj = null, W = 0, H = 0, step = 7;
    let dots = [], homeCountry = -1, countryHeat = new Map();
    let geo = null, primed = false, seen = new Set(), resizeTimer = null;
    const pointNodes = new Map(), arcNodes = new Map(), ccCache = new Map();
    let opts = { onSelect: null, catLabel: c => c, maxLive: 12 };
    let insets = { top: 0, right: 0, bottom: 0, left: 0 };   // px kept free for overlay panels

    const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    const flag = cc => /^[A-Z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc].map(c => 127397 + c.charCodeAt(0))) : '🌐';
    const mk = (tag, attrs = {}, parent) => {
        const n = document.createElementNS(SVGNS, tag);
        for (const k in attrs) n.setAttribute(k, attrs[k]);
        if (parent) parent.appendChild(n);
        return n;
    };

    // ── Geometry helpers ─────────────────────────────────────────────────────
    function inBox(b, lon, lat) {
        const [[x0, y0], [x1, y1]] = b;
        if (lat < y0 || lat > y1) return false;
        return x0 <= x1 ? lon >= x0 && lon <= x1 : lon >= x0 || lon <= x1;   // antimeridian
    }
    function countryOf(lon, lat) {
        const key = lon.toFixed(2) + ',' + lat.toFixed(2);
        if (ccCache.has(key)) return ccCache.get(key);
        let hit = -1;
        for (let i = 0; i < countries.length; i++) {
            if (inBox(bboxes[i], lon, lat) && d3.geoContains(countries[i], [lon, lat])) { hit = i; break; }
        }
        if (ccCache.size > 20000) ccCache.clear();
        ccCache.set(key, hit);
        return hit;
    }
    function arcPath(a, b) {
        const [x1, y1] = a, [x2, y2] = b, dx = x2 - x1, dy = y2 - y1, d = Math.hypot(dx, dy) || 1;
        let nx = -dy / d, ny = dx / d;
        if (ny > 0) { nx = -nx; ny = -ny; }               // always bow upwards
        const lift = Math.min(d * 0.32, H * 0.38);
        return `M${x1.toFixed(1)},${y1.toFixed(1)} Q${((x1 + x2) / 2 + nx * lift).toFixed(1)},${((y1 + y2) / 2 + ny * lift).toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`;
    }
    const homeXY = () => proj([geo.home.lon, geo.home.lat]);

    // ── Layout: projection, land dots, svg skeleton ─────────────────────────
    function layout() {
        const r = el.getBoundingClientRect();
        if (r.width < 80 || r.height < 80) return;
        W = r.width; H = r.height;
        const dpr = window.devicePixelRatio || 1;
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

        proj = d3.geoNaturalEarth1().fitExtent([[12 + insets.left, 14 + insets.top], [W - 12 - insets.right, H - 14 - insets.bottom]],
                                               { type: 'FeatureCollection', features: countries });
        step = Math.max(4.5, Math.min(9, W / 190));
        buildDots();

        svg.innerHTML = '';
        pointNodes.clear(); arcNodes.clear();
        const defs = mk('defs', {}, svg);
        defs.innerHTML = `
            <filter id="smGlow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="2.4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            <radialGradient id="smHomeGrad"><stop offset="0" stop-color="${HOME}" stop-opacity=".55"/><stop offset="1" stop-color="${HOME}" stop-opacity="0"/></radialGradient>`;
        layers.arcs = mk('g', {}, svg);
        layers.points = mk('g', {}, svg);
        layers.fx = mk('g', {}, svg);
        layers.home = mk('g', {}, svg);
        if (geo) { drawHome(); update(geo, null); } else drawBase();
    }

    function buildDots() {
        // Land mask: rasterise countries once, then sample on a grid.
        const off = document.createElement('canvas');
        off.width = Math.ceil(W); off.height = Math.ceil(H);
        const octx = off.getContext('2d');
        const p = d3.geoPath(proj, octx);
        octx.fillStyle = '#fff';
        octx.beginPath(); countries.forEach(f => p(f)); octx.fill();
        const img = octx.getImageData(0, 0, off.width, off.height).data;
        dots = [];
        for (let y = step / 2; y < H; y += step) {
            for (let x = step / 2; x < W; x += step) {
                if (img[(Math.floor(y) * off.width + Math.floor(x)) * 4 + 3] < 128) continue;
                const ll = proj.invert([x, y]);
                dots.push({ x, y, c: ll ? countryOf(ll[0], ll[1]) : -1 });
            }
        }
    }

    function drawBase() {
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H);
        const p = d3.geoPath(proj, ctx);
        ctx.beginPath(); p(d3.geoGraticule10()); ctx.strokeStyle = 'rgba(56,189,248,.055)'; ctx.lineWidth = .6; ctx.stroke();
        ctx.beginPath(); p({ type: 'Sphere' }); ctx.strokeStyle = 'rgba(56,189,248,.22)'; ctx.lineWidth = 1; ctx.stroke();

        const r = step * 0.3;
        for (const d of dots) {
            const heat = countryHeat.get(d.c) || 0;
            if (d.c === homeCountry && d.c !== -1) ctx.fillStyle = 'rgba(34,211,238,.85)';
            else if (heat) ctx.fillStyle = `rgba(${Math.round(120 + 128 * heat)},${Math.round(60 + 53 * (1 - heat))},${Math.round(80 + 33 * (1 - heat))},${(.45 + .5 * heat).toFixed(2)})`;
            else ctx.fillStyle = 'rgba(56,189,248,.22)';
            ctx.beginPath(); ctx.arc(d.x, d.y, heat ? r * 1.15 : r, 0, 6.2832); ctx.fill();
        }
    }

    function drawHome() {
        layers.home.innerHTML = '';
        const [x, y] = homeXY();
        const g = mk('g', { transform: `translate(${x},${y})` }, layers.home);
        mk('circle', { r: 26, fill: 'url(#smHomeGrad)' }, g);
        for (const delay of [0, 1.2]) mk('circle', { r: 6, fill: 'none', stroke: HOME, 'stroke-width': 1.5, class: 'sm-ping', style: `animation-delay:${delay}s` }, g);
        mk('circle', { r: 4.5, fill: HOME, filter: 'url(#smGlow)' }, g);
        mk('circle', { r: 1.8, fill: '#fff' }, g);
        const t = mk('text', { x: 10, y: -10, fill: HOME, 'font-size': 11, 'font-weight': 700, 'font-family': 'ui-monospace,monospace', 'letter-spacing': '.08em' }, g);
        t.textContent = (geo.home.label || 'HOME').toUpperCase();
        homeCountry = countryOf(geo.home.lon, geo.home.lat);
    }

    // ── Data update (diffed so CSS animations keep running) ─────────────────
    function update(g, events) {
        if (!proj || !g) { geo = g; return; }
        const homeMoved = !geo || geo.home.lat !== g.home.lat || geo.home.lon !== g.home.lon || !layers.home.firstChild;
        geo = g;
        if (homeMoved) drawHome();
        const hx = homeXY();

        // country heat (sqrt-scaled share of threat hits)
        const byC = new Map();
        for (const p of g.points) {
            const i = countryOf(p.lon, p.lat);
            if (i >= 0) byC.set(i, (byC.get(i) || 0) + p.hits);
        }
        const mx = Math.max(1, ...byC.values());
        countryHeat = new Map([...byC].map(([k, v]) => [k, Math.sqrt(v / mx)]));
        drawBase();

        // origin markers
        const pts = g.points.slice(0, 150);
        const maxHits = Math.max(1, ...pts.map(p => p.hits));
        const keepP = new Set();
        for (const p of pts) {
            const key = p.lat.toFixed(1) + ',' + p.lon.toFixed(1);
            keepP.add(key);
            const xy = proj([p.lon, p.lat]);
            if (!xy) continue;
            const color = SEV[p.risk] || SEV.info;
            const r = 2.6 + 7 * Math.sqrt(p.hits / maxHits);
            let n = pointNodes.get(key);
            if (!n) {
                const gEl = mk('g', { class: 'sm-pt', style: 'cursor:pointer' }, layers.points);
                n = { g: gEl, ring: mk('circle', { fill: 'none', 'stroke-width': 1.4, class: 'sm-ping', style: `animation-delay:${(Math.random() * 2).toFixed(2)}s` }, gEl),
                      halo: mk('circle', { opacity: .18 }, gEl), core: mk('circle', { filter: 'url(#smGlow)' }, gEl) };
                gEl.addEventListener('mouseenter', e => showTip(n.data, e));
                gEl.addEventListener('mousemove', moveTip);
                gEl.addEventListener('mouseleave', hideTip);
                gEl.addEventListener('click', () => opts.onSelect && n.data && opts.onSelect(n.data.top_ip));
                pointNodes.set(key, n);
            }
            n.data = p;
            n.g.setAttribute('transform', `translate(${xy[0].toFixed(1)},${xy[1].toFixed(1)})`);
            n.ring.setAttribute('r', r); n.ring.setAttribute('stroke', color);
            n.halo.setAttribute('r', r * 2.1); n.halo.setAttribute('fill', color);
            n.core.setAttribute('r', r); n.core.setAttribute('fill', color);
        }
        for (const [k, n] of pointNodes) if (!keepP.has(k)) { n.g.remove(); pointNodes.delete(k); }

        // persistent arcs + comets for the most dangerous origins
        const keepA = new Set();
        g.points.slice(0, 40).forEach((p, i) => {
            const key = p.lat.toFixed(1) + ',' + p.lon.toFixed(1);
            const xy = proj([p.lon, p.lat]);
            if (!xy || Math.hypot(xy[0] - hx[0], xy[1] - hx[1]) < 8) return;
            keepA.add(key);
            const color = SEV[p.risk] || SEV.info;
            const d = arcPath(xy, hx);
            let a = arcNodes.get(key);
            if (!a) {
                const gEl = mk('g', {}, layers.arcs);
                a = { g: gEl, base: mk('path', { fill: 'none', 'stroke-width': 1, 'stroke-dasharray': '2 4', opacity: .35 }, gEl),
                      comet: mk('path', { fill: 'none', 'stroke-width': 2.2, 'stroke-linecap': 'round', pathLength: 100,
                                          'stroke-dasharray': '16 100', class: 'sm-comet', filter: 'url(#smGlow)' }, gEl) };
                const len = Math.hypot(xy[0] - hx[0], xy[1] - hx[1]);
                a.comet.style.setProperty('--dur', (1.8 + len / 260).toFixed(2) + 's');
                a.comet.style.setProperty('--delay', (-Math.random() * 4).toFixed(2) + 's');
                arcNodes.set(key, a);
            }
            for (const n of [a.base, a.comet]) { n.setAttribute('d', d); n.setAttribute('stroke', color); }
        });
        for (const [k, a] of arcNodes) if (!keepA.has(k)) { a.g.remove(); arcNodes.delete(k); }

        // live: one-shot comet for each newly seen, located event
        if (events) {
            const fresh = [];
            for (const e of events) {
                const k = e.dt_iso + e.ip + e.path;
                if (!seen.has(k)) { seen.add(k); if (primed && e.lat != null) fresh.push(e); }
            }
            if (seen.size > 6000) seen = new Set([...seen].slice(-3000));
            primed = true;
            fresh.slice(0, opts.maxLive).forEach((e, i) => setTimeout(() => liveShot(e), i * 260));
        }
    }

    function liveShot(e) {
        const xy = proj([e.lon, e.lat]), hx = homeXY();
        if (!xy) return;
        const color = SEV[e.severity] || SEV.info;
        const flash = mk('circle', { cx: xy[0], cy: xy[1], r: 5, fill: 'none', stroke: color, 'stroke-width': 2, class: 'sm-impact' }, layers.fx);
        flash.addEventListener('animationend', () => flash.remove());
        const p = mk('path', { d: arcPath(xy, hx), fill: 'none', stroke: color, 'stroke-width': 3, 'stroke-linecap': 'round',
                               pathLength: 100, 'stroke-dasharray': '22 100', class: 'sm-comet sm-comet-once', filter: 'url(#smGlow)' }, layers.fx);
        p.style.setProperty('--dur', '1.4s');
        p.addEventListener('animationend', () => {
            p.remove();
            const hit = mk('circle', { cx: hx[0], cy: hx[1], r: 6, fill: 'none', stroke: color, 'stroke-width': 2.5, class: 'sm-impact' }, layers.fx);
            hit.addEventListener('animationend', () => hit.remove());
        });
    }

    // ── Tooltip ──────────────────────────────────────────────────────────────
    function showTip(p, ev) {
        if (!p) return;
        const color = SEV[p.risk] || SEV.info;
        tip.innerHTML = `
            <div class="flex items-center gap-2 mb-1.5"><span class="text-lg leading-none">${flag(p.cc)}</span>
                <div><div class="font-bold text-white text-xs">${esc(p.city || p.country)}</div><div class="text-[10px]" style="color:#8b949e">${esc(p.country)} · ${esc(p.cc)}</div></div>
                <span class="sev sev-${esc(p.risk)} ml-auto">${esc(p.risk)}</span></div>
            <div class="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] font-mono">
                <span style="color:#8b949e">Top IP</span><span style="color:${color}">${esc(p.top_ip)}</span>
                <span style="color:#8b949e">Attacker IPs</span><span class="text-white">${p.ips}</span>
                <span style="color:#8b949e">Threat hits</span><span class="text-white">${p.hits.toLocaleString()}</span>
                <span style="color:#8b949e">Risk score</span><span class="text-white">${p.score}</span></div>
            <div class="flex flex-wrap gap-1 mt-1.5">${(p.cats || []).map(c => `<span class="chip">${esc(opts.catLabel(c))}</span>`).join('')}</div>
            <div class="text-[10px] mt-1.5" style="color:#6e7681">Click to filter events by ${esc(p.top_ip)}</div>`;
        tip.classList.remove('hidden');
        moveTip(ev);
    }
    function moveTip(ev) {
        const r = el.getBoundingClientRect(), tw = tip.offsetWidth, th = tip.offsetHeight;
        let x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 14;
        if (x + tw > W - 6) x = ev.clientX - r.left - tw - 14;
        if (y + th > H - 6) y = ev.clientY - r.top - th - 14;
        tip.style.left = Math.max(6, x) + 'px'; tip.style.top = Math.max(6, y) + 'px';
    }
    function hideTip() { tip.classList.add('hidden'); }

    // ── Public API ───────────────────────────────────────────────────────────
    window.SecMap = {
        flag,
        async init(container, options) {
            Object.assign(opts, options || {});
            el = container;
            canvas = el.querySelector('canvas');
            svg = el.querySelector('svg');
            tip = el.querySelector('.sm-map-tip');
            const topo = await (await fetch('/static/vendor/countries-110m.json')).json();
            countries = topojson.feature(topo, topo.objects.countries).features.filter(f => f.id !== '010'); // no Antarctica
            bboxes = countries.map(f => d3.geoBounds(f));
            new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(layout, 160); }).observe(el);
            layout();
        },
        update,
        resetLive() { primed = false; seen.clear(); },
        setInsets(i) { insets = { top: 0, right: 0, bottom: 0, left: 0, ...(i || {}) }; if (countries.length) layout(); },
    };
})();
