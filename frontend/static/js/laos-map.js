/* Security Monitor — Lao PDR province map.
 *
 * SVG choropleth of the 18 provinces (users / requests / threats), English +
 * Lao labels, pulsing city points (red ring where attacks originate), hover
 * tooltip, click-to-select. Needs d3 (vendored). All data strings escaped.
 */
(function () {
    'use strict';
    const SVGNS = 'http://www.w3.org/2000/svg';
    const LAO_FONT = "'Noto Sans Lao','Phetsarath OT','Saysettha OT','Lao UI','Leelawadee UI',sans-serif";
    const METRICS = {
        users:    { label: 'Users',    low: '#0c2533', high: '#22d3ee', accent: '#22d3ee' },
        requests: { label: 'Requests', low: '#0f1f3a', high: '#60a5fa', accent: '#60a5fa' },
        threats:  { label: 'Threats',  low: '#2a1016', high: '#f87171', accent: '#f87171' },
    };
    // Labels that would collide with a neighbour: [dx, dy] in px from centroid
    const LABEL_NUDGE = { 'LA-VT': [-18, 30], 'LA-VI': [-14, 10], 'LA-XN': [22, -16], 'LA-XA': [-30, -10], 'LA-XI': [6, -6] };
    // Lao names keyed by ISO 3166-2 (mirrors backend/laos.py)
    const LAO = {
        'LA-VT': ['Vientiane Capital', 'ນະຄອນຫຼວງວຽງຈັນ'], 'LA-PH': ['Phongsaly', 'ຜົ້ງສາລີ'],
        'LA-LM': ['Luang Namtha', 'ຫຼວງນ້ຳທາ'], 'LA-OU': ['Oudomxay', 'ອຸດົມໄຊ'], 'LA-BK': ['Bokeo', 'ບໍ່ແກ້ວ'],
        'LA-LP': ['Luang Prabang', 'ຫຼວງພະບາງ'], 'LA-HO': ['Houaphanh', 'ຫົວພັນ'], 'LA-XA': ['Xayaboury', 'ໄຊຍະບູລີ'],
        'LA-XI': ['Xiengkhouang', 'ຊຽງຂວາງ'], 'LA-VI': ['Vientiane Province', 'ແຂວງວຽງຈັນ'],
        'LA-BL': ['Bolikhamxay', 'ບໍລິຄຳໄຊ'], 'LA-KH': ['Khammouane', 'ຄຳມ່ວນ'], 'LA-SV': ['Savannakhet', 'ສະຫວັນນະເຂດ'],
        'LA-SL': ['Salavan', 'ສາລະວັນ'], 'LA-XE': ['Sekong', 'ເຊກອງ'], 'LA-CH': ['Champasak', 'ຈຳປາສັກ'],
        'LA-AT': ['Attapeu', 'ອັດຕະປື'], 'LA-XN': ['Xaisomboun', 'ໄຊສົມບູນ'],
    };

    let el, svg, tip, features = [], proj, path, W = 0, H = 0;
    let data = null, metric = 'users', selected = null, resizeTimer = null;
    let insets = { top: 0, right: 0, bottom: 0, left: 0 };
    let opts = { onSelect: null };
    const L = {};

    const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    const mk = (tag, attrs = {}, parent) => {
        const n = document.createElementNS(SVGNS, tag);
        for (const k in attrs) n.setAttribute(k, attrs[k]);
        if (parent) parent.appendChild(n);
        return n;
    };
    const provData = iso => (data?.provinces || []).find(p => p.iso === iso);

    function layout() {
        const r = el.getBoundingClientRect();
        if (r.width < 80 || r.height < 80 || !features.length) return;
        W = r.width; H = r.height;
        svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
        const fc = { type: 'FeatureCollection', features };
        proj = d3.geoMercator().fitExtent([[24 + insets.left, 52 + insets.top], [W - 24 - insets.right, H - 40 - insets.bottom]], fc);
        path = d3.geoPath(proj);
        svg.innerHTML = '';
        mk('defs', {}, svg).innerHTML = `
            <filter id="lmGlow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/>
                <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            <filter id="lmShadow" x="-10%" y="-10%" width="120%" height="120%"><feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#22d3ee" flood-opacity=".35"/></filter>`;
        // country silhouette glow underneath
        mk('path', { d: path(fc), fill: 'none', stroke: '#22d3ee', 'stroke-width': 3, opacity: .35, filter: 'url(#lmShadow)' }, svg);
        L.prov = mk('g', {}, svg);
        L.labels = mk('g', { 'pointer-events': 'none' }, svg);
        L.points = mk('g', {}, svg);
        for (const f of features) {
            const iso = f.properties.iso;
            const p = mk('path', { d: path(f), 'data-iso': iso, class: 'lm-prov', 'stroke-linejoin': 'round', style: 'cursor:pointer;transition:fill .6s' }, L.prov);
            p.addEventListener('mouseenter', e => { hoverProv(iso, true); showTip(iso, e); });
            p.addEventListener('mousemove', moveTip);
            p.addEventListener('mouseleave', () => { hoverProv(iso, false); hideTip(); });
            p.addEventListener('click', () => select(selected === iso ? null : iso, true));
            const [cx, cy] = path.centroid(f), [dx, dy] = LABEL_NUDGE[iso] || [0, 0];
            const g = mk('g', { transform: `translate(${(cx + dx).toFixed(1)},${(cy + dy).toFixed(1)})`, 'data-iso': iso }, L.labels);
            if (dx || dy) mk('line', { x1: 0, y1: 0, x2: -dx, y2: -dy, stroke: '#22d3ee', 'stroke-opacity': .4, 'stroke-width': 1 }, g);
            const t1 = mk('text', { 'text-anchor': 'middle', y: -4, 'font-size': 10.5, 'font-weight': 700, fill: '#e6edf3',
                                    'font-family': 'ui-sans-serif,system-ui', 'paint-order': 'stroke', stroke: '#02060c', 'stroke-width': 3 }, g);
            t1.textContent = LAO[iso]?.[0] || f.properties.name;
            const t2 = mk('text', { 'text-anchor': 'middle', y: 9, 'font-size': 10, fill: '#8bd3e6', 'font-family': LAO_FONT,
                                    'paint-order': 'stroke', stroke: '#02060c', 'stroke-width': 3 }, g);
            t2.textContent = LAO[iso]?.[1] || '';
            mk('text', { 'text-anchor': 'middle', y: 23, 'font-size': 11, 'font-weight': 800, 'font-family': 'ui-monospace,monospace',
                         'paint-order': 'stroke', stroke: '#02060c', 'stroke-width': 3, class: 'lm-val' }, g);
        }
        render();
    }

    function render() {
        if (!path) return;
        paintProvinces();
        drawPoints();
    }

    function paintProvinces() {
        const m = METRICS[metric];
        const vals = (data?.provinces || []).map(p => p[metric]);
        const max = Math.max(1, ...vals);
        const scale = v => v ? d3.interpolateRgb(m.low, m.high)(0.18 + 0.82 * Math.sqrt(v / max)) : '#071019';
        L.prov.querySelectorAll('.lm-prov').forEach(p => {
            const iso = p.getAttribute('data-iso'), d = provData(iso), v = d ? d[metric] : 0;
            p.setAttribute('fill', scale(v));
            const sel = iso === selected;
            p.setAttribute('stroke', sel ? '#ffffff' : d?.threats ? 'rgba(248,113,113,.75)' : 'rgba(34,211,238,.45)');
            p.setAttribute('stroke-width', sel ? 2.4 : d?.threats ? 1.4 : 0.9);
            p.setAttribute('filter', sel ? 'url(#lmGlow)' : '');
            if (sel) p.parentNode.appendChild(p);   // bring outline on top
        });
        L.labels.querySelectorAll('g[data-iso]').forEach(g => {
            const d = provData(g.getAttribute('data-iso')), v = d ? d[metric] : 0;
            const t = g.querySelector('.lm-val');
            t.textContent = v ? v.toLocaleString() : '';
            t.setAttribute('fill', metric === 'threats' ? '#fca5a5' : m.accent);
        });
    }

    function drawPoints() {
        L.points.innerHTML = '';
        const pts = (data?.points || []).slice(0, 120);
        const maxU = Math.max(1, ...pts.map(p => p.users));
        for (const p of pts) {
            const xy = proj([p.lon, p.lat]);
            if (!xy) continue;
            const r = 2.5 + 7 * Math.sqrt(p.users / maxU), hot = p.threats > 0;
            const g = mk('g', { transform: `translate(${xy[0].toFixed(1)},${xy[1].toFixed(1)})`, style: 'cursor:pointer' }, L.points);
            mk('circle', { r, fill: 'none', stroke: hot ? '#f87171' : '#22d3ee', 'stroke-width': 1.4, class: 'sm-ping',
                           style: `animation-delay:${(Math.random() * 2).toFixed(2)}s` }, g);
            mk('circle', { r, fill: hot ? '#f87171' : '#67e8f9', opacity: .9, filter: 'url(#lmGlow)' }, g);
            g.addEventListener('mouseenter', e => showPointTip(p, e));
            g.addEventListener('mousemove', moveTip);
            g.addEventListener('mouseleave', hideTip);
        }
    }

    function hoverProv(iso, on) {
        const p = L.prov.querySelector(`[data-iso="${iso}"]`);
        if (!p || iso === selected) return;
        if (on) { p.setAttribute('stroke', '#e6edf3'); p.setAttribute('stroke-width', 1.8); }
        else paintProvinces();
    }
    function select(iso, fromMap) {
        selected = iso;
        paintProvinces();
        if (fromMap && opts.onSelect) opts.onSelect(iso);
    }

    // ── Tooltips ─────────────────────────────────────────────────────────────
    function showTip(iso, ev) {
        const d = provData(iso) || {}, [en, lo] = LAO[iso] || [iso, ''];
        tip.innerHTML = `
            <div class="mb-1.5"><div class="font-bold text-white text-sm">${esc(en)}</div>
                <div class="text-xs" style="color:#8bd3e6;font-family:${LAO_FONT}">${esc(lo)}</div></div>
            <div class="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] font-mono">
                <span style="color:#8b949e">Users (IPs)</span><span style="color:#22d3ee">${(d.users || 0).toLocaleString()}</span>
                <span style="color:#8b949e">Requests</span><span style="color:#60a5fa">${(d.requests || 0).toLocaleString()}</span>
                <span style="color:#8b949e">Threat hits</span><span style="color:${d.threats ? '#f87171' : '#6e7681'}">${(d.threats || 0).toLocaleString()}</span>
                <span style="color:#8b949e">Attacker IPs</span><span style="color:${d.attackers ? '#fb923c' : '#6e7681'}">${d.attackers || 0}</span></div>
            ${d.top_cities?.length ? `<div class="text-[10px] mt-1.5" style="color:#6e7681">Cities: ${d.top_cities.map(esc).join(', ')}</div>` : ''}`;
        tip.classList.remove('hidden');
        moveTip(ev);
    }
    function showPointTip(p, ev) {
        const [en] = LAO[p.province] || [p.province];
        tip.innerHTML = `<div class="font-bold text-white text-xs mb-1">${esc(p.city)} <span style="color:#6e7681">· ${esc(en)}</span></div>
            <div class="grid grid-cols-2 gap-x-3 text-[11px] font-mono">
                <span style="color:#8b949e">Users</span><span style="color:#22d3ee">${p.users}</span>
                <span style="color:#8b949e">Requests</span><span style="color:#60a5fa">${p.requests.toLocaleString()}</span>
                <span style="color:#8b949e">Threat hits</span><span style="color:${p.threats ? '#f87171' : '#6e7681'}">${p.threats}</span></div>`;
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

    window.LaosMap = {
        LAO, METRICS, LAO_FONT,
        async init(container, options) {
            Object.assign(opts, options || {});
            el = container; svg = el.querySelector('svg'); tip = el.querySelector('.sm-map-tip');
            const gj = await (await fetch('/static/vendor/lao-provinces.geojson')).json();
            features = gj.features;
            // d3 wants clockwise outer rings; RFC 7946 GeoJSON (e.g. a refreshed
            // geoBoundaries file) is counter-clockwise, which d3 would draw as
            // "the whole globe minus the province". Rewind anything inverted.
            for (const f of features) {
                const polys = f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
                for (const p of polys) if (d3.geoArea({ type: 'Polygon', coordinates: p }) > 2 * Math.PI) p.forEach(r => r.reverse());
            }
            new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(layout, 160); }).observe(el);
            layout();
            return gj.attribution || '';
        },
        update(d) { data = d; render(); },
        setMetric(m) { if (METRICS[m]) { metric = m; paintProvinces(); } },
        get metric() { return metric; },
        select(iso) { select(iso, false); },
        setInsets(i) { insets = { top: 0, right: 0, bottom: 0, left: 0, ...(i || {}) }; layout(); },
    };
})();
