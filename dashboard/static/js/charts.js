/** ApexCharts helpers. Destroy existing instance before re-creating (safe on repeated calls). */
const _charts = {};

function _destroy(id) {
    if (_charts[id]) {
        try { _charts[id].destroy(); } catch {}
        delete _charts[id];
    }
}

function _cssVar(v) {
    return getComputedStyle(document.documentElement).getPropertyValue(v).trim();
}

function _baseOpts() {
    const th = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
    return {
        chart: { fontFamily: 'inherit', background: 'transparent', toolbar: { show: false } },
        theme: { mode: th },
        tooltip: { theme: th },
        grid: { borderColor: _cssVar('--border-color') },
    };
}

function initTimelineChart(id, data) {
    _destroy(id);
    const el = document.getElementById(id);
    if (!el) return;
    if (!data?.length) {
        el.innerHTML = '<div class="empty-state">No data in this time range</div>';
        return;
    }
    const chart = new ApexCharts(el, {
        ..._baseOpts(),
        chart: { ..._baseOpts().chart, type: 'area', height: 220 },
        series: [{ name: 'Alerts', data: data.map(d => ({ x: new Date(d.bucket).getTime(), y: d.count })) }],
        xaxis: { type: 'datetime', labels: { style: { colors: _cssVar('--text-secondary') } } },
        yaxis: { min: 0, labels: { style: { colors: _cssVar('--text-secondary') } } },
        stroke: { curve: 'smooth', width: 2 },
        fill: { type: 'gradient', gradient: { opacityFrom: 0.4, opacityTo: 0.05 } },
        colors: [_cssVar('--accent')],
        dataLabels: { enabled: false },
    });
    chart.render();
    _charts[id] = chart;
}

function initDonutChart(id, data) {
    _destroy(id);
    const el = document.getElementById(id);
    if (!el) return;
    const labels = ['Critical', 'High', 'Medium', 'Low'];
    const values = labels.map(l => data[l] || 0);
    if (values.every(v => v === 0)) {
        el.innerHTML = '<div class="empty-state">No alerts in this time range</div>';
        return;
    }
    const chart = new ApexCharts(el, {
        ..._baseOpts(),
        chart: { ..._baseOpts().chart, type: 'donut', height: 260 },
        series: values,
        labels,
        colors: labels.map(l => _cssVar(`--sev-${l.toLowerCase()}`)),
        legend: { position: 'right', labels: { colors: _cssVar('--text-primary') } },
        plotOptions: { pie: { donut: { size: '65%' } } },
    });
    chart.render();
    _charts[id] = chart;
}

function initTopRulesChart(id, data) {
    _destroy(id);
    const el = document.getElementById(id);
    if (!el) return;
    if (!data?.length) {
        el.innerHTML = '<div class="empty-state">No rule hits in this time range</div>';
        return;
    }
    const chart = new ApexCharts(el, {
        ..._baseOpts(),
        chart: { ..._baseOpts().chart, type: 'bar', height: 260 },
        plotOptions: { bar: { horizontal: true, distributed: true } },
        series: [{ name: 'Hits', data: data.map(d => d.count) }],
        xaxis: {
            categories: data.map(d => d.rule_name.length > 28 ? d.rule_name.slice(0, 26) + '…' : d.rule_name),
            labels: { style: { colors: _cssVar('--text-secondary') } },
        },
        colors: data.map(d => _cssVar(`--sev-${(d.top_severity || 'low').toLowerCase()}`)),
        legend: { show: false },
        dataLabels: { enabled: true, style: { colors: ['#fff'] } },
    });
    chart.render();
    _charts[id] = chart;
}
