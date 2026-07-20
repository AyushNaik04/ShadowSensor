/** Time range manager singleton. Exposes window.TimeRange. */
window.TimeRange = (function () {
    const KEY = 'shadowsensor-time-range';
    const DEFAULT = { mode: 'quick', quick: '24h', from: null, to: null };
    const LABELS = {
        '15m': 'Last 15 minutes',
        '1h': 'Last 1 hour',
        '6h': 'Last 6 hours',
        '24h': 'Last 24 hours',
        '7d': 'Last 7 days',
        '30d': 'Last 30 days',
    };
    let _state = { ...DEFAULT };
    let _listeners = [];

    function load() {
        try {
            const s = JSON.parse(localStorage.getItem(KEY));
            if (s?.mode) _state = s;
        } catch {}
    }

    function save() {
        try { localStorage.setItem(KEY, JSON.stringify(_state)); } catch {}
    }

    function notify() {
        _listeners.forEach(fn => { try { fn(_state); } catch {} });
    }

    function syncHiddenFields() {
        const quickEl = document.getElementById('param-quick');
        const fromEl = document.getElementById('param-from');
        const toEl = document.getElementById('param-to');
        if (!quickEl || !fromEl || !toEl) return;
        if (_state.mode === 'quick') {
            quickEl.value = _state.quick || '24h';
            fromEl.value = '';
            toEl.value = '';
        } else {
            quickEl.value = '';
            fromEl.value = _state.from || '';
            toEl.value = _state.to || '';
        }
    }

    function updateQuickBtnHighlight() {
        document.querySelectorAll('.quick-btn').forEach(btn => {
            const range = btn.getAttribute('data-range');
            if (_state.mode === 'quick' && range === _state.quick) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }

    function updateDisplay() {
        const el = document.getElementById('time-range-display');
        if (el) {
            el.textContent = _state.mode === 'quick'
                ? (LABELS[_state.quick] || _state.quick)
                : `${_state.from} → ${_state.to}`;
        }
        syncHiddenFields();
        updateQuickBtnHighlight();
    }

    return {
        init() { load(); updateDisplay(); },
        getParams() {
            return _state.mode === 'quick'
                ? `quick=${_state.quick}`
                : `from=${encodeURIComponent(_state.from)}&to=${encodeURIComponent(_state.to)}`;
        },
        setQuick(r) {
            _state = { mode: 'quick', quick: r, from: null, to: null };
            save();
            updateDisplay();
            notify();
        },
        setCustom(f, t) {
            _state = { mode: 'custom', quick: null, from: f, to: t };
            save();
            updateDisplay();
            notify();
        },
        onChange(fn) { _listeners.push(fn); },
        getState() { return { ..._state }; },
    };
})();
