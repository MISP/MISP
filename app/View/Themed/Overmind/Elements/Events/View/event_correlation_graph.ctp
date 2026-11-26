<?php
$eventId   = h($data['Event']['id']   ?? '');
$eventInfo = addslashes(h($data['Event']['info'] ?? ''));
$eventDate = addslashes(h($data['Event']['date'] ?? ''));

echo $this->element('genericElements/assetLoader', [
    'js' => ['d3', 'd3-sankey.min']
]);
?>

<div class="card shadow-sm mb-3">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:rgba(66,139,202,.15);">
                <i class="fas fa-project-diagram" style="color:#428bca;font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Correlation Graph') ?></div>
                <div class="small text-muted mt-1" id="sankey-count">…</div>
            </div>
        </div>
    </div>

    <!-- BODY -->
    <div class="p-3">

        <!-- Loader -->
        <div id="correlations-loader" class="text-center py-4 text-muted">
            <div class="spinner-border spinner-border-sm me-2" role="status"></div>
            <?= h(__('Analyzing correlations…')) ?>
        </div>

        <!-- Content (revealed after fetch) -->
        <div id="correlations-content" style="display:none;">

            <!-- Sankey stage -->
            <div id="sankey-stage" class="sankey-stage" style="display:none;">

                <!-- Toolbar -->
                <div id="sankey-toolbar" class="d-flex align-items-center gap-2 flex-wrap mb-2"
                     style="min-height:24px;">
                    <span id="sankey-filter-badge" class="badge text-bg-danger d-none">
                        <i class="fas fa-filter me-1"></i>
                        <span id="sankey-filter-label"></span>
                        <a href="#" class="text-white ms-1 text-decoration-none"
                           onclick="omResetCorrelationFilter();return false;"
                           title="<?= h(__('Remove filter')) ?>">
                            <i class="fas fa-times-circle"></i>
                        </a>
                    </span>
                    <span id="sankey-zoom-badge" class="badge text-bg-primary d-none">
                        <i class="fa-solid fa-magnifying-glass-plus me-1"></i>
                        <span id="sankey-zoom-label"></span>
                        <a href="#" id="sankey-zoom-reset" class="text-white ms-1 text-decoration-none"
                           title="<?= h(__('Show the whole period')) ?>">
                            <i class="fas fa-times-circle"></i>
                        </a>
                    </span>
                    <span id="sankey-limit-msg" class="small text-muted"></span>
                    <span id="sankey-wl-msg" class="small text-muted"></span>
                    <button type="button" id="sankey-filters-open"
                            class="btn btn-sm btn-outline-secondary ms-auto d-inline-flex align-items-center gap-2"
                            data-bs-toggle="offcanvas" data-bs-target="#sankey-filters"
                            aria-controls="sankey-filters">
                        <i class="fa-solid fa-sliders"></i>
                        <?= h(__('Filters')) ?>
                        <span id="sankey-filters-count" class="badge rounded-pill text-bg-correlation d-none"></span>
                    </button>
                </div>

                <!-- Empty state (no correlation, or everything filtered out) -->
                <div id="sankey-empty"
                     class="d-none d-flex flex-column align-items-center text-muted pt-2 small"></div>

                <!-- Graph -->
                <div style="display:flex;align-items:flex-start;justify-content:center;width:100%;">
                    <div id="sankey-shell" class="sankey-shell">
                        <div id="sankey" style="width:100%;height:400px;margin:0 auto;overflow-x:auto;"></div>
                        <button type="button" id="sankey-exclude-btn"
                                class="sankey-exclude-btn btn btn-light border text-danger rounded-circle shadow-sm p-0 position-absolute d-none"
                                title="<?= h(__('Exclude from the graph')) ?>"
                                aria-label="<?= h(__('Exclude from the graph')) ?>">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Related events list with correlating attributes -->
            <div id="correlations-list" style="display:none;">
                <div class="d-flex align-items-center gap-2 mt-3 mb-1">
                    <span class="fw-semibold small text-uppercase text-muted"
                          style="letter-spacing:.05em;white-space:nowrap;">
                        <?= h(__('Correlated events')) ?>
                    </span>
                    <hr class="flex-fill m-0 opacity-25">
                </div>
                <div id="correlations-list-body" class="d-flex flex-column"></div>
            </div>

        </div>
    </div>
</div>

<!-- Filters: no backdrop, so the graph keeps redrawing beside the drawer -->
<div class="offcanvas offcanvas-end" tabindex="-1" id="sankey-filters"
     data-bs-scroll="true" data-bs-backdrop="false" aria-labelledby="sankey-filters-title">
    <div class="offcanvas-header border-bottom">
        <div>
            <div class="small fw-bold text-uppercase text-correlation"><?= h(__('Correlation Graph')) ?></div>
            <h5 class="offcanvas-title mb-0" id="sankey-filters-title"><?= h(__('Filters')) ?></h5>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="offcanvas"
                aria-label="<?= h(__('Close')) ?>"></button>
    </div>
    <div class="offcanvas-body d-flex flex-column gap-4">
        <section>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'correlation',
                'label' => __('Display'),
            ]) ?>
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" role="switch" id="sankey-date-align" checked>
                <label class="form-check-label" for="sankey-date-align"><?= h(__('Use timeline')) ?></label>
            </div>
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" role="switch" id="sankey-show-publisher" checked>
                <label class="form-check-label" for="sankey-show-publisher"><?= h(__('Show publishers')) ?></label>
            </div>
        </section>

        <section>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'correlation',
                'label' => __('Limits'),
            ]) ?>
            <div class="form-check form-switch" id="sankey-hide-warninglist-toggle">
                <input class="form-check-input" type="checkbox" role="switch" id="sankey-hide-warninglist">
                <label class="form-check-label" for="sankey-hide-warninglist"><?= h(__('Hide warninglist hits')) ?></label>
            </div>
            <label class="form-label small mt-3 mb-1" for="sankey-event-limit"><?= h(__('Most recent events shown')) ?></label>
            <input type="number" class="form-control form-control-sm" id="sankey-event-limit"
                   min="1" step="1" inputmode="numeric" placeholder="<?= h(__('All')) ?>">
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Leave empty to draw every correlated event.'),
            ]) ?>
        </section>

        <?php foreach ([
            'iocs' => [__('Correlating IOCs'), __('Search a value or a type'), __('An unticked IOC leaves the graph and the list below, with every event it alone links to.')],
            'events' => [__('Correlated events'), __('Search a title, a date or an organisation'), __('An unticked event leaves the graph and the list below.')],
        ] as $kind => [$label, $placeholder, $hint]): ?>
            <section>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'correlation',
                    'label' => $label,
                    'badge' => ' ',
                ]) ?>
                <div class="d-flex gap-2 mb-2">
                    <input type="search" class="form-control form-control-sm" data-filter-search="<?= $kind ?>"
                           placeholder="<?= h($placeholder) ?>" aria-label="<?= h($placeholder) ?>">
                    <div class="btn-group btn-group-sm flex-shrink-0" role="group">
                        <button type="button" class="btn btn-outline-secondary" data-filter-all="<?= $kind ?>"
                                title="<?= h(__('Tick every row shown')) ?>"><?= h(__('All')) ?></button>
                        <button type="button" class="btn btn-outline-secondary" data-filter-none="<?= $kind ?>"
                                title="<?= h(__('Untick every row shown')) ?>"><?= h(__('None')) ?></button>
                    </div>
                </div>
                <div class="sankey-filter-list list-group overflow-auto" data-filter-list="<?= $kind ?>"></div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', ['text' => $hint]) ?>
            </section>
        <?php endforeach; ?>
    </div>
    <div class="border-top px-3 py-2 d-flex align-items-center gap-2">
        <span class="small text-body-secondary me-auto" id="sankey-filters-summary"></span>
        <button type="button" class="btn btn-sm btn-outline-secondary" id="sankey-filters-reset">
            <i class="fa-solid fa-rotate-left me-1"></i><?= h(__('Reset filters')) ?>
        </button>
    </div>
</div>

<script>
(function () {

    /* ── PHP data ──────────────────────────────────────────── */
    var eventId   = <?= json_encode($eventId) ?>;
    var baseurl   = <?= json_encode($baseurl ?? '') ?>;
    var eventInfo = <?= json_encode($eventInfo) ?>;
    var eventDate = <?= json_encode($eventDate) ?>;

    /* ── state ─────────────────────────────────────────────── */
    var _correlationData         = null;   // working set (warninglist filter applied)
    var _rawCorrelationData      = null;   // untouched API payload
    var _warninglistHits         = {};     // parent attribute id -> [warninglist name, ..]
    var _warninglistHitCount     = 0;
    var _correlationEventDetails = null;
    var _correlationsLoading     = false;
    var _currentEventDateTs      = eventDate ? Date.parse(eventDate + 'T00:00:00Z') : NaN;
    var _sankeyListenersReady    = false;
    var _dataMinTs = NaN, _dataMaxTs = NaN;    // first / last correlated event
    var _domainMinTs = NaN, _domainMaxTs = NaN; // same, snapped to month or year
    var _rangeMinTs  = NaN, _rangeMaxTs  = NaN; // period the graph draws
    var _rangeIsFull = true;
    var _targetMinTs = NaN, _targetMaxTs = NaN; // where a wheel glide is heading
    var _easeFrame   = null;
    var _easeLast    = 0;
    var _wheelArmed  = false;        // the pointer moved over the dates since the page last scrolled
    var _lastPointerScreen = null;
    var _lastPointerMoveTs = 0;
    var _graphZoomReady     = false;
    var _rescaleQueued      = false;
    var _graphUpdateTimer   = null;
    var _graphUpdatePending = false;
    var _pan = null;                 // drag-to-pan in progress
    var _suppressClick = false;      // a pan must not open the node it started on
    var _dateZone = null;            // the graph's date column, in svg pixels
    var updateTargetPositionsOnly = function () {};   // set inside renderSankey
    var rescaleDateLane = function () {};             // set inside renderSankey

    var DAY_MS   = 86400000;
    var MONTH_MS = 2629746000;
    var YEAR_MS  = 31556952000;
    var MIN_ZOOM_SPAN_MS = 7 * DAY_MS;

    /* ── helpers ───────────────────────────────────────────── */
    function formatTimelineDateUtc(ts) {
        var d   = new Date(ts);
        var y   = d.getUTCFullYear();
        var m   = String(d.getUTCMonth() + 1).padStart(2, '0');
        var day = String(d.getUTCDate()).padStart(2, '0');
        return y + '-' + m + '-' + day;
    }

    /* ── UTC date helpers ──────────────────────────────────── */
    function startOfUtcMonth(ts) {
        var d = new Date(ts);
        return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
    }
    function addUtcMonths(ts, n) {
        var d = new Date(ts);
        return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + n, 1);
    }
    function startOfUtcYear(ts) {
        var d = new Date(ts);
        return Date.UTC(d.getUTCFullYear(), 0, 1);
    }
    function addUtcYears(ts, n) {
        var d = new Date(ts);
        return Date.UTC(d.getUTCFullYear() + n, 0, 1);
    }
    function formatSankeyGridDate(ts, unit) {
        var d = new Date(ts);
        if (unit === 'year') return String(d.getUTCFullYear());
        if (unit === 'month') {
            return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0');
        }
        return formatTimelineDateUtc(ts);
    }

    /* room a label needs along the date lane */
    function _tickLabelWidth(unit) {
        return unit === 'year' ? 36 : (unit === 'month' ? 52 : 70);
    }

    function _pickTickStep(span, widthPx) {
        var steps = [
            ['day', 1], ['day', 2], ['day', 7], ['day', 14],
            ['month', 1], ['month', 2], ['month', 3], ['month', 6]
        ];
        for (var i = 0; i < steps.length; i++) {
            var unit = steps[i][0], n = steps[i][1];
            var room = Math.min(8, Math.floor(widthPx / _tickLabelWidth(unit)));
            var count = Math.floor(span / (n * (unit === 'day' ? DAY_MS : MONTH_MS))) + 1;
            if (count <= room) return {unit: unit, n: n};
        }
        var yearRoom = Math.max(1, Math.min(8, Math.floor(widthPx / _tickLabelWidth('year'))));
        var raw = span / YEAR_MS / yearRoom, years = 1;
        while (years < raw) {
            var lead = String(years).charAt(0);
            years *= lead === '2' ? 2.5 : 2;    // 1, 2, 5, 10, 20, 50...
        }
        return {unit: 'year', n: years};
    }

    function _tickTimes(minTs, maxTs, step) {
        var out = [], t;
        if (step.unit === 'day') {
            /* weekly steps fall on Mondays - day 0 of the epoch is a Thursday */
            var offset = step.n >= 7 ? 3 : 0;
            var k = Math.ceil(minTs / DAY_MS);
            while ((((k + offset) % step.n) + step.n) % step.n !== 0) k++;
            for (t = k * DAY_MS; t <= maxTs; t += step.n * DAY_MS) out.push(t);
        } else if (step.unit === 'month') {
            var d = new Date(minTs);
            var m = d.getUTCFullYear() * 12 + d.getUTCMonth();
            if (Date.UTC(Math.floor(m / 12), m % 12, 1) < minTs) m++;
            while (m % step.n !== 0) m++;
            for (; (t = Date.UTC(Math.floor(m / 12), m % 12, 1)) <= maxTs; m += step.n) out.push(t);
        } else {
            var y = new Date(minTs).getUTCFullYear();
            if (Date.UTC(y, 0, 1) < minTs) y++;
            y = Math.ceil(y / step.n) * step.n;
            for (; (t = Date.UTC(y, 0, 1)) <= maxTs; y += step.n) out.push(t);
        }
        return out;
    }

    /* the step follows the zoom, from days up to years */
    function buildSankeyGridTicks(minTs, maxTs, laneStart, laneEnd, widthPx) {
        var laneWidth = laneEnd - laneStart;
        if (!isFinite(minTs) || !isFinite(maxTs) || laneWidth <= 0) return [];
        if (maxTs <= minTs) return [{x: laneStart + laneWidth / 2, label: formatSankeyGridDate(minTs, 'day'), isEdge: true}];
        var step = _pickTickStep(maxTs - minTs, widthPx || laneWidth);
        return _tickTimes(minTs, maxTs, step).map(function (ts) {
            var ratio = (ts - minTs) / (maxTs - minTs);
            return {
                x: laneStart + laneWidth * ratio,
                label: formatSankeyGridDate(ts, step.unit),
                isEdge: ratio < 0.005 || ratio > 0.995
            };
        });
    }

    /* ── shared date domain ────────────────────────────────── */
    function _computeDateDomain(detailsMap) {
        var minTs = Infinity, maxTs = -Infinity;
        Object.keys(detailsMap || {}).forEach(function (eid) {
            var date = (detailsMap[eid] || {}).date || '';
            var ts   = date ? Date.parse(date + 'T00:00:00Z') : NaN;
            if (!isFinite(ts)) return;
            minTs = Math.min(minTs, ts);
            maxTs = Math.max(maxTs, ts);
        });
        _dataMinTs = isFinite(minTs) ? minTs : NaN;
        _dataMaxTs = isFinite(maxTs) ? maxTs : NaN;
        if (isFinite(_currentEventDateTs)) {
            minTs = Math.min(minTs, _currentEventDateTs);
            maxTs = Math.max(maxTs, _currentEventDateTs);
        }
        if (!isFinite(minTs) || !isFinite(maxTs)) {
            _domainMinTs = _domainMaxTs = NaN;
            _rangeMinTs  = _rangeMaxTs  = NaN;
            _targetMinTs = _targetMaxTs = NaN;
            _rangeIsFull = true;
            return;
        }
        var useYear = new Date(minTs).getUTCFullYear() !== new Date(maxTs).getUTCFullYear();
        _domainMinTs = useYear ? startOfUtcYear(minTs) : startOfUtcMonth(minTs);
        _domainMaxTs = useYear
            ? addUtcYears(startOfUtcYear(maxTs), 1)
            : addUtcMonths(startOfUtcMonth(maxTs), 1);
        /* a period the user zoomed to survives a re-render, clamped */
        if (_rangeIsFull || !isFinite(_rangeMinTs) || !isFinite(_rangeMaxTs)) {
            _rangeMinTs = _domainMinTs;
            _rangeMaxTs = _domainMaxTs;
        } else {
            var kept = _clampRange(_rangeMinTs, _rangeMaxTs);
            _rangeMinTs = kept[0];
            _rangeMaxTs = kept[1];
        }
        _rangeIsFull = _rangeMinTs <= _domainMinTs && _rangeMaxTs >= _domainMaxTs;
        _stopEasing();
        _targetMinTs = _rangeMinTs;
        _targetMaxTs = _rangeMaxTs;
    }

    /* ── zoom and pan ──────────────────────────────────────── */
    /* keeps the span, slides it back inside the domain */
    function _clampRange(lo, hi) {
        var span = Math.max(Math.min(MIN_ZOOM_SPAN_MS, _domainMaxTs - _domainMinTs), hi - lo);
        if (span >= _domainMaxTs - _domainMinTs) return [_domainMinTs, _domainMaxTs];
        if (lo < _domainMinTs) return [_domainMinTs, _domainMinTs + span];
        if (lo + span > _domainMaxTs) return [_domainMaxTs - span, _domainMaxTs];
        return [lo, lo + span];
    }

    function _showRange(lo, hi) {
        _rangeMinTs = lo;
        _rangeMaxTs = hi;
        _rangeIsFull = lo <= _domainMinTs && hi >= _domainMaxTs;
        _syncZoomBadge();
    }

    /* a drag follows the pointer exactly, so it skips the glide */
    function _setRange(lo, hi) {
        if (!(_domainMaxTs > _domainMinTs)) return;
        _hideExcludeButton(0);
        _stopEasing();
        var next = _clampRange(lo, hi);
        _targetMinTs = next[0];
        _targetMaxTs = next[1];
        if (next[0] === _rangeMinTs && next[1] === _rangeMaxTs) return;
        _showRange(next[0], next[1]);
        _queueRescale();
        _scheduleGraphUpdate();
    }

    /* the wheel moves a target, and the drawn period glides toward it */
    function _easeRangeTo(lo, hi) {
        if (!(_domainMaxTs > _domainMinTs)) return;
        _hideExcludeButton(0);
        var next = _clampRange(lo, hi);
        _targetMinTs = next[0];
        _targetMaxTs = next[1];
        _scheduleGraphUpdate();
        if (!_easeFrame) {
            _easeLast = 0;
            _easeFrame = requestAnimationFrame(_easeStep);
        }
    }

    function _easeStep(now) {
        var dt = _easeLast ? Math.min(48, now - _easeLast) : 16;
        _easeLast = now;
        var k  = 1 - Math.exp(-dt / 75);
        var lo = _rangeMinTs + (_targetMinTs - _rangeMinTs) * k;
        var hi = _rangeMaxTs + (_targetMaxTs - _rangeMaxTs) * k;
        /* under half a pixel of the lane left to travel */
        var done = Math.abs(_targetMinTs - lo) + Math.abs(_targetMaxTs - hi) < (hi - lo) * 0.002;
        if (done) {
            lo = _targetMinTs;
            hi = _targetMaxTs;
        }
        _showRange(lo, hi);
        rescaleDateLane();
        _easeFrame = done ? null : requestAnimationFrame(_easeStep);
    }

    function _stopEasing() {
        if (_easeFrame) cancelAnimationFrame(_easeFrame);
        _easeFrame = null;
    }

    /* the date under the cursor ends up under it again */
    function _zoomAround(ratio, factor) {
        var full = _domainMaxTs - _domainMinTs, span = _targetMaxTs - _targetMinTs;
        if (!(full > 0) || !(span > 0)) return;
        var next = Math.max(Math.min(MIN_ZOOM_SPAN_MS, full), Math.min(full, span * factor));
        if (next === span) return;
        var anchor = _rangeMinTs + ratio * (_rangeMaxTs - _rangeMinTs);
        _easeRangeTo(anchor - next * ratio, anchor - next * ratio + next);
    }

    /* a day the range label names is a day the graph draws */
    function _inRange(ts) {
        return ts >= Math.floor(_rangeMinTs / DAY_MS) * DAY_MS && ts <= _rangeMaxTs;
    }

    /* the sankey is expensive: the date column follows the gesture live,
       the full redraw (filtering, layout) waits until it settles */
    function _scheduleGraphUpdate() {
        _graphUpdatePending = true;
        clearTimeout(_graphUpdateTimer);
        if (_pan) return;   // the release redraws
        _graphUpdateTimer = setTimeout(_flushGraphUpdate, 250);
    }

    function _flushGraphUpdate() {
        clearTimeout(_graphUpdateTimer);
        _graphUpdateTimer = null;
        if (!_graphUpdatePending) return;
        /* the glide ends before the layout changes under it */
        if (_easeFrame) {
            _graphUpdateTimer = setTimeout(_flushGraphUpdate, 60);
            return;
        }
        _graphUpdatePending = false;
        _applyRangeToGraph();
    }

    function _queueRescale() {
        if (_rescaleQueued) return;
        _rescaleQueued = true;
        requestAnimationFrame(function () {
            _rescaleQueued = false;
            rescaleDateLane();
        });
    }

    function _applyRangeToGraph() {
        if (!_correlationData || !_correlationEventDetails) return;
        /* re-rendering drops any node filter, so retire its badge too */
        var badge = document.getElementById('sankey-filter-badge');
        if (badge) badge.classList.add('d-none');
        _resetCorrList();
        renderSankey(_correlationData, _correlationEventDetails, null, {morph: true});
    }

    function _resetZoom() {
        _easeRangeTo(_domainMinTs, _domainMaxTs);
    }

    function _syncZoomBadge() {
        var badge   = document.getElementById('sankey-zoom-badge');
        var label   = document.getElementById('sankey-zoom-label');
        var alignEl = document.getElementById('sankey-date-align');
        if (!badge || !label) return;
        var shown = !_rangeIsFull && isFinite(_rangeMinTs) && !!(alignEl && alignEl.checked);
        badge.classList.toggle('d-none', !shown);
        if (shown) {
            label.textContent = formatTimelineDateUtc(_rangeMinTs)
                + ' → ' + formatTimelineDateUtc(_rangeMaxTs);
        }
    }

    /* the date column - rotated labels down to the lane's bottom - takes the
       wheel; one listener on #sankey outlives every redraw */
    function _setupGraphZoom() {
        if (_graphZoomReady) return;
        var host = document.getElementById('sankey');
        if (!host) return;
        _graphZoomReady = true;

        /* where the pointer sits along the date lane (0..1), null outside it */
        function laneRatio(e) {
            var alignEl = document.getElementById('sankey-date-align');
            var svgEl   = host.querySelector('svg');
            if (!_dateZone || !svgEl || !alignEl || !alignEl.checked) return null;
            var r = svgEl.getBoundingClientRect();
            var x = e.clientX - r.left, y = e.clientY - r.top;
            if (x < _dateZone.x0 || x > _dateZone.x1 || y < 0 || y > _dateZone.y1) return null;
            return Math.max(0, Math.min(1,
                (x - _dateZone.laneX0) / (_dateZone.laneX1 - _dateZone.laneX0)));
        }
        /* a zoom into a gap leaves no axis - its message still backs out */
        function onEmptyPeriod(e) {
            return !!(e.target.closest && e.target.closest('.sankey-empty-period'));
        }
        function laneWidth() {
            return _dateZone ? _dateZone.laneX1 - _dateZone.laneX0 : host.clientWidth;
        }

        /* scrolling the page brings the dates under a still cursor: that wheel
           belongs to the page until the pointer really moves over them. A smooth
           scroll keeps firing after the wheel stops, so a fresh move outlives it. */
        window.addEventListener('scroll', function () {
            if (performance.now() - _lastPointerMoveTs > 250) _wheelArmed = false;
        }, {passive: true, capture: true});

        host.addEventListener('wheel', function (e) {
            if (!(_domainMaxTs > _domainMinTs)) return;
            var ratio = laneRatio(e);
            if (ratio === null) {
                if (!onEmptyPeriod(e)) return;
                ratio = 0.5;
            }
            /* ctrl is how a trackpad pinch arrives: always meant as a zoom */
            if (!_wheelArmed && !e.ctrlKey) return;
            /* mid page scroll the browser no longer lets the wheel be cancelled -
               zooming then would also scroll */
            if (!e.cancelable) return;
            e.preventDefault();
            var unit = e.deltaMode === 1 ? 33 : (e.deltaMode === 2 ? laneWidth() : 1);
            var dx = e.deltaX * unit, dy = e.deltaY * unit;
            if (e.shiftKey && !dx) { dx = dy; dy = 0; }
            if (Math.abs(dx) > Math.abs(dy)) {
                var shift = (dx / laneWidth()) * (_targetMaxTs - _targetMinTs);
                _easeRangeTo(_targetMinTs + shift, _targetMaxTs + shift);
                return;
            }
            var power = Math.max(-1, Math.min(1, dy * (e.ctrlKey ? 0.01 : 0.0025)));
            _zoomAround(ratio, Math.pow(2, power));
        }, {passive: false});

        /* a press only becomes a pan once it moves, so a node stays clickable */
        host.addEventListener('pointerdown', function (e) {
            if (e.button !== 0 || _rangeIsFull || laneRatio(e) === null) return;
            _pan = {
                id: e.pointerId, x: e.clientX, width: laneWidth(),
                min: _rangeMinTs, max: _rangeMaxTs, moved: false
            };
        });
        host.addEventListener('pointermove', function (e) {
            /* a scroll can replay a move at the same screen spot - that is no intent */
            var moved = !_lastPointerScreen
                || e.screenX !== _lastPointerScreen[0] || e.screenY !== _lastPointerScreen[1];
            _lastPointerScreen = [e.screenX, e.screenY];
            if (moved) _lastPointerMoveTs = performance.now();
            if (!_pan) {
                var overLane = laneRatio(e) !== null;
                if (moved && (overLane || onEmptyPeriod(e))) _wheelArmed = true;
                host.classList.toggle('is-pannable', !_rangeIsFull && overLane);
                return;
            }
            var dx = e.clientX - _pan.x;
            if (!_pan.moved) {
                if (Math.abs(dx) < 4) return;
                _pan.moved = true;
                host.setPointerCapture(_pan.id);
                host.classList.add('is-panning');
                var selection = window.getSelection && window.getSelection();
                if (selection) selection.removeAllRanges();
            }
            var shift = -(dx / _pan.width) * (_pan.max - _pan.min);
            _setRange(_pan.min + shift, _pan.max + shift);
        });
        function endPan() {
            if (!_pan) return;
            if (_pan.moved) {
                _suppressClick = true;
                setTimeout(function () { _suppressClick = false; }, 0);
            }
            _pan = null;
            host.classList.remove('is-panning');
            _flushGraphUpdate();
        }
        host.addEventListener('pointerup', endPan);
        host.addEventListener('pointercancel', endPan);
        host.addEventListener('click', function (e) {
            if (!_suppressClick) return;
            _suppressClick = false;
            e.stopPropagation();
            e.preventDefault();
        }, true);

        host.addEventListener('click', function (e) {
            if (e.target.closest && e.target.closest('[data-zoom-reset]')) _resetZoom();
        });
        var reset = document.getElementById('sankey-zoom-reset');
        if (reset) {
            reset.addEventListener('click', function (e) {
                e.preventDefault();
                _resetZoom();
            });
        }
    }

    /* ── fetch ─────────────────────────────────────────────── */
    function loadCorrelations() {
        if (_correlationData !== null || _correlationsLoading) return;
        _correlationsLoading = true;
        var loaderEl  = document.getElementById('correlations-loader');
        var contentEl = document.getElementById('correlations-content');
        var url = baseurl + '/correlations/eventCorrelations/' + eventId
                + '.json?include_attributes=1&include_org_names=1'
                + '&include_warninglist_hits=1';

        fetch(url)
            .then(function (r) {
                if (!r.ok) throw new Error(r.status);
                return r.json();
            })
            .then(function (data) {
                _correlationsLoading = false;
                if (loaderEl)  loaderEl.style.display  = 'none';
                if (contentEl) contentEl.style.display = '';
                renderCorrelations(data);
            })
            .catch(function () {
                _correlationsLoading = false;
                if (loaderEl) loaderEl.innerHTML =
                    '<p class="text-danger"><i class="fas fa-exclamation-triangle me-2"></i>'
                    + <?= json_encode(h(__('Failed to load correlations.'))) ?> + '</p>';
            });
    }

    /* ── warninglist filter ────────────────────────────────── */
    var _wlLabel      = <?= json_encode(h(__('Warninglist'))) ?>;
    var _wlHintOn     = <?= json_encode(h(__('Drop every correlating attribute that matches an enabled warninglist'))) ?>;
    var _wlHintNone   = <?= json_encode(h(__('No correlating attribute matches an enabled warninglist'))) ?>;
    var _wlHiddenOne  = <?= json_encode(__('%s warninglisted attribute hidden')) ?>;
    var _wlHiddenMany = <?= json_encode(__('%s warninglisted attributes hidden')) ?>;
    var _attrPillOne  = <?= json_encode(__('%s correlating attribute - click to expand')) ?>;
    var _attrPillMany = <?= json_encode(__('%s correlating attributes - click to expand')) ?>;

    function _isWarninglisted(parentId) {
        return !!(_warninglistHits && _warninglistHits[parentId]);
    }

    function _warninglistNames(parentId) {
        return (_warninglistHits[parentId] || []).join(', ');
    }

    function _hideWarninglisted() {
        var input = document.getElementById('sankey-hide-warninglist');
        return !!(input && input.checked && !input.disabled);
    }

    /* the toggle is dead weight when nothing in the graph is warninglisted */
    function _syncWarninglistToggle() {
        var input = document.getElementById('sankey-hide-warninglist');
        var label = document.getElementById('sankey-hide-warninglist-toggle');
        if (!input || !label) return;
        var hasHits = _warninglistHitCount > 0;
        input.disabled = !hasHits;
        if (!hasHits) input.checked = false;
        label.classList.toggle('opacity-50', !hasHits);
        label.title = hasHits ? _wlHintOn : _wlHintNone;
    }

    /* ── exclusions (the filters drawer and the graph's ×) ─── */
    var _excludedIocs   = {};    // parent attribute id -> true
    var _excludedEvents = {};    // event id -> true
    var _eventLimit     = 0;     // most recent events drawn, 0 for all
    var _filterIndex    = null;  // every IOC and event of the payload, with its row
    var _refilterTimer  = null;

    var _fltIocEvents   = <?= json_encode(__('Correlated events')) ?>;
    var _fltEventIocs   = <?= json_encode(__('Correlating IOCs')) ?>;
    var _fltByWl        = <?= json_encode(__('Hidden by the warninglist filter')) ?>;
    var _fltNoEventLeft = <?= json_encode(__('Every event it links to is excluded')) ?>;
    var _fltNoIocLeft   = <?= json_encode(__('Every IOC that links to it is excluded')) ?>;
    var _fltExclOne     = <?= json_encode(__('%s exclusion')) ?>;
    var _fltExclMany    = <?= json_encode(__('%s exclusions')) ?>;
    var _fltNone        = <?= json_encode(__('No IOC or event excluded')) ?>;

    function _countKeys(bag) { return Object.keys(bag).length; }

    function _activeFilterCount() {
        return _countKeys(_excludedIocs) + _countKeys(_excludedEvents)
            + (_eventLimit > 0 ? 1 : 0) + (_hideWarninglisted() ? 1 : 0);
    }

    function _filterRow(kind, id, search) {
        var row = document.createElement('label');
        row.className = 'list-group-item list-group-item-action d-flex gap-2 py-1 px-2 small '
            + (kind === 'events' ? 'align-items-start' : 'align-items-center');
        row.setAttribute('data-search', search.toLowerCase());
        var box = document.createElement('input');
        box.type = 'checkbox';
        box.className = 'form-check-input m-0 flex-shrink-0' + (kind === 'events' ? ' mt-1' : '');
        box.value = id;
        box.setAttribute('data-filter-item', kind);
        row.appendChild(box);
        return {row: row, box: box};
    }

    function _countBadge(n, title) {
        var badge = document.createElement('span');
        badge.className = 'badge rounded-pill text-bg-secondary flex-shrink-0';
        badge.textContent = n;
        badge.title = title;
        return badge;
    }

    /* built once per payload - a filter change only re-ticks the rows */
    function _buildFilterLists() {
        var iocs = {}, events = {};
        Object.keys(_rawCorrelationData || {}).forEach(function (pid) {
            var rels  = _rawCorrelationData[pid] || [];
            var first = rels[0] || {};
            var ioc   = iocs[pid] = {id: pid, value: first.value || pid, type: first.type || '', events: {}};
            rels.forEach(function (rel) {
                var eid = String(rel.id);
                ioc.events[eid] = true;
                var ev = events[eid] || (events[eid] = {
                    id: eid, info: rel.info || ('#' + eid), date: rel.date || '',
                    org: rel.org_name || '', iocs: {}
                });
                ev.iocs[pid] = true;
            });
        });

        var iocList = Object.keys(iocs).map(function (k) { return iocs[k]; });
        iocList.sort(function (a, b) {
            return _countKeys(b.events) - _countKeys(a.events)
                || String(a.value).localeCompare(String(b.value));
        });
        var eventList = Object.keys(events).map(function (k) { return events[k]; });
        eventList.sort(function (a, b) {
            return b.date.localeCompare(a.date) || a.info.localeCompare(b.info);
        });

        var iocBody = document.querySelector('[data-filter-list="iocs"]');
        if (iocBody) {
            iocBody.innerHTML = '';
            iocList.forEach(function (ioc) {
                var parts = _filterRow('iocs', ioc.id, ioc.value + ' ' + ioc.type);
                var value = document.createElement('span');
                value.className = 'text-truncate flex-fill';
                value.textContent = ioc.value;
                value.title = ioc.value;
                parts.row.appendChild(value);
                if (_isWarninglisted(ioc.id)) {
                    var wl = document.createElement('i');
                    wl.className = 'fa-solid fa-triangle-exclamation text-warning flex-shrink-0';
                    wl.title = _wlLabel + ': ' + _warninglistNames(ioc.id);
                    parts.row.appendChild(wl);
                }
                if (ioc.type) {
                    var type = document.createElement('span');
                    type.className = 'badge text-bg-light border fw-normal flex-shrink-0';
                    type.textContent = ioc.type;
                    parts.row.appendChild(type);
                }
                parts.row.appendChild(_countBadge(_countKeys(ioc.events), _fltIocEvents));
                ioc.row = parts.row;
                ioc.box = parts.box;
                iocBody.appendChild(parts.row);
            });
        }

        var eventBody = document.querySelector('[data-filter-list="events"]');
        if (eventBody) {
            eventBody.innerHTML = '';
            eventList.forEach(function (ev) {
                var parts = _filterRow('events', ev.id, ev.info + ' ' + ev.date + ' ' + ev.org);
                var text = document.createElement('span');
                text.className = 'flex-fill overflow-hidden';
                var title = document.createElement('span');
                title.className = 'd-block text-truncate';
                title.textContent = ev.info;
                title.title = ev.info;
                var meta = document.createElement('span');
                meta.className = 'd-block text-truncate text-body-secondary small';
                meta.textContent = [ev.date, ev.org].filter(Boolean).join(' · ');
                text.appendChild(title);
                text.appendChild(meta);
                parts.row.appendChild(text);
                parts.row.appendChild(_countBadge(_countKeys(ev.iocs), _fltEventIocs));
                ev.row = parts.row;
                ev.box = parts.box;
                eventBody.appendChild(parts.row);
            });
        }
        _filterIndex = {iocs: iocList, events: eventList};
    }

    /* ticks, greyed rows, counters and the toolbar badge follow the state */
    function _syncFilterUi() {
        if (!_filterIndex) return;
        var hideWl = _hideWarninglisted();
        var shownIocs = 0, shownEvents = 0;
        function wlHidden(pid) { return hideWl && _isWarninglisted(pid); }

        _filterIndex.iocs.forEach(function (ioc) {
            var excluded  = !!_excludedIocs[ioc.id];
            var byWl      = wlHidden(ioc.id);
            var reachable = Object.keys(ioc.events).some(function (eid) { return !_excludedEvents[eid]; });
            ioc.box.checked  = !excluded && !byWl;
            ioc.box.disabled = byWl;
            ioc.row.classList.toggle('opacity-50', byWl || (!excluded && !reachable));
            ioc.row.title = byWl ? _fltByWl : (!excluded && !reachable ? _fltNoEventLeft : '');
            if (!excluded && !byWl && reachable) shownIocs++;
        });
        _filterIndex.events.forEach(function (ev) {
            var excluded  = !!_excludedEvents[ev.id];
            var reachable = Object.keys(ev.iocs).some(function (pid) {
                return !_excludedIocs[pid] && !wlHidden(pid);
            });
            ev.box.checked = !excluded;
            ev.row.classList.toggle('opacity-50', !excluded && !reachable);
            ev.row.title = !excluded && !reachable ? _fltNoIocLeft : '';
            if (!excluded && reachable) shownEvents++;
        });

        [['iocs', shownIocs, _filterIndex.iocs.length], ['events', shownEvents, _filterIndex.events.length]]
            .forEach(function (c) {
                var list  = document.querySelector('[data-filter-list="' + c[0] + '"]');
                var badge = list && list.closest('section').querySelector('.badge');
                if (badge) badge.textContent = c[1] + ' / ' + c[2];
            });

        var active  = _activeFilterCount();
        var exclusions = _countKeys(_excludedIocs) + _countKeys(_excludedEvents);
        var countEl = document.getElementById('sankey-filters-count');
        if (countEl) {
            countEl.textContent = active;
            countEl.classList.toggle('d-none', active === 0);
        }
        var summary = document.getElementById('sankey-filters-summary');
        if (summary) {
            summary.textContent = exclusions === 0 ? _fltNone
                : (exclusions === 1 ? _fltExclOne : _fltExclMany).replace('%s', exclusions);
        }
        var reset = document.getElementById('sankey-filters-reset');
        if (reset) reset.disabled = active === 0;
    }

    /* a run of ticks redraws once */
    function _refilter(now) {
        var badge = document.getElementById('sankey-filter-badge');
        if (badge) badge.classList.add('d-none');
        _syncFilterUi();
        clearTimeout(_refilterTimer);
        _refilterTimer = setTimeout(function () {
            if (_rawCorrelationData) applyCorrelations({morph: true});
        }, now ? 0 : 150);
    }

    function _resetFilters() {
        _excludedIocs = {};
        _excludedEvents = {};
        _eventLimit = 0;
        var limit = document.getElementById('sankey-event-limit');
        if (limit) limit.value = '';
        var wl = document.getElementById('sankey-hide-warninglist');
        if (wl) wl.checked = false;
        _refilter(true);
    }

    /* ── the × a hovered IOC or event offers ───────────────── */
    var _excludeTarget = null;
    var _excludeHideTimer = null;

    function _showExcludeButton(d, labelEl) {
        var btn   = document.getElementById('sankey-exclude-btn');
        var shell = document.getElementById('sankey-shell');
        if (!btn || !shell || !labelEl || _pan || _easeFrame) return;
        clearTimeout(_excludeHideTimer);
        var s = shell.getBoundingClientRect(), r = labelEl.getBoundingClientRect();
        var size = btn.offsetWidth || 20;
        /* past the end of the label the pointer is already on */
        var left = d.type === 'attribute' ? r.left - s.left - size - 4 : r.right - s.left + 4;
        btn.style.left = Math.round(left) + 'px';
        btn.style.top  = Math.round(r.top - s.top + (r.height - size) / 2) + 'px';
        _excludeTarget = {type: d.type, id: String(d.id)};
        btn.classList.remove('d-none');
    }

    function _hideExcludeButton(delay) {
        clearTimeout(_excludeHideTimer);
        var hide = function () {
            var btn = document.getElementById('sankey-exclude-btn');
            if (btn) btn.classList.add('d-none');
        };
        if (delay) _excludeHideTimer = setTimeout(hide, delay);
        else hide();
    }

    function _excludeHovered() {
        if (!_excludeTarget) return;
        if (_excludeTarget.type === 'attribute') _excludedIocs[_excludeTarget.id] = true;
        else _excludedEvents[_excludeTarget.id] = true;
        _excludeTarget = null;
        _hideExcludeButton(0);
        _refilter(true);
    }

    /* ── empty states ──────────────────────────────────────── */
    /* reason: 'filters', 'warninglist', or nothing when there is no correlation */
    function _showEmptyState(reason) {
        var stageEl   = document.getElementById('sankey-stage');
        var toolbarEl = document.getElementById('sankey-toolbar');
        var emptyEl   = document.getElementById('sankey-empty');
        var graphEl   = document.getElementById('sankey');
        var listEl    = document.getElementById('correlations-list');
        var zoomEl    = document.getElementById('sankey-zoom-badge');

        if (stageEl)  stageEl.style.display  = '';
        _dateZone = null;
        _hideExcludeButton(0);
        if (zoomEl)   zoomEl.classList.add('d-none');
        if (listEl)   listEl.style.display   = 'none';
        if (graphEl) {
            graphEl.innerHTML     = '';
            graphEl.style.height  = '0px';
            graphEl.style.opacity = '1';
        }
        /* renderSankey() never ran, so its counter still describes the old set */
        var limitMsgEl = document.getElementById('sankey-limit-msg');
        if (limitMsgEl) limitMsgEl.textContent = '';
        /* keep the toolbar reachable when a filter is what emptied the graph */
        if (toolbarEl) toolbarEl.classList.toggle('d-none', !reason);
        if (emptyEl) {
            emptyEl.classList.remove('d-none');
            emptyEl.innerHTML =
                '<i class="fas fa-' + (reason ? 'filter' : 'link')
                + ' fa-2x mb-2 d-block mx-auto opacity-50"></i>'
                + (reason === 'filters'
                    ? <?= json_encode(h(__('Everything is filtered out.'))) ?>
                      + '<div class="mt-2"><button type="button" data-filters-reset'
                      + ' class="btn btn-sm btn-outline-secondary">'
                      + <?= json_encode(h(__('Reset filters'))) ?> + '</button></div>'
                    : reason === 'warninglist'
                        ? <?= json_encode(h(__('Every correlating attribute is warninglisted.'))) ?>
                        : <?= json_encode(h(__('No correlated events found.'))) ?>);
        }
    }

    /* d-none, not style.display - .d-flex is an !important utility */
    function _hideEmptyState() {
        var toolbarEl = document.getElementById('sankey-toolbar');
        var emptyEl   = document.getElementById('sankey-empty');
        if (emptyEl)   emptyEl.classList.add('d-none');
        if (toolbarEl) toolbarEl.classList.remove('d-none');
    }

    /* ── process API response ──────────────────────────────── */
    function renderCorrelations(payload) {
        _rawCorrelationData = (payload && payload.correlations !== undefined)
            ? (payload.correlations || {})
            : (payload || {});
        _warninglistHits     = (payload && payload.warninglist_hits) || {};
        _warninglistHitCount = Object.keys(_warninglistHits).length;
        _syncWarninglistToggle();
        _buildFilterLists();
        _syncFilterUi();
        _registerToggleListeners();
        _setupGraphZoom();
        applyCorrelations({});
    }

    /* ── build the working set, then (re)draw ──────────────── */
    function applyCorrelations(options) {
        options = options || {};
        var hideWl = _hideWarninglisted();
        var data   = {};
        var hidden = 0;
        for (var rawPid in _rawCorrelationData) {
            if (!Object.prototype.hasOwnProperty.call(_rawCorrelationData, rawPid)) continue;
            if (hideWl && _isWarninglisted(rawPid)) { hidden++; continue; }
            if (_excludedIocs[rawPid]) continue;
            var kept = (_rawCorrelationData[rawPid] || []).filter(function (rel) {
                return !_excludedEvents[rel.id];
            });
            if (kept.length) data[rawPid] = kept;
        }
        _correlationData = data;

        var wlMsgEl = document.getElementById('sankey-wl-msg');
        if (wlMsgEl) {
            wlMsgEl.textContent = hidden > 0
                ? (hidden === 1 ? _wlHiddenOne : _wlHiddenMany).replace('%s', hidden)
                : '';
        }

        var eventDetails  = {};
        var eventCounts   = {};
        var attributeMap  = {};

        for (var parentId in data) {
            (data[parentId] || []).forEach(function (rel) {
                var eid = rel.id;
                if (!eventDetails[eid]) {
                    var distRaw = rel.Attribute && rel.Attribute.distribution !== undefined
                        ? parseInt(rel.Attribute.distribution, 10) : -1;
                    eventDetails[eid] = {
                        info:         rel.info,
                        date:         rel.date,
                        org:          rel.org_id,
                        orgName:      rel.org_name || '',
                        distribution: rel.distribution
                    };
                    eventCounts[eid] = 0;
                } else if (eventDetails[eid].distribution === -1
                           && rel.Attribute && rel.Attribute.distribution !== undefined) {
                    eventDetails[eid].distribution =
                        parseInt(rel.Attribute.distribution, 10);
                }
                eventCounts[eid]++;
                if (!attributeMap[eid]) attributeMap[eid] = [];
                var attrCategory = rel.category
                    || (rel.Attribute ? rel.Attribute.category : '') || '';
                attributeMap[eid].push({
                    id:       parentId,
                    value:    rel.value || parentId,
                    type:     rel.type  || '',
                    category: attrCategory,
                    attribute: rel.Attribute || null
                });
            });
        }
        _correlationEventDetails = eventDetails;

        /* the header keeps the whole payload's count, the filters say what is drawn */
        var total    = Object.keys(eventDetails).length;
        var allTotal = _filterIndex ? _filterIndex.events.length : total;
        var countEl  = document.getElementById('sankey-count');
        if (countEl) {
            countEl.textContent = allTotal === 0
                ? <?= json_encode(h(__('No correlations'))) ?>
                : allTotal + ' ' + (allTotal === 1
                    ? <?= json_encode(h(__('related event'))) ?>
                    : <?= json_encode(h(__('related events'))) ?>);
        }

        if (total === 0) {
            var excluded = _countKeys(_excludedIocs) + _countKeys(_excludedEvents) > 0;
            _showEmptyState(excluded ? 'filters' : (hidden > 0 ? 'warninglist' : null));
            return;
        }
        _hideEmptyState();

        _computeDateDomain(eventDetails);
        _syncZoomBadge();
        renderSankey(data, eventDetails, null,
            options.morph ? {morph: true} : (options.animateToggle ? {animateToggle: true} : {}));
        renderCorrelationsList(eventDetails, eventCounts, attributeMap);
    }

    /* ── events list with correlating attributes ──────────── */
    var _distMap = <?= json_encode(array_map(function ($meta) {
        $meta['label'] = h($meta['label']);
        return $meta;
    }, $this->DistributionLevel->all()), JSON_FORCE_OBJECT) ?>;
    var _distFallback = {bg:'#f1f5f9', color:'#64748b', icon:'fas fa-link', label:''};

    function renderCorrelationsList(eventDetails, eventCounts, attributeMap) {
        var listEl = document.getElementById('correlations-list');
        var bodyEl = document.getElementById('correlations-list-body');
        if (!listEl || !bodyEl) return;

        var sortedEids = Object.keys(eventCounts).sort(function (a, b) {
            return eventCounts[b] - eventCounts[a];
        });

        bodyEl.innerHTML = '';

        sortedEids.forEach(function (eid) {
            var det     = eventDetails[eid] || {};
            var attrs   = attributeMap[eid] || [];
            var info    = det.info    || ('#' + eid);
            var date    = det.date    || '';
            var orgName = det.orgName || '';
            var distId  = det.distribution;
            var dist    = (_distMap[distId] !== undefined)
                ? _distMap[distId] : _distFallback;

            /* collect unique parent IDs for DOM-based filtering */
            var allParentIds = attrs.map(function (a) { return a.id; });
            var uniqueParentIds = allParentIds.filter(
                function (v, i) { return allParentIds.indexOf(v) === i; }
            );

            /* deduplicate attribute entries */
            var seenValues = {};
            var uniqueAttrs = attrs.filter(function (a) {
                var key = a.type + ':' + a.value;
                if (seenValues[key]) return false;
                seenValues[key] = true;
                return true;
            });

            /* card wrapper */
            var card = document.createElement('div');
            card.className = 'corr-event-card border-bottom';
            card.setAttribute('data-attr-parent-ids',
                uniqueParentIds.join(','));

            /* distribution badge */
            var distBadge = document.createElement('div');
            distBadge.className =
                'rounded-2 d-flex align-items-center justify-content-center'
                + ' flex-shrink-0 mt-1';
            distBadge.style.cssText = 'width:34px;height:34px;'
                + 'background:' + dist.bg + ';'
                + 'border:1px solid ' + dist.color + '33;';
            if (dist.label) distBadge.title = dist.label;
            distBadge.innerHTML = '<i class="' + dist.icon
                + '" style="color:' + dist.color + ';font-size:.85rem;"></i>';

            /* header row - the link no longer spans it, the pill is a button */
            var header = document.createElement('div');
            header.className =
                'd-flex align-items-start gap-3 px-3 py-2 corr-event-row';

            var link = document.createElement('a');
            link.href = baseurl + '/events/view2/' + eid;
            link.className =
                'd-flex align-items-start gap-3 flex-fill overflow-hidden'
                + ' text-decoration-none text-dark';

            var meta = document.createElement('div');
            meta.className = 'flex-fill overflow-hidden';
            meta.innerHTML =
                '<div class="fw-semibold text-truncate small lh-sm">'
                + escapeHtml(info) + '</div>'
                + '<div class="d-flex align-items-center gap-2 mt-1 flex-wrap">'
                + (orgName
                    ? '<span class="text-muted" style="font-size:.75rem;">'
                      + escapeHtml(orgName)
                      + '</span><span class="text-muted" style="font-size:.75rem;">·</span>'
                    : '')
                + (date
                    ? '<time class="text-muted" style="font-size:.75rem;">'
                      + escapeHtml(date) + '</time>'
                    : '')
                + '</div>';

            link.appendChild(distBadge);
            link.appendChild(meta);

            /* attributes — index format: italic category > bordered type value */
            var attrsEl = document.createElement('div');
            attrsEl.id = 'corr-attrs-' + eid;
            attrsEl.className =
                'corr-event-attrs d-none px-3 pb-2 pt-1 d-flex flex-column gap-1';

            uniqueAttrs.forEach(function (a) {
                var row = document.createElement('div');
                row.className = 'd-flex align-items-center gap-1 flex-wrap corr-attr-row';
                row.setAttribute('data-parent-id', a.id);

                if (a.category) {
                    var catEl = document.createElement('p');
                    catEl.className = 'fst-italic text-muted mb-0';
                    catEl.style.fontSize = '.75rem';
                    catEl.textContent = a.category;
                    var chevron = document.createElement('i');
                    chevron.className = 'fa-solid fa-chevron-right ms-1';
                    chevron.style.fontSize = '.65rem';
                    catEl.appendChild(chevron);
                    row.appendChild(catEl);
                }

                if (a.type) {
                    var typeEl = document.createElement('p');
                    typeEl.className = 'border border-dark rounded px-1 mb-0';
                    typeEl.style.fontSize = '.75rem';
                    typeEl.textContent = a.type;
                    row.appendChild(typeEl);
                }

                var valEl = document.createElement('span');
                valEl.className = 'small corr-attr-value';
                valEl.textContent = a.value;
                row.appendChild(valEl);

                if (_isWarninglisted(a.id)) {
                    var wlIcon = document.createElement('i');
                    wlIcon.className =
                        'fa-solid fa-triangle-exclamation text-warning ms-1';
                    wlIcon.style.fontSize = '.7rem';
                    wlIcon.title = _wlLabel + ': ' + _warninglistNames(a.id);
                    row.appendChild(wlIcon);
                }

                attrsEl.appendChild(row);
            });

            var shown      = uniqueAttrs.length;
            var anyWarned   = uniqueAttrs.some(function (a) {
                return _isWarninglisted(a.id);
            });
            var toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'corr-attr-toggle flex-shrink-0 mt-1';
            toggle.setAttribute('aria-expanded', 'false');
            toggle.setAttribute('aria-controls', attrsEl.id);
            toggle.title = (shown === 1 ? _attrPillOne : _attrPillMany)
                .replace('%s', shown);
            toggle.innerHTML = (anyWarned
                    ? '<i class="fa-solid fa-triangle-exclamation'
                      + ' corr-attr-toggle-warning"></i>'
                    : '')
                + '<span>' + shown + '</span>'
                + '<i class="fa-solid fa-chevron-down corr-attr-toggle-chevron"></i>';

            header.appendChild(link);
            header.appendChild(toggle);
            card.appendChild(header);
            card.appendChild(attrsEl);
            bodyEl.appendChild(card);
        });

        _delegateCorrListToggle(bodyEl);
        listEl.style.display = '';
    }

    /* ── expand / collapse a card's attribute list ──────────── */
    var _corrListDelegated = false;

    function _setCardExpanded(card, expanded) {
        if (!card) return;
        var btn   = card.querySelector('.corr-attr-toggle');
        var attrs = card.querySelector('.corr-event-attrs');
        if (!btn || !attrs) return;
        attrs.classList.toggle('d-none', !expanded);
        btn.classList.toggle('is-expanded', expanded);
        btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    }

    /* one listener on the body, which survives every re-render */
    function _delegateCorrListToggle(bodyEl) {
        if (_corrListDelegated || !bodyEl) return;
        _corrListDelegated = true;
        bodyEl.addEventListener('click', function (e) {
            var btn = e.target.closest('.corr-attr-toggle');
            if (!btn) return;
            e.preventDefault();
            _setCardExpanded(
                btn.closest('.corr-event-card'),
                btn.getAttribute('aria-expanded') !== 'true'
            );
        });
    }

    /* ── list filter helpers ───────────────────────────────── */
    function _filterCorrList(attrId) {
        var bodyEl = document.getElementById('correlations-list-body');
        if (!bodyEl) return;
        var attrStr = String(attrId);
        bodyEl.querySelectorAll('.corr-event-card').forEach(function (card) {
            var ids = (card.getAttribute('data-attr-parent-ids') || '').split(',');
            if (ids.indexOf(attrStr) !== -1) {
                card.style.display = '';
                card.querySelectorAll('.corr-attr-row').forEach(function (row) {
                    row.style.opacity =
                        row.getAttribute('data-parent-id') === attrStr ? '1' : '0.25';
                });
                /* the highlight is worthless while the list is collapsed */
                _setCardExpanded(card, true);
            } else {
                card.style.display = 'none';
            }
        });
    }

    function _resetCorrList() {
        var bodyEl = document.getElementById('correlations-list-body');
        if (!bodyEl) return;
        bodyEl.querySelectorAll('.corr-event-card').forEach(function (card) {
            card.style.display = '';
            card.querySelectorAll('.corr-attr-row').forEach(function (row) {
                row.style.opacity = '';
            });
            _setCardExpanded(card, false);
        });
    }

    function escapeHtml(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /* ── filter and display listeners (once) ───────────────── */
    function _registerToggleListeners() {
        if (_sankeyListenersReady) return;
        _sankeyListenersReady = true;

        function redraw() {
            if (_correlationData && _correlationEventDetails) {
                renderSankey(_correlationData, _correlationEventDetails, null, {morph: true});
            }
        }

        document.getElementById('sankey-date-align').addEventListener('change', function () {
            _syncZoomBadge();
            /* the period filter follows the axis, and a graph drawn without
               the axis has no date column to slide into */
            if (!_rangeIsFull || (this.checked && !_dateZone)) {
                redraw();
                return;
            }
            updateTargetPositionsOnly(true);
        });
        document.getElementById('sankey-show-publisher').addEventListener('change', redraw);
        document.getElementById('sankey-hide-warninglist').addEventListener('change', function () {
            if (_rawCorrelationData) _refilter(true);
        });

        var limitTimer = null;
        document.getElementById('sankey-event-limit').addEventListener('input', function () {
            var value = parseInt(this.value, 10);
            clearTimeout(limitTimer);
            limitTimer = setTimeout(function () {
                var next = value > 0 ? value : 0;
                if (next === _eventLimit) return;
                _eventLimit = next;
                _syncFilterUi();
                redraw();
            }, 300);
        });

        var drawer = document.getElementById('sankey-filters');
        drawer.addEventListener('change', function (e) {
            var box = e.target.closest('[data-filter-item]');
            if (!box) return;
            var bag = box.getAttribute('data-filter-item') === 'iocs' ? _excludedIocs : _excludedEvents;
            if (box.checked) delete bag[box.value];
            else bag[box.value] = true;
            _refilter();
        });
        drawer.addEventListener('input', function (e) {
            var kind = e.target.getAttribute('data-filter-search');
            if (!kind) return;
            var needle = e.target.value.trim().toLowerCase();
            document.querySelectorAll('[data-filter-list="' + kind + '"] > [data-search]').forEach(function (row) {
                row.classList.toggle('d-none', needle !== '' && row.getAttribute('data-search').indexOf(needle) === -1);
            });
        });
        /* All / None act on the rows the search leaves visible */
        drawer.addEventListener('click', function (e) {
            var all  = e.target.closest('[data-filter-all]');
            var none = e.target.closest('[data-filter-none]');
            if (!all && !none) return;
            var kind = (all || none).getAttribute(all ? 'data-filter-all' : 'data-filter-none');
            var bag  = kind === 'iocs' ? _excludedIocs : _excludedEvents;
            document.querySelectorAll('[data-filter-list="' + kind + '"] > [data-search]:not(.d-none) [data-filter-item]')
                .forEach(function (box) {
                    if (box.disabled) return;
                    if (all) delete bag[box.value];
                    else bag[box.value] = true;
                });
            _refilter(true);
        });
        document.getElementById('sankey-filters-reset').addEventListener('click', _resetFilters);
        document.getElementById('sankey-empty').addEventListener('click', function (e) {
            if (e.target.closest('[data-filters-reset]')) _resetFilters();
        });

        var excludeBtn = document.getElementById('sankey-exclude-btn');
        excludeBtn.addEventListener('mouseenter', function () { clearTimeout(_excludeHideTimer); });
        excludeBtn.addEventListener('mouseleave', function () { _hideExcludeButton(220); });
        excludeBtn.addEventListener('click', _excludeHovered);
    }

    /* ── renderSankey ──────────────────────────────────────── */
    function renderSankey(data, eventDetails, filterAttributeId, options) {
        options = options || {};
        var nodes   = [];
        var links   = [];
        var nodeMap = {};
        var orgNodeByTargetEventId = {};
        var filterOrgId = options.filterOrgId || null;

        var alignToDate      = document.getElementById('sankey-date-align').checked;
        var latestEventsOnly = _eventLimit > 0;
        var showPublisher    = document.getElementById('sankey-show-publisher').checked;
        var latestEventsLimit = _eventLimit;

        var currentEventName      = eventInfo || ('Event #' + eventId);
        var currentEventFullTitle = 'Event #' + eventId;
        if (eventDate) currentEventFullTitle += ' (' + eventDate + ')';
        if (eventInfo) currentEventFullTitle += ': ' + eventInfo;

        var sankeyEl      = document.getElementById('sankey');
        var sankeyStageEl = document.getElementById('sankey-stage');

        function addNode(name, type, id, fullTitle) {
            var key = name + '_' + type;
            if (nodeMap[key] === undefined) {
                nodeMap[key] = nodes.length;
                nodes.push({name: name, type: type, id: id, fullTitle: fullTitle});
            }
            return nodeMap[key];
        }

        var sourceIdx = addNode(currentEventName, 'source', eventId, currentEventFullTitle);

        /* a zoom on the date lane restricts which period the graph draws */
        var rangeActive = alignToDate && isFinite(_rangeMinTs)
            && isFinite(_rangeMaxTs) && !_rangeIsFull;
        function relInRange(rel) {
            if (!rangeActive) return true;
            var det = eventDetails && eventDetails[rel.id] ? eventDetails[rel.id] : null;
            var evDate = rel.date || (det && det.date) || '';
            var ts = evDate ? Date.parse(evDate + 'T00:00:00Z') : NaN;
            if (!isFinite(ts)) return true;   // undated events stay visible
            return _inRange(ts);
        }

        var parentIds;
        if (filterAttributeId) {
            parentIds = Object.keys(data).filter(function (id) { return id == filterAttributeId; });
        } else {
            /* rank within the period, so zooming in can reach what the cap hides */
            var drawable = {};
            Object.keys(data).forEach(function (pid) {
                drawable[pid] = (data[pid] || []).filter(relInRange).length;
            });
            parentIds = Object.keys(drawable)
                .filter(function (pid) { return drawable[pid] > 0; })
                .sort(function (a, b) { return drawable[b] - drawable[a]; })
                .slice(0, 100);
        }

        var allowedTargetEventIds = null;
        if (latestEventsOnly) {
            var latestTargetEvents = [];
            var seen = {};
            parentIds.forEach(function (pid) {
                (data[pid] || []).forEach(function (rel) {
                    if (seen[rel.id]) return;
                    if (!relInRange(rel)) return;
                    seen[rel.id] = true;
                    var det = eventDetails && eventDetails[rel.id] ? eventDetails[rel.id] : null;
                    var evDate = rel.date || (det && det.date) || '';
                    var ts    = evDate ? Date.parse(evDate + 'T00:00:00Z') : NaN;
                    latestTargetEvents.push({id: String(rel.id), dateTs: isFinite(ts) ? ts : -Infinity});
                });
            });
            latestTargetEvents.sort(function (a, b) {
                if (b.dateTs !== a.dateTs) return b.dateTs - a.dateTs;
                return String(b.id).localeCompare(String(a.id), undefined, {numeric: true});
            });
            allowedTargetEventIds = {};
            latestTargetEvents.slice(0, latestEventsLimit).forEach(function (item) {
                allowedTargetEventIds[item.id] = true;
            });
        }

        var eventLinkCounts = {};
        if (eventDetails) {
            for (var eid0 in eventDetails) eventLinkCounts[eid0] = 0;
        }
        parentIds.forEach(function (pid) {
            (data[pid] || []).forEach(function (rel) {
                if (allowedTargetEventIds && !allowedTargetEventIds[String(rel.id)]) return;
                if (!relInRange(rel)) return;
                eventLinkCounts[rel.id] = (eventLinkCounts[rel.id] || 0) + 1;
            });
        });

        parentIds.forEach(function (pid) {
            var relations = data[pid] || [];
            var filtered  = relations.filter(function (rel) {
                if (allowedTargetEventIds && !allowedTargetEventIds[String(rel.id)]) return false;
                if (!relInRange(rel)) return false;
                if (filterOrgId) {
                    var relOrgId = rel.org_id || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].org) || 'unknown';
                    return String(relOrgId) === String(filterOrgId);
                }
                return true;
            });
            if (!filtered.length) return;

            var attrValue = (relations[0] && relations[0].value) ? relations[0].value : ('Attr #' + pid);
            var attrLabel = attrValue;
            var attrTitle = attrValue;
            if (_isWarninglisted(pid)) {
                attrLabel = '\u26a0 ' + attrValue;
                attrTitle = attrValue + ' | ' + _wlLabel + ': ' + _warninglistNames(pid);
            }
            var attrIdx   = addNode(attrLabel, 'attribute', pid, attrTitle);
            links.push({source: sourceIdx, target: attrIdx, value: filtered.length});

            filtered.forEach(function (rel) {
                var count   = eventLinkCounts[rel.id] || 1;
                var rawName = rel.info || ('#' + rel.id);
                var short   = rawName.length > 56 ? rawName.substring(0, 53) + '...' : rawName;
                var tgtName = count > 1 ? '(' + count + ') ' + short : short;
                var relDate = rel.date || '';
                var relOrg  = rel.org_name || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].orgName) || <?= json_encode(h(__('Unknown source'))) ?>;
                var full    = count > 1 ? '(' + count + ') ' + rawName : rawName;
                if (relDate) full += ' (' + relDate + ')';
                if (relOrg)  full += ' | ' + <?= json_encode(h(__('Publisher'))) ?> + ': ' + relOrg;
                var tgtIdx  = addNode(tgtName, 'target', rel.id, full);
                if (showPublisher && orgNodeByTargetEventId[rel.id] === undefined) {
                    var relOrgId = rel.org_id || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].org) || 'unknown';
                    orgNodeByTargetEventId[rel.id] = addNode(relOrg, 'org', relOrgId, relOrg);
                }
                links.push({source: attrIdx, target: tgtIdx, value: 1});
            });
        });

        if (showPublisher) {
            Object.keys(orgNodeByTargetEventId).forEach(function (evtId) {
                var orgIdx = orgNodeByTargetEventId[evtId];
                var tgtIdx = null;
                for (var i = 0; i < nodes.length; i++) {
                    if (nodes[i].type === 'target' && String(nodes[i].id) === String(evtId)) {
                        tgtIdx = i; break;
                    }
                }
                if (tgtIdx !== null && orgIdx !== undefined) {
                    links.push({source: tgtIdx, target: orgIdx, value: 1});
                }
            });
        }

        var displayedEventsIds = {};
        links.forEach(function (l) {
            if (nodes[l.target] && nodes[l.target].type === 'target') {
                displayedEventsIds[nodes[l.target].id] = true;
            }
        });
        var totalDisplayed = Object.keys(displayedEventsIds).length;
        var totalPossible  = Object.keys(eventDetails || {}).length;

        var limitMsgEl = document.getElementById('sankey-limit-msg');
        if (limitMsgEl) {
            limitMsgEl.textContent = totalPossible > totalDisplayed
                ? <?= json_encode(__('Showing top %s of %s correlating events')) ?>.replace('%s', totalDisplayed).replace('%s', totalPossible)
                : <?= json_encode(__('Showing %s correlating events')) ?>.replace('%s', totalDisplayed);
        }

        if (links.length === 0) {
            /* a zoom into a gap: no axis is left, so the message takes the wheel */
            _dateZone = null;
            rescaleDateLane = updateTargetPositionsOnly = function () {};
            if (sankeyEl) {
                sankeyEl.style.height  = '';
                sankeyEl.style.opacity = '1';
                sankeyEl.innerHTML = rangeActive
                    ? '<div class="sankey-empty-period text-center text-muted small py-4">'
                      + '<i class="fa-solid fa-calendar-xmark fa-2x mb-2 d-block mx-auto opacity-50"></i>'
                      + <?= json_encode(h(__('No correlated event in this period.'))) ?>
                      + '<div class="mt-2"><button type="button" data-zoom-reset'
                      + ' class="btn btn-sm btn-outline-primary">'
                      + <?= json_encode(h(__('Show the whole period'))) ?>
                      + '</button></div></div>'
                    : '<div class="text-center text-muted small py-4">'
                      + <?= json_encode(h(__('No correlated events found.'))) ?> + '</div>';
            }
            return;
        }
        if (sankeyStageEl) sankeyStageEl.style.display = '';

        /* ── layout helpers (hoisted) ─────────────────────── */
        function truncateSourceLabel(name) {
            return name.length > 30 ? name.substring(0, 30) + '...' : name;
        }
        function estimateLabelWidth(chars, charW, minW, maxW) {
            return Math.max(minW, Math.min(maxW, chars * charW));
        }

        /* ── sizing ───────────────────────────────────────── */
        var displayedAttrCount   = nodes.filter(function (n) { return n.type === 'attribute'; }).length;
        var displayedTargetCount = nodes.filter(function (n) { return n.type === 'target'; }).length;
        var estimatedRows = Math.max(displayedAttrCount, displayedTargetCount);
        var height = Math.max(280, Math.min(1800, 110 + (estimatedRows * 22)));

        /* set before the width is read: the page scrollbar it may bring takes from that width */
        if (sankeyEl) {
            sankeyEl.style.height  = height + 'px';
            sankeyEl.style.opacity = options.animateToggle ? '0.18' : '1';
        }

        var viewportWidth   = window.innerWidth || 0;
        var stageWidth      = Math.max(
            sankeyStageEl ? sankeyStageEl.clientWidth : 0,
            sankeyEl      ? sankeyEl.offsetWidth      : 0
        );
        var stageRect       = sankeyStageEl ? sankeyStageEl.getBoundingClientRect() : null;
        var viewportPadding = stageRect ? Math.max(stageRect.left || 0, viewportWidth - (stageRect.right || viewportWidth), 12) : 12;
        var containerWidth  = Math.max(720, Math.min(stageWidth || viewportWidth, viewportWidth - (viewportPadding * 2)));

        var longestTargetLen = 0, longestOrgLen = 0;
        nodes.forEach(function (n) {
            if (n.type === 'target') longestTargetLen = Math.max(longestTargetLen, (n.name || '').length);
            else if (n.type === 'org') longestOrgLen  = Math.max(longestOrgLen,  (n.name || '').length);
        });
        var srcLabelBudget   = estimateLabelWidth(('★ ' + truncateSourceLabel(currentEventName)).length, 6.2, 150, 260);
        var rightLabelBudget = estimateLabelWidth(longestOrgLen + 6, 6.1, showPublisher ? 96 : 36, showPublisher ? 220 : 72);
        var avail            = Math.max(0, containerWidth - 420);
        var compRatio        = (srcLabelBudget + rightLabelBudget) > 0 ? Math.min(1, avail / (srcLabelBudget + rightLabelBudget)) : 1;
        var margin = {
            top:    88,
            right:  Math.max(showPublisher ? 96 : 32, Math.floor(rightLabelBudget * compRatio)),
            bottom: 20,
            left:   Math.max(120, Math.floor(srcLabelBudget * compRatio))
        };
        var width = Math.max(640, containerWidth - margin.left - margin.right);

        height = height - margin.top - margin.bottom;

        /* nodes and links are matched across redraws by what they stand for */
        function layoutKey(d) { return d.type + ':' + d.id; }
        function capturePreviousLayout() {
            var old = sankeyEl && sankeyEl.querySelector('svg');
            var inner = old && old.querySelector('g');
            if (!inner) return null;
            var offset = /translate\(([-\d.e]+)[ ,]+([-\d.e]+)\)/.exec(inner.getAttribute('transform') || '');
            var prev = {
                ox: offset ? +offset[1] : margin.left, oy: offset ? +offset[2] : margin.top,
                nodes: {}, links: {}, lane: null
            };
            d3.select(old).selectAll('.sankey-node').each(function (d) {
                prev.nodes[layoutKey(d)] = {x: d.x0, y: d.y0, h: d.y1 - d.y0};
            });
            d3.select(old).selectAll('.sankey-link').each(function (d) {
                prev.links[layoutKey(d.source) + '>' + layoutKey(d.target)] =
                    {d: this.getAttribute('d'), w: this.getAttribute('stroke-width')};
            });
            var lane = old.querySelector('.sankey-target-grid > rect');
            if (lane) prev.lane = {y: +lane.getAttribute('y'), h: +lane.getAttribute('height')};
            return prev;
        }
        /* a zoom redraw glides from the old layout instead of replacing it */
        var previous = options.morph ? capturePreviousLayout() : null;
        _hideExcludeButton(0);

        if (sankeyEl) sankeyEl.innerHTML = '';
        var svg = d3.select('#sankey').append('svg')
            .attr('width',  width + margin.left + margin.right)
            .attr('height', height + margin.top + margin.bottom)
            .style('opacity', options.animateToggle ? 0 : 1)
            .append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        var sankey = d3.sankey()
            .nodeWidth(15)
            .nodePadding(10)
            .extent([[1, 1], [width - 1, height - 6]]);

        var graph = sankey({
            nodes: nodes.map(function (d) { return Object.assign({}, d); }),
            links: links.map(function (d) { return Object.assign({}, d); })
        });

        /* ── node position refinement ─────────────────────── */
        var sankeyNodeWidth = graph.nodes.length ? (graph.nodes[0].x1 - graph.nodes[0].x0) : 15;
        var attributeMaxX1 = 0;
        var targetNodes = [], orgNodes = [];
        var targetDateExtents = {min: Infinity, max: -Infinity};
        var currentEventDateTs = _currentEventDateTs;

        graph.nodes.forEach(function (node) {
            if (node.type === 'attribute') {
                attributeMaxX1 = Math.max(attributeMaxX1, node.x1);
            } else if (node.type === 'target') {
                targetNodes.push(node);
                var det = eventDetails && node.id ? eventDetails[node.id] : null;
                var ts  = det && det.date ? Date.parse(det.date + 'T00:00:00Z') : NaN;
                if (isFinite(ts)) {
                    targetDateExtents.min = Math.min(targetDateExtents.min, ts);
                    targetDateExtents.max = Math.max(targetDateExtents.max, ts);
                    node.eventDateTs = ts;
                }
            } else if (node.type === 'org') {
                orgNodes.push(node);
            }
        });

        var hasSpreadableDates, sankeyScaleMinTs, sankeyScaleMaxTs;
        if (isFinite(_rangeMinTs) && isFinite(_rangeMaxTs) && _rangeMaxTs > _rangeMinTs) {
            /* the zoomed period is the single source of truth for the scale */
            sankeyScaleMinTs = _rangeMinTs;
            sankeyScaleMaxTs = _rangeMaxTs;
            hasSpreadableDates = isFinite(targetDateExtents.min) && isFinite(targetDateExtents.max);
        } else {
            hasSpreadableDates = isFinite(targetDateExtents.min) && isFinite(targetDateExtents.max) && targetDateExtents.max > targetDateExtents.min;
            var sankeyDomainMinTs = targetDateExtents.min, sankeyDomainMaxTs = targetDateExtents.max;
            if (isFinite(currentEventDateTs)) {
                sankeyDomainMinTs = isFinite(sankeyDomainMinTs) ? Math.min(sankeyDomainMinTs, currentEventDateTs) : currentEventDateTs;
                sankeyDomainMaxTs = isFinite(sankeyDomainMaxTs) ? Math.max(sankeyDomainMaxTs, currentEventDateTs) : currentEventDateTs;
            }
            var useYearScale = isFinite(sankeyDomainMinTs) && isFinite(sankeyDomainMaxTs)
                && new Date(sankeyDomainMinTs).getUTCFullYear() !== new Date(sankeyDomainMaxTs).getUTCFullYear();
            sankeyScaleMinTs = isFinite(sankeyDomainMinTs) ? (useYearScale ? startOfUtcYear(sankeyDomainMinTs) : startOfUtcMonth(sankeyDomainMinTs)) : sankeyDomainMinTs;
            sankeyScaleMaxTs = isFinite(sankeyDomainMaxTs) ? (useYearScale ? addUtcYears(startOfUtcYear(sankeyDomainMaxTs), 1) : addUtcMonths(startOfUtcMonth(sankeyDomainMaxTs), 1)) : sankeyDomainMaxTs;
        }

        var rightLabelPadding = showPublisher ? 16 : 10;
        var orgLabelReserve   = showPublisher
            ? Math.max(96, Math.min(260, Math.round(longestOrgLen * 6.2) + 40))
            : 28;
        var targetToOrgGap    = alignToDate ? (showPublisher ? 84 : 52) : (showPublisher ? 56 : 36);
        var targetLaneStartFloor = attributeMaxX1 + 90;
        var targetLaneStart      = targetLaneStartFloor;
        var alignedLaneStart  = Math.max(targetLaneStartFloor, Math.floor(width * (alignToDate ? 0.42 : 0.68)));
        var alignedLaneEnd    = Math.max(alignedLaneStart + sankeyNodeWidth + 120, Math.floor(width * (alignToDate ? 0.74 : 0.82)));
        var maxAlignedLaneEnd = width - orgLabelReserve - targetToOrgGap - sankeyNodeWidth;
        if (alignedLaneEnd > maxAlignedLaneEnd) {
            alignedLaneEnd = Math.max(alignedLaneStart + sankeyNodeWidth + 80, maxAlignedLaneEnd);
        }
        if (alignedLaneStart > alignedLaneEnd - sankeyNodeWidth - 80) {
            alignedLaneStart = Math.max(targetLaneStartFloor, alignedLaneEnd - sankeyNodeWidth - 80);
        }
        var orgColumnX0  = Math.max(attributeMaxX1 + targetToOrgGap + sankeyNodeWidth, width - sankeyNodeWidth - rightLabelPadding);
        var targetLaneEnd = alignToDate ? Math.min(alignedLaneEnd, orgColumnX0 - targetToOrgGap) : Math.max(alignedLaneEnd, orgColumnX0 - targetToOrgGap);
        /* nodes span [alignedLaneStart, alignedLaneEnd - nodeWidth] by their left
           edge, so their centres - and therefore the date axis - live here */
        var dateLaneStart = alignedLaneStart + (sankeyNodeWidth / 2);
        var dateLaneEnd   = alignedLaneEnd   - (sankeyNodeWidth / 2);
        var targetFixedX0 = Math.max(targetLaneStart, targetLaneEnd - Math.max(42, Math.floor(width * 0.035)));
        var orgLabelGap   = 18, targetLabelGap = 18, targetHoverPad = 14, orgLabelMaxLength = 34;

        /* a node the scale no longer covers is pinned to the edge and flagged */
        function placeOnDateLane(node, minTs, maxTs) {
            node.outOfRange = false;
            if (!hasSpreadableDates || !isFinite(node.eventDateTs)) {
                node.alignedX0 = alignedLaneStart + ((alignedLaneEnd - alignedLaneStart - sankeyNodeWidth) / 2);
                return;
            }
            var ratio = (node.eventDateTs - minTs) / Math.max(1, (maxTs - minTs));
            node.outOfRange = node.eventDateTs < Math.floor(minTs / DAY_MS) * DAY_MS
                || node.eventDateTs > maxTs;
            node.alignedX0 = alignedLaneStart
                + ((alignedLaneEnd - alignedLaneStart - sankeyNodeWidth) * Math.max(0, Math.min(1, ratio)));
        }

        if (targetNodes.length > 0 && targetLaneEnd > targetLaneStart) {
            targetNodes.forEach(function (node) {
                node.fixedX0 = targetFixedX0;
                node.fixedX1 = node.fixedX0 + sankeyNodeWidth;
                placeOnDateLane(node, sankeyScaleMinTs, sankeyScaleMaxTs);
                node.x0 = alignToDate ? node.alignedX0 : node.fixedX0;
                node.x1 = node.x0 + sankeyNodeWidth;
            });
        }
        orgNodes.forEach(function (node) {
            node.x0 = orgColumnX0;
            node.x1 = node.x0 + sankeyNodeWidth;
        });

        /* ── interaction helpers ──────────────────────────── */
        function sankeyNodeFill(node) {
            if (node.type === 'target')    return '#8fbfe8';
            if (node.type === 'org')       return '#b7c5d6';
            if (node.type === 'source')    return '#6fbe80';
            if (node.type === 'attribute') return '#f39a1f';
            return '#428bca';
        }
        function isSankeyInteractiveNode(node) {
            return node && (node.type === 'target' || node.type === 'attribute' || node.type === 'org');
        }
        function handleSankeyNodeClick(node) {
            if (node.type === 'target' && node.id) {
                window.location.href = baseurl + '/events/view2/' + node.id;
            } else if (node.type === 'attribute' && node.id) {
                omFilterCorrelations(node.id, 'attribute');
            }
        }
        function sankeyLinkConnectedToAttribute(link, node) {
            if (link.source && link.source.type === 'target' && link.target && link.target.type === 'org') {
                return graph.links.some(function (cl) { return cl.source === node && cl.target === link.source; });
            }
            return link.source === node || link.target === node;
        }
        function sankeyLinkConnectedToTarget(link, node) {
            if (node.type === 'target' && link.source === node && link.target && link.target.type === 'org') return true;
            if (link.target === node) return true;
            if (node.type === 'org') {
                if (link.target === node && link.source && link.source.type === 'target') return true;
                if (link.source && link.source.type === 'attribute' && link.target && link.target.type === 'target') {
                    var tgt = link.target;
                    return graph.links.some(function (cl) { return cl.source === tgt && cl.target === node; });
                }
            }
            return graph.links.some(function (cl) {
                return cl.target === node && cl.source === link.target && link.source && link.source.type === 'source';
            });
        }
        function sankeyNodeConnectedToAttribute(cn, an) {
            if (cn === an || cn.type === 'source') return true;
            if (cn.type === 'org') {
                return graph.links.some(function (l) {
                    return l.source === an && l.target && l.target.type === 'target'
                        && graph.links.some(function (cl) { return cl.source === l.target && cl.target === cn; });
                });
            }
            return graph.links.some(function (l) {
                return (l.source === an && l.target === cn) || (l.target === an && l.source === cn);
            });
        }
        function sankeyNodeConnectedToTarget(cn, an) {
            if (cn === an || cn.type === 'source') return true;
            if (cn.type === 'org') {
                if (an.type === 'org') return true;
                if (an.type === 'target') return graph.links.some(function (l) { return l.source === an && l.target === cn; });
                if (an.type === 'attribute') {
                    return graph.links.some(function (l) {
                        return l.source === an && l.target && l.target.type === 'target'
                            && graph.links.some(function (cl) { return cl.source === l.target && cl.target === cn; });
                    });
                }
                return false;
            }
            if (an.type === 'target' && cn.type === 'attribute') return graph.links.some(function (l) { return l.source === cn && l.target === an; });
            if (an.type === 'org') {
                if (cn.type === 'target') return graph.links.some(function (l) { return l.source === cn && l.target === an; });
                if (cn.type === 'attribute') {
                    return graph.links.some(function (l) {
                        return l.source === cn && l.target && l.target.type === 'target'
                            && graph.links.some(function (cl) { return cl.source === l.target && cl.target === an; });
                    });
                }
            }
            return graph.links.some(function (l) {
                return (l.target === an && l.source === cn) || (l.source === an && l.target === cn);
            });
        }
        function applySankeyHoverState(an, linkOpacity) {
            if (!isSankeyInteractiveNode(an)) return;
            svg.selectAll('.sankey-link').transition().duration(200)
                .style('stroke-opacity', function (l) {
                    var c = an.type === 'attribute' ? sankeyLinkConnectedToAttribute(l, an) : sankeyLinkConnectedToTarget(l, an);
                    return c ? linkOpacity : 0.08;
                });
            svg.selectAll('.sankey-label').transition().duration(200)
                .style('opacity', function (n) {
                    return (an.type === 'attribute' ? sankeyNodeConnectedToAttribute(n, an) : sankeyNodeConnectedToTarget(n, an)) ? 1 : 0.1;
                })
                .style('fill', function (n) {
                    if (n.type === 'source') return '#21486f';
                    if (n.type === 'org') {
                        var c = an.type === 'attribute' ? sankeyNodeConnectedToAttribute(n, an) : sankeyNodeConnectedToTarget(n, an);
                        return c ? '#31465b' : 'rgba(86, 105, 125, 0.5)';
                    }
                    return null;
                })
                .style('font-weight', function (n) {
                    if (n.type === 'org') {
                        var c = an.type === 'attribute' ? sankeyNodeConnectedToAttribute(n, an) : sankeyNodeConnectedToTarget(n, an);
                        return c ? '700' : '400';
                    }
                    return isSankeyInteractiveNode(n) ? 'bold' : 'normal';
                });
            svg.selectAll('.sankey-node rect:not(.sankey-target-hitbox)').transition().duration(200)
                .style('opacity', function (n) {
                    if (!isSankeyInteractiveNode(n)) return 1;
                    var c = an.type === 'attribute' ? sankeyNodeConnectedToAttribute(n, an) : sankeyNodeConnectedToTarget(n, an);
                    return n.type === 'org' ? (c ? 0.9 : 0.22) : (c ? 1 : 0.18);
                });
        }
        function resetSankeyHoverState(an) {
            if (!isSankeyInteractiveNode(an)) return;
            svg.selectAll('.sankey-link').transition().duration(200)
                .style('stroke-opacity', function (l) {
                    return (l.source && l.source.type === 'target' && l.target && l.target.type === 'org') ? 0.24 : 0.5;
                });
            svg.selectAll('.sankey-label').transition().duration(200)
                .style('opacity', 1)
                .style('fill', function (n) {
                    if (n.type === 'source') return '#21486f';
                    if (n.type === 'org')    return 'rgba(86, 105, 125, 0.62)';
                    return null;
                })
                .style('font-weight', function (n) {
                    return n.type === 'org' ? '500' : (isSankeyInteractiveNode(n) ? 'bold' : 'normal');
                });
            svg.selectAll('.sankey-node rect:not(.sankey-target-hitbox)').transition().duration(200)
                .style('opacity', function (n) { return n.type === 'org' ? 0.58 : 1; });
        }

        /* an IOC or an event offers its × next to its label */
        function hoverNode(d, linkOpacity) {
            applySankeyHoverState(d, linkOpacity);
            if (d.type !== 'attribute' && d.type !== 'target') return;
            _showExcludeButton(d, labelSelection.filter(function (n) { return n === d; }).node());
        }
        function leaveNode(d) {
            resetSankeyHoverState(d);
            _hideExcludeButton(220);
        }

        /* ── timeline grid ────────────────────────────────── */
        var gridGroup = null, tickLayer = null, markerLayer = null;
        var laneTop = 0, laneBottom = 0, axisY = 0, tickTopY = 0;

        if (targetNodes.length > 0 && dateLaneEnd > dateLaneStart && alignToDate) {
            laneTop    = Math.max(0, d3.min(targetNodes, function (d) { return d.y0; }) - 12);
            laneBottom = Math.min(height, d3.max(targetNodes, function (d) { return d.y1; }) + 8);
            var laneHeight = Math.max(0, laneBottom - laneTop);

            if (laneHeight > 0) {
                gridGroup = svg.append('g').attr('class', 'sankey-target-grid');
                axisY = laneTop - 28;
                tickTopY = axisY - 12;

                gridGroup.append('rect').attr('x', dateLaneStart).attr('y', laneTop)
                    .attr('width', dateLaneEnd - dateLaneStart).attr('height', laneHeight)
                    .attr('fill', 'rgba(84,142,94,.035)').attr('stroke', 'rgba(71,109,79,.12)').attr('stroke-width', 1)
                    .append('title').text(<?= json_encode(__('Scroll to zoom, drag to pan')) ?>);
                gridGroup.append('line').attr('x1', dateLaneStart).attr('x2', dateLaneEnd)
                    .attr('y1', axisY).attr('y2', axisY)
                    .attr('stroke', 'rgba(63,88,70,.34)').attr('stroke-width', 2).attr('shape-rendering', 'geometricPrecision');
                tickLayer   = gridGroup.append('g');
                markerLayer = gridGroup.append('g');
                drawDateGrid(sankeyScaleMinTs, sankeyScaleMaxTs);
            }
        }

        /* the ticks and the star are redrawn on every zoom step */
        function drawDateGrid(minTs, maxTs) {
            if (!tickLayer) return;
            tickLayer.selectAll('*').remove();
            markerLayer.selectAll('*').remove();

            var tg = tickLayer.selectAll('g')
                .data(buildSankeyGridTicks(minTs, maxTs, dateLaneStart, dateLaneEnd))
                .enter().append('g').attr('class', 'sankey-target-grid-tick');
            tg.append('line')
                .attr('x1', function (d) { return d.x; }).attr('x2', function (d) { return d.x; })
                .attr('y1', tickTopY).attr('y2', laneBottom)
                .attr('stroke', function (d) { return d.isEdge ? 'rgba(63,88,70,.28)' : 'rgba(63,88,70,.18)'; })
                .attr('stroke-width', 1).attr('shape-rendering', 'crispEdges');
            tg.append('line')
                .attr('x1', function (d) { return d.x; }).attr('x2', function (d) { return d.x; })
                .attr('y1', tickTopY).attr('y2', axisY)
                .attr('stroke', 'rgba(63,88,70,.42)').attr('stroke-width', 1.4).attr('shape-rendering', 'crispEdges');
            tg.append('text')
                .attr('x', function (d) { return d.x; }).attr('y', laneTop - 38)
                .attr('text-anchor', 'start').attr('dx', '3px').attr('dy', '-2px')
                .attr('transform', function (d) { return 'rotate(-55,' + d.x + ',' + (laneTop - 38) + ')'; })
                .style('font', '700 10px sans-serif').style('fill', '#44515f')
                .text(function (d) { return d.label; });

            if (!isFinite(currentEventDateTs) || !(maxTs > minTs)) return;
            /* pinned to an edge, the star would claim a date it does not have */
            if (currentEventDateTs < Math.floor(minTs / DAY_MS) * DAY_MS || currentEventDateTs > maxTs) return;
            var ceRatio = Math.max(0, Math.min(1, (currentEventDateTs - minTs) / (maxTs - minTs)));
            var ceX     = dateLaneStart + ((dateLaneEnd - dateLaneStart) * ceRatio);
            var ceNW    = sankeyNodeWidth;
            var ceNX    = Math.max(dateLaneStart - (ceNW / 2),
                          Math.min(dateLaneEnd - (ceNW / 2), ceX - ceNW / 2));
            var ceNY    = laneTop - 18, ceNH = 16;
            var ceCY    = ceNY + ceNH / 2, ceLX = ceNX + ceNW + targetLabelGap;
            var mg = markerLayer.append('g').attr('class', 'sankey-current-event-marker');
            mg.append('rect').attr('x', ceNX).attr('y', ceNY).attr('width', ceNW).attr('height', ceNH)
                .attr('fill', '#6fbe80').append('title').text(currentEventFullTitle);
            mg.append('text').attr('x', ceNX + ceNW / 2).attr('y', ceCY)
                .attr('text-anchor', 'middle').attr('dy', '0.35em')
                .style('font', '700 10px sans-serif').style('fill', '#fff')
                .text('★').append('title').text(currentEventFullTitle);
            mg.append('line').attr('x1', ceNX + ceNW).attr('x2', ceLX - 6)
                .attr('y1', ceCY).attr('y2', ceCY)
                .attr('stroke', 'rgba(74,92,112,.45)').attr('stroke-width', 1)
                .attr('shape-rendering', 'crispEdges').attr('pointer-events', 'none');
            mg.append('text').attr('x', ceLX).attr('y', ceCY)
                .attr('text-anchor', 'start').attr('dy', '0.35em')
                .style('font', '700 10px sans-serif').style('fill', '#26313d')
                .text(truncateSourceLabel(currentEventName)).append('title').text(currentEventFullTitle);
        }

        /* the wheel and the pan act on this box: the rotated labels down to the lane's bottom */
        _dateZone = gridGroup ? {
            x0: margin.left + alignedLaneStart - 4,
            x1: margin.left + alignedLaneEnd + 4,
            y1: margin.top + laneBottom,
            laneX0: margin.left + dateLaneStart,
            laneX1: margin.left + dateLaneEnd
        } : null;

        /* ── draw nodes ───────────────────────────────────── */
        var nodeGroup = svg.append('g').selectAll('g').data(graph.nodes).enter().append('g')
            .attr('class', function (d) { return 'sankey-node sankey-node-' + d.type; });

        nodeGroup.filter(function (d) { return d.type === 'target' || d.type === 'org'; })
            .append('rect')
            .attr('class', function (d) { return d.type === 'org' ? 'sankey-org-hitbox' : 'sankey-target-hitbox'; })
            .attr('x', function (d) { return d.type === 'org' ? d.x0 - 2 : Math.max(targetLaneStart - 4, d.x0 - targetHoverPad); })
            .attr('y', function (d) { return Math.max(0, d.y0 - 3); })
            .attr('width', function (d) {
                if (d.type === 'org') {
                    var lbl = (d.name || '').length > orgLabelMaxLength ? d.name.substring(0, orgLabelMaxLength - 3) + '...' : (d.name || '');
                    return Math.max((d.x1 - d.x0) + orgLabelGap + (lbl.length * 6.2) + 8, 52);
                }
                return Math.max((d.x1 - d.x0) + targetHoverPad + targetLabelGap + 8, 42);
            })
            .attr('height', function (d) { return Math.max((d.y1 - d.y0) + 6, 16); })
            .attr('fill', 'rgba(255,255,255,0)').attr('cursor', 'pointer')
            .on('click', handleSankeyNodeClick)
            .on('mouseover', function (d) { hoverNode(d, 0.7); })
            .on('mouseout', leaveNode);

        nodeGroup.append('rect')
            .attr('x', function (d) { return d.x0; }).attr('y', function (d) { return d.y0; })
            .attr('height', function (d) { return d.y1 - d.y0; }).attr('width', function (d) { return d.x1 - d.x0; })
            .attr('fill', sankeyNodeFill)
            .attr('cursor', function (d) { return isSankeyInteractiveNode(d) ? 'pointer' : 'default'; })
            .on('click', handleSankeyNodeClick)
            .on('mouseover', function (d) { hoverNode(d, 0.7); })
            .on('mouseout', leaveNode)
            .style('opacity', function (d) { return d.type === 'org' ? 0.42 : 1; })
            .append('title').text(function (d) { return d.fullTitle || d.name; });

        /* ── draw links ───────────────────────────────────── */
        var link = svg.append('g').attr('fill', 'none').attr('stroke-opacity', 0.5)
            .selectAll('path').data(graph.links).enter().append('path')
            .attr('class', 'sankey-link')
            .attr('d', function (d) {
                var x0 = d.source.x1, x1 = d.target.x0, xi = d3.interpolateNumber(x0, x1), x2 = xi(0.5), x3 = xi(0.5);
                return 'M' + x0 + ',' + d.y0 + 'C' + x2 + ',' + d.y0 + ' ' + x3 + ',' + d.y1 + ' ' + x1 + ',' + d.y1;
            })
            .attr('stroke', function (d) {
                if (d.source.type === 'source'    && d.target.type === 'attribute') return '#f6e8a6';
                if (d.source.type === 'attribute' && d.target.type === 'target')    return '#7ec8f3';
                if (d.source.type === 'target'    && d.target.type === 'org')       return 'rgba(116,147,179,.22)';
                return '#428bca';
            })
            .attr('stroke-width', function (d) { return Math.max(1, d.width); });

        /* ── draw labels ──────────────────────────────────── */
        var leaderLines = svg.append('g').selectAll('line')
            .data(graph.nodes.filter(function (d) { return d.type === 'target'; })).enter().append('line')
            .attr('class', 'sankey-target-label-line')
            .attr('x1', function (d) { return d.x1; }).attr('x2', function (d) { return d.x1 + targetLabelGap - 6; })
            .attr('y1', function (d) { return (d.y0 + d.y1) / 2; }).attr('y2', function (d) { return (d.y0 + d.y1) / 2; })
            .attr('stroke', 'rgba(74,92,112,.45)').attr('stroke-width', 1)
            .attr('shape-rendering', 'crispEdges').attr('pointer-events', 'none');

        var labelSelection = svg.append('g').style('font', '10px sans-serif')
            .selectAll('text').data(graph.nodes).enter().append('text')
            .attr('class', 'sankey-label')
            .attr('x', function (d) {
                if (d.type === 'source' || d.type === 'attribute') return d.x0 - (d.type === 'source' ? 18 : 8);
                if (d.type === 'target') return d.x1 + targetLabelGap;
                if (d.type === 'org')    return d.x1 + orgLabelGap;
                return d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6;
            })
            .attr('y', function (d) { return (d.y1 + d.y0) / 2; })
            .attr('dy', '0.35em')
            .attr('text-anchor', function (d) {
                if (d.type === 'source' || d.type === 'attribute') return 'end';
                return 'start';
            })
            .attr('cursor', function (d) { return isSankeyInteractiveNode(d) ? 'pointer' : 'default'; })
            .style('fill', function (d) {
                if (d.type === 'source') return '#21486f';
                if (d.type === 'org')    return 'rgba(86,105,125,.48)';
                return null;
            })
            .style('paint-order', function (d) { return d.type === 'source' ? 'stroke' : null; })
            .style('stroke',       function (d) { return d.type === 'source' ? 'rgba(255,255,255,.96)' : 'none'; })
            .style('stroke-width', function (d) { return d.type === 'source' ? 4 : 0; })
            .style('stroke-linejoin', function (d) { return d.type === 'source' ? 'round' : null; })
            .style('font-weight', function (d) {
                if (d.type === 'org') return '400';
                return isSankeyInteractiveNode(d) ? 'bold' : 'normal';
            });

        labelSelection.append('title').text(function (d) { return d.fullTitle || d.name; });
        labelSelection
            .on('click', handleSankeyNodeClick)
            .on('mouseover', function (d) { hoverNode(d, 0.5); })
            .on('mouseout', leaveNode)
            .text(function (d) {
                if (d.type === 'source') return '★ ' + truncateSourceLabel(d.name);
                var maxLen = d.type === 'target' ? 60 : (d.type === 'org' ? orgLabelMaxLength : 50);
                return d.name.length > maxLen ? d.name.substring(0, maxLen - 3) + '...' : d.name;
            });

        var labelHitboxes = svg.append('g').attr('class', 'sankey-target-label-hitboxes')
            .selectAll('rect').data(graph.nodes.filter(function (d) { return d.type === 'target'; })).enter()
            .append('rect')
            .attr('x', function (d) { return d.x1 + targetLabelGap - 4; })
            .attr('y', function (d) { return Math.max(0, (d.y0 + d.y1) / 2 - 8); })
            .attr('width', function (d) {
                var lbl = d.name.length > 60 ? d.name.substring(0, 57) + '...' : d.name;
                return Math.max(42, (lbl.length * 6.2) + 8);
            })
            .attr('height', 16)
            .attr('fill', 'rgba(255,255,255,0)').attr('cursor', 'pointer')
            .on('click', handleSankeyNodeClick)
            .on('mouseover', function (d) { hoverNode(d, 0.5); })
            .on('mouseout', leaveNode);
        labelHitboxes.append('title').text(function (d) { return d.fullTitle || d.name; });

        /* ── date-align animation (exposed to toggle listener) */
        function moveTargets(dur) {
            var useDate = document.getElementById('sankey-date-align').checked;
            function step(sel) { return dur ? sel.transition().duration(dur) : sel; }

            graph.nodes.forEach(function (node) {
                if (node.type !== 'target') return;
                node.x0 = useDate ? node.alignedX0 : node.fixedX0;
                node.x1 = node.x0 + sankeyNodeWidth;
            });
            function faded(d) { return useDate && !!d.outOfRange; }

            var targetGroups = nodeGroup.filter(function (d) { return d.type === 'target'; })
                .classed('is-out-of-range', faded);
            step(targetGroups.selectAll('rect:not(.sankey-target-hitbox)'))
                .attr('x', function (d) { return d.x0; }).attr('width', function (d) { return d.x1 - d.x0; });
            step(targetGroups.select('.sankey-target-hitbox'))
                .attr('x', function (d) { return Math.max(targetLaneStart - 4, d.x0 - targetHoverPad); })
                .attr('width', function (d) { return Math.max((d.x1 - d.x0) + targetHoverPad + targetLabelGap + 8, 42); });

            step(link.classed('is-out-of-range', function (d) { return faded(d.source) || faded(d.target); }))
                .attr('d', function (d) {
                    var x0 = d.source.x1, x1 = d.target.x0, xi = d3.interpolateNumber(x0, x1), x2 = xi(0.5), x3 = xi(0.5);
                    return 'M' + x0 + ',' + d.y0 + 'C' + x2 + ',' + d.y0 + ' ' + x3 + ',' + d.y1 + ' ' + x1 + ',' + d.y1;
                });

            step(leaderLines.classed('is-out-of-range', faded))
                .attr('x1', function (d) { return d.x1; })
                .attr('x2', function (d) { return d.x1 + targetLabelGap - 6; });

            step(labelSelection.filter(function (d) { return d.type === 'target'; })
                .classed('is-out-of-range', faded))
                .attr('x', function (d) { return d.x1 + targetLabelGap; });

            step(labelHitboxes)
                .attr('x', function (d) { return d.x1 + targetLabelGap - 4; });
        }

        updateTargetPositionsOnly = function (animate) {
            var dur = animate ? 450 : 0;
            settleMorph();
            moveTargets(dur);
            if (gridGroup) {
                var useDate = document.getElementById('sankey-date-align').checked;
                gridGroup.transition().duration(dur).style('opacity', useDate ? 1 : 0);
            }
        };

        /* live zoom: only the date column moves, the redraw follows later */
        rescaleDateLane = function () {
            if (!gridGroup || !isFinite(_rangeMinTs) || !(_rangeMaxTs > _rangeMinTs)) return;
            settleMorph();
            targetNodes.forEach(function (node) { placeOnDateLane(node, _rangeMinTs, _rangeMaxTs); });
            drawDateGrid(_rangeMinTs, _rangeMaxTs);
            moveTargets(0);
        };

        /* ── glide from the previous layout ───────────────── */
        var morphing = false;
        var morphed  = [nodeGroup, labelSelection, leaderLines, labelHitboxes];
        function morphStep(sel) {
            return sel.transition('morph').duration(420).ease('cubic-in-out');
        }
        /* inline opacity would outrank the out-of-range class later on */
        function dropOpacity() { d3.select(this).style('opacity', null); }

        function morphFrom(prev) {
            morphing = true;
            setTimeout(function () { morphing = false; }, 470);
            svg.attr('transform', 'translate(' + prev.ox + ',' + prev.oy + ')');
            morphStep(svg).attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

            function known(d) { return !!prev.nodes[layoutKey(d)]; }
            morphed.forEach(function (sel) {
                var kept = sel.filter(known);
                kept.attr('transform', function (d) {
                    var p = prev.nodes[layoutKey(d)];
                    return 'translate(' + (p.x - d.x0) + ',' + (p.y - d.y0) + ')';
                });
                morphStep(kept).attr('transform', 'translate(0,0)');
                var fresh = sel.filter(function (d) { return !known(d); }).style('opacity', 0);
                morphStep(fresh).style('opacity', 1).each('end', dropOpacity);
            });
            nodeGroup.filter(known).select('rect:not(.sankey-target-hitbox):not(.sankey-org-hitbox)')
                .each(function (d) {
                    var to = d3.select(this).attr('height');
                    morphStep(d3.select(this).attr('height', prev.nodes[layoutKey(d)].h))
                        .attr('height', to);
                });

            link.each(function (d) {
                var el = d3.select(this);
                var p  = prev.links[layoutKey(d.source) + '>' + layoutKey(d.target)];
                if (!p) {
                    morphStep(el.style('opacity', 0)).style('opacity', 1).each('end', dropOpacity);
                    return;
                }
                var toPath = el.attr('d'), toWidth = el.attr('stroke-width');
                morphStep(el.attr('d', p.d).attr('stroke-width', p.w))
                    .attr('d', toPath).attr('stroke-width', toWidth);
            });

            if (gridGroup && prev.lane) {
                var laneRect = gridGroup.select('rect');
                var toY = laneRect.attr('y'), toH = laneRect.attr('height');
                morphStep(laneRect.attr('y', prev.lane.y).attr('height', prev.lane.h))
                    .attr('y', toY).attr('height', toH);
                morphStep(tickLayer.selectAll('.sankey-target-grid-tick').select('line')
                    .attr('y2', prev.lane.y + prev.lane.h)).attr('y2', laneBottom);
            }
        }

        /* a wheel or a toggle mid-glide jumps it to its end first */
        function settleMorph() {
            if (!morphing) return;
            morphing = false;
            svg.interrupt('morph').attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');
            morphed.forEach(function (sel) {
                sel.interrupt('morph').attr('transform', null).style('opacity', null);
            });
            nodeGroup.selectAll('rect').interrupt('morph')
                .filter(':not(.sankey-target-hitbox):not(.sankey-org-hitbox)')
                .attr('height', function (d) { return d.y1 - d.y0; });
            link.interrupt('morph').style('opacity', null)
                .attr('stroke-width', function (d) { return Math.max(1, d.width); });
            if (gridGroup) {
                gridGroup.select('rect').interrupt('morph')
                    .attr('y', laneTop).attr('height', Math.max(0, laneBottom - laneTop));
            }
        }

        if (previous) morphFrom(previous);

        /* ── fade in after toggle re-render ───────────────── */
        if (options.animateToggle) {
            d3.select('#sankey svg').transition().duration(260).style('opacity', 1);
            if (sankeyEl) sankeyEl.style.opacity = '1';
        }
    }

    /* ── public: filter ────────────────────────────────────── */
    window.omFilterCorrelations = function (filterValue, filterType) {
        if (!_correlationData) return;
        var badge = document.getElementById('sankey-filter-badge');
        var lbl   = document.getElementById('sankey-filter-label');
        if (filterValue && badge && lbl) {
            var label = filterValue;
            if (filterType === 'attribute' && _correlationData[filterValue] && _correlationData[filterValue][0]) {
                label = _correlationData[filterValue][0].value || filterValue;
            } else if (filterType === 'org' && _correlationEventDetails) {
                var match = Object.values(_correlationEventDetails).find(function (d) { return d && String(d.org) === String(filterValue); });
                if (match && match.orgName) label = match.orgName;
            }
            lbl.textContent = label;
            badge.classList.remove('d-none');
        }
        renderSankey(
            _correlationData,
            _correlationEventDetails,
            filterType === 'attribute' ? filterValue : null,
            {animateToggle: true, filterOrgId: filterType === 'org' ? filterValue : null}
        );
        if (filterType === 'attribute') {
            _filterCorrList(filterValue);
        }
    };

    window.omResetCorrelationFilter = function () {
        var badge = document.getElementById('sankey-filter-badge');
        if (badge) badge.classList.add('d-none');
        var msg = document.getElementById('sankey-limit-msg');
        if (msg) msg.textContent = '';
        if (_correlationData && _correlationEventDetails) {
            renderSankey(_correlationData, _correlationEventDetails, null, {animateToggle: true});
        }
        _resetCorrList();
    };

    /* ── init ──────────────────────────────────────────────── */
    document.addEventListener('shown.bs.tab', function (e) {
        if (e.target && e.target.getAttribute('href') === '#tab-correlation') {
            loadCorrelations();
        }
    });

    var corrPane = document.getElementById('tab-correlation');
    if (corrPane && corrPane.classList.contains('active')) {
        loadCorrelations();
    }

}());
</script>
