<?php
$eventId   = h($data['Event']['id']   ?? '');
$eventInfo = addslashes(h($data['Event']['info'] ?? ''));
$eventDate = addslashes(h($data['Event']['date'] ?? ''));

// The filter bar wears the index filter bars' look, whose stylesheet the
// ajax tabs bring along and this one, drawn with the page, has to ask for.
echo $this->element('genericElements/assetLoader', [
    'css' => ['index-filters'],
    'js' => ['d3', 'd3-sankey.min']
]);

// Sortable headings of the correlated events: key => label
$corrColumns = [
    'info' => __('Event'),
    'org' => __('Creator org'),
    'date' => __('Date'),
    'count' => __('Correlating attributes'),
];
?>

<div class="corr-index">

    <!-- Filter bar: the search narrows the graph and the list, the panel holds the filters.
         Drawn as the index filter bars, but filtering here, so no data-ifp-bar. -->
    <div class="ifp-bar d-flex flex-wrap align-items-center corr-bar">
        <label class="ifp-query" id="corr-search-box">
            <i class="fas fa-search ifp-q-icon" aria-hidden="true"></i>
            <input id="corr-search" type="search" autocomplete="off" spellcheck="false"
                   placeholder="<?= h(__('Filter by value, type, event or organisation…')) ?>"
                   aria-label="<?= h(__('Filter by value, type, event or organisation')) ?>">
            <span class="ifp-q-end">
                <button type="button" class="ifp-q-clear" id="corr-search-clear"
                        title="<?= h(__('Clear the search')) ?>" aria-label="<?= h(__('Clear the search')) ?>">
                    <i class="fas fa-times" aria-hidden="true"></i>
                </button>
            </span>
        </label>
        <button type="button" class="ifp-fbtn" id="sankey-filters-open"
                aria-expanded="false" aria-controls="sankey-filters"
                title="<?= h(__('Show or hide the filters')) ?>">
            <i class="fas fa-sliders" aria-hidden="true"></i>
            <span><?= h(__('Filters')) ?></span>
            <span id="sankey-filters-count" class="badge rounded-pill bg-primary d-none"></span>
            <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
        </button>

        <div class="ifp-panel corr-panel" id="sankey-filters" role="region"
             aria-label="<?= h(__('Filters')) ?>" hidden>
            <div class="ifp-panel-body">
                <div class="ifp-quicks corr-quicks">
                    <label class="ifp-quick corr-quick">
                        <input class="visually-hidden" type="checkbox" role="switch" id="sankey-date-align" checked>
                        <span class="ifp-switch" aria-hidden="true"></span>
                        <?= h(__('Use timeline')) ?>
                    </label>
                    <label class="ifp-quick corr-quick">
                        <input class="visually-hidden" type="checkbox" role="switch" id="sankey-show-publisher" checked>
                        <span class="ifp-switch" aria-hidden="true"></span>
                        <?= h(__('Show publishers')) ?>
                    </label>
                    <label class="ifp-quick corr-quick" id="sankey-hide-warninglist-toggle">
                        <input class="visually-hidden" type="checkbox" role="switch" id="sankey-hide-warninglist">
                        <span class="ifp-switch" aria-hidden="true"></span>
                        <?= h(__('Hide warninglist hits')) ?>
                    </label>
                    <label class="corr-limit" for="sankey-event-limit"
                           title="<?= h(__('Leave empty to draw every correlated event.')) ?>">
                        <?= h(__('Most recent events shown')) ?>
                        <input type="number" class="form-control form-control-sm" id="sankey-event-limit"
                               min="1" step="1" inputmode="numeric" placeholder="<?= h(__('All')) ?>">
                    </label>
                </div>

                <div class="corr-panel-grid">
                    <?php foreach ([
                        'iocs' => [__('Correlating IOCs'), __('Search a value, a type or an object'), __('An unticked IOC leaves the graph and the list below, with every event it alone links to.')],
                        'events' => [__('Correlated events'), __('Search a title, a date or an organisation'), __('An unticked event leaves the graph and the list below.')],
                    ] as $kind => [$label, $placeholder, $hint]): ?>
                        <section class="ifp-sec corr-sec">
                            <div class="ifp-sec-label">
                                <?= h($label) ?>
                                <span class="badge rounded-pill bg-primary"></span>
                            </div>
                            <?php if ($kind === 'iocs'): ?>
                                <?php foreach (['types' => __('Types'), 'objects' => __('Objects')] as $facet => $facetLabel): ?>
                                    <div class="sankey-facet d-none mb-2" data-facet="<?= $facet ?>">
                                        <div class="corr-facet-label"><?= h($facetLabel) ?></div>
                                        <div class="d-flex flex-wrap gap-1" data-facet-list role="group"
                                             aria-label="<?= h($facetLabel) ?>"></div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
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
                            <div class="corr-hint"><?= h($hint) ?></div>
                        </section>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="ifp-win-foot">
                <span class="ifp-chips-none me-auto" id="sankey-filters-summary"></span>
                <button type="button" class="btn btn-sm btn-outline-secondary" id="sankey-filters-reset">
                    <i class="fa-solid fa-rotate-left me-1"></i><?= h(__('Reset filters')) ?>
                </button>
            </div>
        </div>
    </div>

    <!-- What is drawn: the count, then what narrows it from the graph itself -->
    <div class="ifp-row corr-row" id="sankey-toolbar">
        <span class="ifp-count" id="sankey-limit-msg"></span>
        <span class="corr-row-note" id="sankey-wl-msg"></span>
        <div class="ifp-chips" id="corr-chips">
            <span class="corr-chips-filters" id="corr-filter-chips"></span>
            <span id="sankey-filter-badge" class="ifp-chip d-none">
                <span class="ifp-chip-label"><?= h(__('Focus')) ?><span class="ifp-chip-op">:</span>
                    <span class="ifp-chip-value" id="sankey-filter-label"></span></span>
                <a href="#" class="ifp-chip-x" onclick="omResetCorrelationFilter();return false;"
                   title="<?= h(__('Remove filter')) ?>" aria-label="<?= h(__('Remove filter')) ?>">
                    <i class="fas fa-times" aria-hidden="true"></i>
                </a>
            </span>
            <span id="sankey-zoom-badge" class="ifp-chip d-none">
                <span class="ifp-chip-label"><?= h(__('Period')) ?><span class="ifp-chip-op">:</span>
                    <span class="ifp-chip-value" id="sankey-zoom-label"></span></span>
                <a href="#" id="sankey-zoom-reset" class="ifp-chip-x"
                   title="<?= h(__('Show the whole period')) ?>" aria-label="<?= h(__('Show the whole period')) ?>">
                    <i class="fas fa-times" aria-hidden="true"></i>
                </a>
            </span>
            <button type="button" class="ifp-clear d-none" id="corr-chips-clear"><?= __('Clear all') ?></button>
        </div>
    </div>

    <!-- Graph -->
    <div class="card shadow-sm mb-3 corr-graph">
        <div class="corr-card-head">
            <span class="corr-card-icon corr-graph-icon"><i class="fas fa-project-diagram" aria-hidden="true"></i></span>
            <div class="me-auto">
                <div class="corr-card-title"><?= __('Correlation Graph') ?></div>
                <div class="corr-card-sub corr-overview-head" id="sankey-overview-head" hidden></div>
            </div>
            <span class="sankey-overview-key" id="sankey-overview-key" hidden>
                <span class="sankey-overview-star">★</span><?= h(__('This event')) ?>
            </span>
        </div>

        <div class="p-3">
            <!-- Loader -->
            <div id="correlations-loader" class="text-center py-4 text-muted">
                <div class="misp-loader mb-2" role="status"></div>
                <?= h(__('Analyzing correlations…')) ?>
            </div>

            <!-- Content (revealed after fetch) -->
            <div id="correlations-content" style="display:none;">
                <div id="sankey-stage" class="sankey-stage" style="display:none;">

                    <!-- Period brush: every correlated event, its window is the period the graph draws -->
                    <div id="sankey-overview" class="sankey-overview" hidden></div>

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
            </div>
        </div>
    </div>

    <!-- Correlated events, each opening on the attributes it shares with this event -->
    <div class="card shadow-sm mb-4 corr-events" id="correlations-list" style="display:none;">
        <div class="corr-card-head">
            <span class="corr-card-icon corr-events-icon"><i class="fas fa-link" aria-hidden="true"></i></span>
            <div class="me-auto">
                <div class="corr-card-title"><?= h(__('Correlated events')) ?></div>
                <div class="corr-card-sub" id="corr-events-count"></div>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0 ix-table corr-table">
                <thead class="checkbox-index">
                    <tr>
                        <th class="corr-col-expand"></th>
                        <?php foreach ($corrColumns as $key => $label): ?>
                            <th class="corr-col-<?= h($key) ?>">
                                <a href="#" data-corr-sort="<?= h($key) ?>">
                                    <span class="sortable-header"><?= h($label) ?><i class="sort-icon"></i></span>
                                </a>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody id="correlations-list-body"></tbody>
            </table>
        </div>
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
    var _correlationData         = null;   // working set: IOC key -> relations still drawn
    var _rawCorrelationData      = null;   // untouched API payload
    var _iocs                    = null;   // IOC key -> {value, rels, pids}, one per matched value
    var _parentAttributes        = {};     // this event's attribute id -> {type, object}
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
    var _overview     = null;        // the period brush strip
    var _overviewBars = [];          // its bars: {from, to, count}, in ms
    var _brushing     = false;       // a brush drag is changing the period
    var _brushBars    = null;        // bar indices under the brush
    var updateTargetPositionsOnly = function () {};   // set inside renderSankey
    var rescaleDateLane = function () {};             // set inside renderSankey

    var DAY_MS   = 86400000;
    var MONTH_MS = 2629746000;
    var YEAR_MS  = 31556952000;
    var MIN_ZOOM_SPAN_MS = 7 * DAY_MS;
    var OVERVIEW_MAX_BARS = 120;
    var OVERVIEW_UNITS = ['day', 'week', 'month', 'quarter', 'year'];

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
        _syncOverview();
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
        if (_pan || _brushing) return;   // the release redraws
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
        var focused = badge && !badge.classList.contains('d-none');
        if (badge) badge.classList.add('d-none');
        if (focused) _resetCorrList();
        renderSankey(_correlationData, _correlationEventDetails, null, {morph: true});
        _rerenderCorrList();
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

    /* ── period brush ──────────────────────────────────────── */
    /* the strip always spans the whole domain, its window is the drawn period */
    var _overviewTitle = <?= json_encode(h(__('Correlated events over time'))) ?>;
    var _overviewHint  = <?= json_encode(h(__('Drag to choose the period drawn below, click to show it all.'))) ?>;
    var _overviewUnits = <?= json_encode([
        'day' => h(__('One bar per day.')),
        'week' => h(__('One bar per week.')),
        'month' => h(__('One bar per month.')),
        'quarter' => h(__('One bar per quarter.')),
        'year' => h(__('One bar per year.')),
    ]) ?>;

    function _nextBar(ts, unit) {
        if (unit === 'day')     return ts + DAY_MS;
        if (unit === 'week')    return ts + 7 * DAY_MS;
        if (unit === 'month')   return addUtcMonths(ts, 1);
        if (unit === 'quarter') return addUtcMonths(ts, 3);
        return addUtcYears(ts, 1);
    }

    /* the finest calendar unit that keeps the bars readable */
    function _overviewBuckets(minTs, maxTs) {
        var unit, bars;
        for (var u = 0; u < OVERVIEW_UNITS.length; u++) {
            var cap = u === OVERVIEW_UNITS.length - 1 ? Infinity : OVERVIEW_MAX_BARS;
            unit = OVERVIEW_UNITS[u];
            bars = [];
            for (var t = minTs; t < maxTs && bars.length <= cap; t = _nextBar(t, unit)) {
                bars.push({from: t, to: Math.min(maxTs, _nextBar(t, unit)), count: 0});
            }
            if (bars.length <= cap) break;
        }
        return {unit: unit, bars: bars};
    }

    function _barIndexAt(ts) {
        var lo = 0, hi = _overviewBars.length - 1;
        while (lo < hi) {
            var mid = (lo + hi + 1) >> 1;
            if (_overviewBars[mid].from <= ts) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    /* 0..bar count along the strip */
    function _barPosition(ts) {
        var n = _overviewBars.length;
        if (ts >= _overviewBars[n - 1].to) return n;
        var i = _barIndexAt(ts), bar = _overviewBars[i];
        return i + Math.max(0, (ts - bar.from) / (bar.to - bar.from));
    }

    /* the date lane's tick picker, so both axes read alike */
    function _overviewLabels(widthPx) {
        var n = _overviewBars.length, labels = {};
        var step = _pickTickStep(_domainMaxTs - _domainMinTs, widthPx);
        _tickTimes(_domainMinTs, _domainMaxTs, step).forEach(function (ts) {
            var i = _barIndexAt(ts);
            if (ts >= _domainMaxTs || (i / n) * widthPx + _tickLabelWidth(step.unit) > widthPx) return;
            labels[i] = {
                text: formatSankeyGridDate(ts, step.unit),
                major: ts === startOfUtcYear(ts)
            };
        });
        return labels;
    }

    function _buildOverview(eventDetails) {
        var host = document.getElementById('sankey-overview');
        _overview  = null;
        _brushing  = false;
        _brushBars = null;
        if (!host) return;
        host.innerHTML = '';
        if (!window.MispTimeline || !(_domainMaxTs > _domainMinTs)) {
            _syncOverview();
            return;
        }
        var buckets = _overviewBuckets(_domainMinTs, _domainMaxTs);
        _overviewBars = buckets.bars;
        var max = 0;
        Object.keys(eventDetails).forEach(function (eid) {
            var date = (eventDetails[eid] || {}).date || '';
            var ts   = date ? Date.parse(date + 'T00:00:00Z') : NaN;
            if (!isFinite(ts)) return;
            max = Math.max(max, ++_overviewBars[_barIndexAt(ts)].count);
        });
        var contentEl = document.getElementById('correlations-content');
        var labels = _overviewLabels((contentEl && contentEl.clientWidth) || 800);
        var dated  = isFinite(_currentEventDateTs);

        _overview = window.MispTimeline.overview({
            bars: _overviewBars,
            max: max,
            maxLabels: _overviewBars.length,
            tickLabel: function (i) { return labels[i] || null; },
            /* the card's head says what the strip is */
            head: '',
            onRange: function (from, to) {
                _brushBars = {from: from, to: to};
                /* a press still inside its bar may yet be a click */
                if (!_brushing && from === to) return;
                _brushing = true;
                _brushTo(from, to);
            },
            onSettle: function () {
                if (_brushBars) _brushTo(_brushBars.from, _brushBars.to);
                _endBrush();
            },
            onClear: function () {
                _brushing  = false;
                _brushBars = null;
                _resetZoom();
            }
        });
        _overview.el.addEventListener('pointercancel', _endBrush);
        host.appendChild(_overview.el);
        var headEl = document.getElementById('sankey-overview-head');
        if (headEl) {
            headEl.innerHTML = '<strong>' + _overviewTitle + '</strong>'
                + '<span>' + _overviewUnits[buckets.unit] + ' ' + _overviewHint + '</span>';
        }

        if (dated) {
            var plot = _overview.el.querySelector('.tl-ov-plot');
            var mark = document.createElement('div');
            mark.className = 'sankey-overview-current';
            mark.style.left = (100 * _barPosition(_currentEventDateTs + DAY_MS / 2)
                / _overviewBars.length) + '%';
            mark.innerHTML = '<span class="sankey-overview-star">★</span>';
            plot.insertBefore(mark, plot.querySelector('[data-misp-brush]'));
        }
        _syncOverview();
    }

    /* a run reaching the last bar runs to the domain's end, so a full sweep is "everything" */
    function _brushTo(from, to) {
        var last = to === _overviewBars.length - 1;
        _setRange(_overviewBars[from].from, last ? _domainMaxTs : _overviewBars[to].to - 1);
        _syncOverview();
    }

    function _endBrush() {
        if (!_brushing && !_brushBars) return;
        _brushing  = false;
        _brushBars = null;
        _syncOverview();
        _flushGraphUpdate();
    }

    function _syncOverview() {
        var host    = document.getElementById('sankey-overview');
        var alignEl = document.getElementById('sankey-date-align');
        if (!host) return;
        host.hidden = !_overview || !(alignEl && alignEl.checked);
        var headEl = document.getElementById('sankey-overview-head');
        var keyEl  = document.getElementById('sankey-overview-key');
        if (headEl) headEl.hidden = host.hidden;
        if (keyEl)  keyEl.hidden  = host.hidden || !isFinite(_currentEventDateTs);
        if (host.hidden) return;
        if (_rangeIsFull && !_brushing) {
            _overview.set(null);
            return;
        }
        _overview.set({from: _barPosition(_rangeMinTs), to: _barPosition(_rangeMaxTs) - 1});
    }

    /* ── fetch ─────────────────────────────────────────────── */
    function loadCorrelations() {
        if (_correlationData !== null || _correlationsLoading) return;
        _correlationsLoading = true;
        var loaderEl  = document.getElementById('correlations-loader');
        var contentEl = document.getElementById('correlations-content');
        var url = baseurl + '/correlations/eventCorrelations/' + eventId
                + '.json?include_attributes=1&include_org_names=1'
                + '&include_warninglist_hits=1&include_parent_attributes=1';

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
    var _attrOpenEvent = <?= json_encode(__('Open event: %s')) ?>;
    var _corrEventsOne   = <?= json_encode(__('%s event')) ?>;
    var _corrEventsMany  = <?= json_encode(__('%s events')) ?>;
    var _corrEventsOf    = <?= json_encode(__('%s of %s events in the period')) ?>;
    var _corrNoneInPeriod = <?= json_encode(__('No correlated event in this period.')) ?>;
    var _corrAttrsOne    = <?= json_encode(__('%s correlating attribute')) ?>;
    var _corrAttrsMany   = <?= json_encode(__('%s correlating attributes')) ?>;
    var _corrDistTitle   = <?= json_encode(__('Distribution: %s')) ?>;
    var _corrExpandTitle = <?= json_encode(__('Show the correlating attributes')) ?>;
    var _corrColValue    = <?= json_encode(__('Value')) ?>;
    var _corrColCategory = <?= json_encode(__('Category')) ?>;
    var _corrColType     = <?= json_encode(__('Type')) ?>;
    var _corrColObject   = <?= json_encode(__('Object')) ?>;
    var _corrColIds      = <?= json_encode(__('IDS')) ?>;
    var _corrIdsOn       = <?= json_encode(__('IDS active')) ?>;
    var _corrIdsOff      = <?= json_encode(__('IDS inactive')) ?>;

    function _isWarninglisted(parentId) {
        return !!(_warninglistHits && _warninglistHits[parentId]);
    }

    /* warninglists match attributes: an IOC carries the hits of every attribute behind it */
    function _iocWarninglisted(key) {
        return Object.keys(_iocs[key].pids).some(_isWarninglisted);
    }

    function _iocWarninglistNames(key) {
        var names = {};
        Object.keys(_iocs[key].pids).forEach(function (pid) {
            (_warninglistHits[pid] || []).forEach(function (name) { names[name] = true; });
        });
        return Object.keys(names).join(', ');
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
    var _excludedIocs    = {};   // IOC key -> true
    var _excludedEvents  = {};   // event id -> true
    var _excludedTypes   = {};   // attribute type -> true
    var _excludedObjects = {};   // object template, '' for standalone -> true
    var _eventLimit      = 0;    // most recent events drawn, 0 for all
    var _searchNeedle    = '';   // the bar's search, lower-cased
    var _filterIndex     = null; // every IOC and event of the payload, with its row
    var _refilterTimer   = null;

    var _fltIocEvents   = <?= json_encode(__('Correlated events')) ?>;
    var _fltEventIocs   = <?= json_encode(__('Correlating IOCs')) ?>;
    var _fltByWl        = <?= json_encode(__('Hidden by the warninglist filter')) ?>;
    var _fltByKind      = <?= json_encode(__('Hidden by the type or object filter')) ?>;
    var _fltNoEventLeft = <?= json_encode(__('Every event it links to is excluded')) ?>;
    var _fltNoIocLeft   = <?= json_encode(__('Every IOC that links to it is excluded')) ?>;
    var _fltExclOne     = <?= json_encode(__('%s exclusion')) ?>;
    var _fltExclMany    = <?= json_encode(__('%s exclusions')) ?>;
    var _fltNone        = <?= json_encode(__('Nothing excluded')) ?>;
    var _fltStandalone  = <?= json_encode(__('Standalone')) ?>;
    var _chipSearch     = <?= json_encode(__('Search')) ?>;
    var _chipWl         = <?= json_encode(__('Warninglist hits')) ?>;
    var _chipWlHidden   = <?= json_encode(__('hidden')) ?>;
    var _chipLimit      = <?= json_encode(__('Most recent events')) ?>;
    var _chipRemove     = <?= json_encode(__('Remove this filter')) ?>;
    var _chipKinds      = {
        types:   {one: <?= json_encode(__('Type')) ?>, many: <?= json_encode(__('Types')) ?>},
        objects: {one: <?= json_encode(__('Object')) ?>, many: <?= json_encode(__('Objects')) ?>},
        iocs:    {one: <?= json_encode(__('IOC')) ?>, many: <?= json_encode(__('IOCs')) ?>},
        events:  {one: <?= json_encode(__('Event')) ?>, many: <?= json_encode(__('Events')) ?>}
    };
    var _chipValues     = <?= json_encode(__('%s values')) ?>;
    var CHIPS_PER_KIND  = 3;   // past it, a kind's exclusions share one chip

    function _countKeys(bag) { return Object.keys(bag).length; }

    function _exclusionCount() {
        return _countKeys(_excludedIocs) + _countKeys(_excludedEvents)
            + _countKeys(_excludedTypes) + _countKeys(_excludedObjects);
    }

    function _activeFilterCount() {
        return _exclusionCount() + (_eventLimit > 0 ? 1 : 0) + (_hideWarninglisted() ? 1 : 0);
    }

    /* the bar's search: a relation stays when its value, its attribute or its event matches */
    function _matchesSearch(key, rel) {
        if (!_searchNeedle) return true;
        var attr = rel.Attribute || {};
        return [
            _iocs[key].value, rel.value, attr.type, attr.category,
            attr.Object ? attr.Object.name : '', rel.info, rel.org_name, rel.date, '#' + rel.id
        ].join(' ').toLowerCase().indexOf(_searchNeedle) !== -1;
    }

    /* what the attribute behind a relation lets through: warninglist, type, object */
    function _attrShown(pid, hideWl) {
        if (hideWl && _isWarninglisted(pid)) return false;
        var attr = _parentAttributes[pid];
        return !attr || (!_excludedTypes[attr.type] && !_excludedObjects[attr.object || '']);
    }

    function _filterRow(kind, id, search) {
        var row = document.createElement('label');
        row.className = 'list-group-item list-group-item-action d-flex align-items-start gap-2 py-1 px-2 small';
        row.setAttribute('data-search', search.toLowerCase());
        var box = document.createElement('input');
        box.type = 'checkbox';
        box.className = 'form-check-input m-0 mt-1 flex-shrink-0';
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
        var events = {}, types = {}, objects = {};
        var iocList = Object.keys(_iocs).map(function (key) {
            var ioc = {id: key, value: _iocs[key].value, rels: _iocs[key].rels, events: {}, types: {}, objects: {}};
            ioc.rels.forEach(function (rel) {
                var eid = String(rel.id);
                ioc.events[eid] = true;
                var ev = events[eid] || (events[eid] = {
                    id: eid, info: rel.info || ('#' + eid), date: rel.date || '',
                    org: rel.org_name || '', iocs: {}, rels: []
                });
                ev.iocs[key] = true;
                ev.rels.push(rel);
            });
            Object.keys(_iocs[key].pids).forEach(function (pid) {
                var attr = _parentAttributes[pid];
                if (!attr) return;
                ioc.types[attr.type] = true;
                ioc.objects[attr.object || ''] = true;
            });
            Object.keys(ioc.types).forEach(function (t) { types[t] = (types[t] || 0) + 1; });
            Object.keys(ioc.objects).forEach(function (o) { objects[o] = (objects[o] || 0) + 1; });
            return ioc;
        });

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
                var typeNames   = Object.keys(ioc.types);
                var objectNames = Object.keys(ioc.objects).filter(Boolean);
                var parts = _filterRow('iocs', ioc.id, [ioc.value].concat(typeNames, objectNames).join(' '));
                var text = document.createElement('span');
                text.className = 'flex-fill overflow-hidden';
                var value = document.createElement('span');
                value.className = 'd-block text-truncate';
                value.textContent = ioc.value;
                value.title = ioc.value;
                text.appendChild(value);
                var meta = typeNames.join(', ') + (objectNames.length ? ' · ' + objectNames.join(', ') : '');
                if (meta) {
                    var metaEl = document.createElement('span');
                    metaEl.className = 'd-block text-truncate text-body-secondary small';
                    metaEl.textContent = meta;
                    text.appendChild(metaEl);
                }
                parts.row.appendChild(text);
                if (_iocWarninglisted(ioc.id)) {
                    var wl = document.createElement('i');
                    wl.className = 'fa-solid fa-triangle-exclamation text-warning flex-shrink-0 mt-1';
                    wl.title = _wlLabel + ': ' + _iocWarninglistNames(ioc.id);
                    parts.row.appendChild(wl);
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
        _buildFacet('types', types, function (t) { return t; });
        _buildFacet('objects', objects, function (o) { return o || _fltStandalone; });
        _filterIndex = {iocs: iocList, events: eventList};
    }

    /* a facet with a single option would filter nothing, so it stays hidden */
    function _buildFacet(kind, counts, label) {
        var wrap = document.querySelector('[data-facet="' + kind + '"]');
        var list = wrap && wrap.querySelector('[data-facet-list]');
        if (!list) return;
        var names = Object.keys(counts).sort(function (a, b) {
            return counts[b] - counts[a] || label(a).localeCompare(label(b));
        });
        list.innerHTML = '';
        wrap.classList.toggle('d-none', names.length < 2);
        names.forEach(function (name, i) {
            var box = document.createElement('input');
            box.type = 'checkbox';
            box.className = 'btn-check';
            box.id = 'sankey-facet-' + kind + '-' + i;
            box.value = name;
            box.setAttribute('data-filter-item', kind);
            var chip = document.createElement('label');
            chip.className = 'sankey-facet-chip';
            chip.htmlFor = box.id;
            var text = document.createElement('span');
            text.className = 'sankey-facet-name';
            text.textContent = label(name);
            chip.appendChild(text);
            var count = document.createElement('span');
            count.className = 'sankey-facet-count';
            count.textContent = counts[name];
            count.title = _fltEventIocs;
            chip.appendChild(count);
            list.appendChild(box);
            list.appendChild(chip);
        });
    }

    /* ticks, greyed rows, counters and the toolbar badge follow the state */
    function _syncFilterUi() {
        if (!_filterIndex) return;
        var hideWl = _hideWarninglisted();
        var shownIocs = 0, shownEvents = 0;

        _filterIndex.iocs.forEach(function (ioc) {
            var excluded  = !!_excludedIocs[ioc.id];
            var pids      = Object.keys(_iocs[ioc.id].pids);
            var byAttr    = !pids.some(function (pid) { return _attrShown(pid, hideWl); });
            var reachable = ioc.rels.some(function (rel) {
                return !_excludedEvents[rel.id] && _attrShown(rel._pid, hideWl);
            });
            ioc.box.checked  = !excluded && !byAttr;
            ioc.box.disabled = byAttr;
            ioc.row.classList.toggle('opacity-50', byAttr || (!excluded && !reachable));
            ioc.row.title = byAttr
                ? (hideWl && pids.every(_isWarninglisted) ? _fltByWl : _fltByKind)
                : (!excluded && !reachable ? _fltNoEventLeft : '');
            if (!excluded && reachable) shownIocs++;
        });
        _filterIndex.events.forEach(function (ev) {
            var excluded  = !!_excludedEvents[ev.id];
            var reachable = ev.rels.some(function (rel) {
                return !_excludedIocs[rel._ioc] && _attrShown(rel._pid, hideWl);
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
        document.querySelectorAll('[data-facet-list] [data-filter-item]').forEach(function (box) {
            var bag = box.getAttribute('data-filter-item') === 'types' ? _excludedTypes : _excludedObjects;
            box.checked = !bag[box.value];
        });

        var active  = _activeFilterCount();
        var exclusions = _exclusionCount();
        var countEl = document.getElementById('sankey-filters-count');
        if (countEl) {
            countEl.textContent = active;
            countEl.classList.toggle('d-none', active === 0);
        }
        var openBtn = document.getElementById('sankey-filters-open');
        if (openBtn) openBtn.classList.toggle('is-set', active > 0);
        var summary = document.getElementById('sankey-filters-summary');
        if (summary) {
            summary.textContent = exclusions === 0 ? _fltNone
                : (exclusions === 1 ? _fltExclOne : _fltExclMany).replace('%s', exclusions);
        }
        var reset = document.getElementById('sankey-filters-reset');
        if (reset) reset.disabled = active === 0;
        _syncFilterChips();
    }

    /* ── the active filters as the index bars show them: one removable chip each ── */
    function _filterChip(label, op, value, kind, key) {
        return '<span class="ifp-chip"><span class="ifp-chip-label">' + escapeHtml(label)
            + '<span class="ifp-chip-op">' + escapeHtml(op) + '</span> '
            + '<span class="ifp-chip-value">' + escapeHtml(value) + '</span></span>'
            + '<a href="#" class="ifp-chip-x" data-corr-chip="' + escapeHtml(kind) + '"'
            + (key === undefined ? '' : ' data-corr-chip-key="' + escapeHtml(key) + '"')
            + ' title="' + escapeHtml(_chipRemove) + '" aria-label="' + escapeHtml(_chipRemove) + '">'
            + '<i class="fas fa-times" aria-hidden="true"></i></a></span>';
    }

    function _chipLabelOf(kind, key) {
        if (kind === 'objects') return key || _fltStandalone;
        if (kind === 'iocs') return _iocs[key] ? String(_iocs[key].value) : key;
        if (kind === 'events') {
            var ev = _filterIndex && _filterIndex.events.find(function (e) { return e.id === String(key); });
            return ev ? ev.info : '#' + key;
        }
        return key;
    }

    function _syncFilterChips() {
        var slot  = document.getElementById('corr-filter-chips');
        var clear = document.getElementById('corr-chips-clear');
        if (!slot) return;
        var html = '';
        var search = document.getElementById('corr-search');
        if (_searchNeedle && search) html += _filterChip(_chipSearch, ':', search.value.trim(), 'search');
        if (_hideWarninglisted()) html += _filterChip(_chipWl, ':', _chipWlHidden, 'warninglist');
        if (_eventLimit > 0) html += _filterChip(_chipLimit, ':', String(_eventLimit), 'limit');
        [['types', _excludedTypes], ['objects', _excludedObjects], ['iocs', _excludedIocs], ['events', _excludedEvents]]
            .forEach(function (pair) {
                var keys = Object.keys(pair[1]);
                if (keys.length > CHIPS_PER_KIND) {
                    html += _filterChip(_chipKinds[pair[0]].many, ' ≠', _chipValues.replace('%s', keys.length), pair[0]);
                    return;
                }
                keys.forEach(function (key) {
                    html += _filterChip(_chipKinds[pair[0]].one, ' ≠', _chipLabelOf(pair[0], key), pair[0], key);
                });
            });
        slot.innerHTML = html;
        if (clear) clear.classList.toggle('d-none', html === '');
    }

    function _removeFilterChip(kind, key) {
        var bags = {types: _excludedTypes, objects: _excludedObjects, iocs: _excludedIocs, events: _excludedEvents};
        if (kind === 'search') {
            _setSearch('');
        } else if (kind === 'warninglist') {
            var wl = document.getElementById('sankey-hide-warninglist');
            if (wl) wl.checked = false;
        } else if (kind === 'limit') {
            _eventLimit = 0;
            var limit = document.getElementById('sankey-event-limit');
            if (limit) limit.value = '';
        } else if (bags[kind]) {
            if (key === null) {
                Object.keys(bags[kind]).forEach(function (k) { delete bags[kind][k]; });
            } else {
                delete bags[kind][key];
            }
        }
        _refilter(true);
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
        _excludedTypes = {};
        _excludedObjects = {};
        _eventLimit = 0;
        var limit = document.getElementById('sankey-event-limit');
        if (limit) limit.value = '';
        var wl = document.getElementById('sankey-hide-warninglist');
        if (wl) wl.checked = false;
        _setSearch('');
        _refilter(true);
    }

    function _setSearch(value) {
        var input = document.getElementById('corr-search');
        if (input && input.value !== value) input.value = value;
        var box = document.getElementById('corr-search-box');
        if (box) box.classList.toggle('has-value', value !== '');
        _searchNeedle = value.trim().toLowerCase();
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
        _overview = null;
        _syncOverview();
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
    /* one IOC per matched value: a composite attribute matched on both halves feeds two */
    function _groupByValue(raw) {
        var iocs = {}, keyOf = {}, next = 0;
        Object.keys(raw).forEach(function (pid) {
            (raw[pid] || []).forEach(function (rel) {
                var value = rel.value || ('#' + pid);
                /* correlation ignores case */
                var norm = value.toLowerCase();
                var key  = keyOf[norm] || (keyOf[norm] = String(next++));
                var ioc  = iocs[key] || (iocs[key] = {value: value, rels: [], pids: {}});
                rel._pid = pid;
                rel._ioc = key;
                ioc.rels.push(rel);
                ioc.pids[pid] = true;
            });
        });
        return iocs;
    }

    function renderCorrelations(payload) {
        _rawCorrelationData = (payload && payload.correlations !== undefined)
            ? (payload.correlations || {})
            : (payload || {});
        _iocs                = _groupByValue(_rawCorrelationData);
        _parentAttributes    = (payload && payload.parent_attributes) || {};
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
        var hidden = hideWl ? _warninglistHitCount : 0;
        Object.keys(_iocs).forEach(function (key) {
            if (_excludedIocs[key]) return;
            var kept = _iocs[key].rels.filter(function (rel) {
                return !_excludedEvents[rel.id] && _attrShown(rel._pid, hideWl)
                    && _matchesSearch(key, rel);
            });
            if (kept.length) data[key] = kept;
        });
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

        for (var iocKey in data) {
            (data[iocKey] || []).forEach(function (rel) {
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
                /* the card shows the correlated event's attribute: its type and category */
                attributeMap[eid].push({
                    id:       rel._ioc,
                    value:    rel.value || _iocs[rel._ioc].value,
                    type:     (rel.Attribute && rel.Attribute.type) || '',
                    category: attrCategory,
                    attribute: rel.Attribute || null
                });
            });
        }
        _correlationEventDetails = eventDetails;

        var total = Object.keys(eventDetails).length;
        if (total === 0) {
            var excluded = _exclusionCount() > 0 || _searchNeedle !== '';
            _showEmptyState(excluded ? 'filters' : (hidden > 0 ? 'warninglist' : null));
            return;
        }
        _hideEmptyState();

        _computeDateDomain(eventDetails);
        _syncZoomBadge();
        _buildOverview(eventDetails);
        renderSankey(data, eventDetails, null,
            options.morph ? {morph: true} : (options.animateToggle ? {animateToggle: true} : {}));
        renderCorrelationsList(eventDetails, eventCounts, attributeMap);
    }

    /* ── events list with correlating attributes ──────────── */
    var _distMap = <?= json_encode(array_map(function ($meta) {
        $meta['label'] = h($meta['label']);
        return $meta;
    }, $this->DistributionLevel->all()), JSON_FORCE_OBJECT) ?>;
    var _distFallback = {bg:'#f1f5f9', color:'#64748b', icon:'fas fa-link', label:'', token:'dist-unknown'};

    function renderCorrelationsList(eventDetails, eventCounts, attributeMap) {
        var listEl = document.getElementById('correlations-list');
        var bodyEl = document.getElementById('correlations-list-body');
        if (!listEl || !bodyEl) return;
        _corrListArgs = [eventDetails, eventCounts, attributeMap];

        /* the period the timeline zooms on narrows the list as it does the
           graph; an undated event stays, as it does there */
        var alignEl = document.getElementById('sankey-date-align');
        var rangeActive = !!(alignEl && alignEl.checked) && !_rangeIsFull
            && isFinite(_rangeMinTs) && isFinite(_rangeMaxTs);
        var inPeriod = function (eid) {
            if (!rangeActive) return true;
            var date = (eventDetails[eid] || {}).date || '';
            var ts = date ? Date.parse(date + 'T00:00:00Z') : NaN;
            return !isFinite(ts) || _inRange(ts);
        };


        var allEids = Object.keys(eventCounts);
        var rows = allEids.filter(inPeriod).map(function (eid) {
            var det = eventDetails[eid] || {};
            var attrs = attributeMap[eid] || [];
            /* one row per correlating value, however many relations carry it */
            var seen = {};
            var unique = attrs.filter(function (a) {
                var key = a.type + ':' + a.value;
                if (seen[key]) return false;
                seen[key] = true;
                return true;
            });
            var iocKeys = attrs.map(function (a) { return a.id; })
                .filter(function (v, i, all) { return all.indexOf(v) === i; });
            return {
                eid: eid,
                info: det.info || ('#' + eid),
                date: det.date || '',
                org: det.org || '',
                orgName: det.orgName || '',
                distribution: det.distribution,
                attrs: unique,
                iocKeys: iocKeys
            };
        });

        var dir = _corrSort.dir === 'asc' ? 1 : -1;
        rows.sort(function (a, b) {
            var by;
            if (_corrSort.key === 'count') {
                by = a.attrs.length - b.attrs.length;
            } else if (_corrSort.key === 'org') {
                by = a.orgName.localeCompare(b.orgName);
            } else if (_corrSort.key === 'date') {
                by = a.date.localeCompare(b.date);
            } else {
                by = a.info.localeCompare(b.info);
            }
            return by * dir || b.attrs.length - a.attrs.length || a.info.localeCompare(b.info);
        });

        bodyEl.innerHTML = '';
        var attrTotal = 0;
        rows.forEach(function (r) {
            attrTotal += r.attrs.length;
            var row = _corrEventRow(r);
            var detail = _corrDetailRow(r);
            bodyEl.appendChild(row);
            bodyEl.appendChild(detail);
            /* a re-render (a filter, a sort, a zoom) keeps the rows the reader opened */
            if (_corrOpened[r.eid]) _setRowExpanded(row, true);
        });
        if (!rows.length) {
            bodyEl.innerHTML = '<tr class="corr-empty"><td colspan="5">'
                + escapeHtml(_corrNoneInPeriod) + '</td></tr>';
        }

        var countEl = document.getElementById('corr-events-count');
        if (countEl) {
            countEl.textContent = (rows.length < allEids.length
                    ? _corrEventsOf.replace('%s', rows.length).replace('%s', allEids.length)
                    : (rows.length === 1 ? _corrEventsOne : _corrEventsMany).replace('%s', rows.length))
                + ' · ' + (attrTotal === 1 ? _corrAttrsOne : _corrAttrsMany).replace('%s', attrTotal);
        }
        document.querySelectorAll('[data-corr-sort]').forEach(function (link) {
            var on = link.getAttribute('data-corr-sort') === _corrSort.key;
            link.classList.toggle('asc', on && _corrSort.dir === 'asc');
            link.classList.toggle('desc', on && _corrSort.dir === 'desc');
        });

        _delegateCorrList();
        listEl.style.display = '';
    }

    function _corrDistChip(distId) {
        var dist = _distMap[distId] !== undefined ? _distMap[distId] : _distFallback;
        var tone = function (role, value) {
            return dist.token ? 'var(--misp-' + dist.token + '-' + role + ', ' + value + ')' : value;
        };
        var chip = document.createElement('span');
        chip.className = 'ov-obj-dist';
        chip.style.setProperty('--ov-dist-bg', tone('bg', dist.bg));
        chip.style.setProperty('--ov-dist-ink', tone('fg', dist.color));
        if (dist.label) chip.title = _corrDistTitle.replace('%s', dist.label);
        chip.innerHTML = '<i class="' + escapeHtml(dist.icon) + '"></i>';
        return chip;
    }

    function _corrEventRow(r) {
        var row = document.createElement('tr');
        row.className = 'corr-row';
        row.setAttribute('data-eid', r.eid);
        row.setAttribute('data-ioc-keys', r.iocKeys.join(','));

        var expand = document.createElement('td');
        expand.className = 'corr-col-expand';
        expand.innerHTML = '<button type="button" class="oi-expand corr-expand" aria-expanded="false"'
            + ' aria-controls="corr-attrs-' + escapeHtml(r.eid) + '" title="' + escapeHtml(_corrExpandTitle) + '">'
            + '<i class="fas fa-chevron-right"></i></button>';
        row.appendChild(expand);

        var event = document.createElement('td');
        event.className = 'corr-col-info';
        var wrap = document.createElement('div');
        wrap.className = 'corr-event';
        wrap.appendChild(_corrDistChip(r.distribution));
        var title = document.createElement('div');
        title.className = 'corr-event-title';
        title.innerHTML = '<a class="corr-event-name" href="' + escapeHtml(baseurl + '/events/view/' + r.eid) + '"'
            + ' title="' + escapeHtml(r.info) + '">' + escapeHtml(r.info) + '</a>'
            + '<span class="corr-event-id">#' + escapeHtml(r.eid) + '</span>';
        wrap.appendChild(title);
        event.appendChild(wrap);
        row.appendChild(event);

        var org = document.createElement('td');
        org.className = 'corr-col-org';
        org.innerHTML = r.orgName
            ? '<a class="corr-org" href="' + escapeHtml(baseurl + '/organisations/view/' + r.org) + '">'
              + '<i class="misp-icon misp-icon-organisation misp-simple" aria-hidden="true"></i>'
              + '<span>' + escapeHtml(r.orgName) + '</span></a>'
            : '<span class="corr-none">—</span>';
        row.appendChild(org);

        var date = document.createElement('td');
        date.className = 'corr-col-date';
        date.innerHTML = r.date
            ? '<time datetime="' + escapeHtml(r.date) + '">' + escapeHtml(r.date) + '</time>'
            : '<span class="corr-none">—</span>';
        row.appendChild(date);

        var count = document.createElement('td');
        count.className = 'corr-col-count';
        var warned = r.attrs.some(function (a) { return _iocWarninglisted(a.id); });
        count.innerHTML = '<button type="button" class="corr-count" title="'
            + escapeHtml((r.attrs.length === 1 ? _attrPillOne : _attrPillMany).replace('%s', r.attrs.length)) + '">'
            + '<span class="misp-icon misp-icon-attribute misp-simple" aria-hidden="true"></span>'
            + '<span>' + r.attrs.length + '</span>'
            + (warned ? '<i class="fa-solid fa-triangle-exclamation corr-count-warning" title="'
                + escapeHtml(_wlLabel) + '"></i>' : '')
            + '</button>';
        row.appendChild(count);
        return row;
    }

    /* the attributes it shares, as the attribute index lists them */
    function _corrDetailRow(r) {
        var detail = document.createElement('tr');
        detail.className = 'corr-detail';
        detail.id = 'corr-attrs-' + r.eid;
        detail.hidden = true;
        var cell = document.createElement('td');
        cell.colSpan = 5;
        var html = '<div class="corr-detail-box"><table class="table mb-0 ix-table corr-attr-table"><thead><tr>'
            + '<th>' + escapeHtml(_corrColValue) + '</th>'
            + '<th>' + escapeHtml(_corrColCategory) + '</th>'
            + '<th>' + escapeHtml(_corrColType) + '</th>'
            + '<th>' + escapeHtml(_corrColObject) + '</th>'
            + '<th class="text-center">' + escapeHtml(_corrColIds) + '</th>'
            + '</tr></thead><tbody>';
        r.attrs.forEach(function (a) {
            var attr = a.attribute || {};
            var href = baseurl + '/events/view/' + r.eid + (attr.uuid ? '/focus:' + attr.uuid : '');
            var toIds = !!(attr.to_ids && attr.to_ids !== '0');
            html += '<tr class="corr-attr-row" data-ioc-key="' + escapeHtml(a.id) + '">'
                + '<td class="corr-attr-value"><a href="' + escapeHtml(href) + '" title="'
                + escapeHtml(a.value + '\n' + _attrOpenEvent.replace('%s', r.info)) + '">'
                + escapeHtml(a.value) + '</a>'
                + (_iocWarninglisted(a.id)
                    ? '<i class="fa-solid fa-triangle-exclamation text-warning ms-2" title="'
                      + escapeHtml(_wlLabel + ': ' + _iocWarninglistNames(a.id)) + '"></i>'
                    : '')
                + '</td>'
                + '<td>' + (a.category
                    ? '<div class="d-flex align-items-center text-nowrap"><p class="fst-italic mb-0">'
                      + escapeHtml(a.category) + '</p><i class="fa-solid fa-chevron-right ms-1"></i></div>'
                    : '<span class="corr-none">—</span>') + '</td>'
                + '<td>' + (a.type
                    ? '<p class="border border-dark rounded p-1 mb-0 d-inline-block">' + escapeHtml(a.type) + '</p>'
                    : '<span class="corr-none">—</span>') + '</td>'
                + '<td>' + (attr.Object && attr.Object.name
                    ? '<span class="corr-object"><i class="misp-icon misp-icon-object misp-simple" aria-hidden="true"></i>'
                      + escapeHtml(attr.Object.name) + '</span>'
                    : '<span class="corr-none">—</span>') + '</td>'
                + '<td class="text-center"><i class="fas fa-shield-halved ' + (toIds ? 'text-warning' : 'corr-ids-off') + '"'
                + ' title="' + escapeHtml(toIds ? _corrIdsOn : _corrIdsOff) + '"></i></td>'
                + '</tr>';
        });
        html += '</tbody></table></div>';
        cell.innerHTML = html;
        detail.appendChild(cell);
        return detail;
    }

    /* ── open / close a row's attributes ───────────────────── */
    var _corrListDelegated = false;
    var _corrListArgs = null;
    var _corrSort = {key: 'count', dir: 'desc'};
    var _corrOpened = {};   // event id -> true, outlives a row the period hides

    function _rerenderCorrList() {
        if (_corrListArgs) renderCorrelationsList.apply(null, _corrListArgs);
    }

    function _setRowExpanded(row, expanded) {
        if (!row) return;
        var detail = row.nextElementSibling;
        var btn = row.querySelector('.corr-expand');
        if (!detail || !detail.classList.contains('corr-detail')) return;
        detail.hidden = !expanded;
        row.classList.toggle('is-open', expanded);
        if (expanded) _corrOpened[row.getAttribute('data-eid')] = true;
        else delete _corrOpened[row.getAttribute('data-eid')];
        if (btn) btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    }

    /* one listener on the table, which survives every re-render */
    function _delegateCorrList() {
        var listEl = document.getElementById('correlations-list');
        if (_corrListDelegated || !listEl) return;
        _corrListDelegated = true;
        listEl.addEventListener('click', function (e) {
            var sort = e.target.closest('[data-corr-sort]');
            if (sort) {
                e.preventDefault();
                var key = sort.getAttribute('data-corr-sort');
                _corrSort = {
                    key: key,
                    dir: _corrSort.key === key
                        ? (_corrSort.dir === 'asc' ? 'desc' : 'asc')
                        : (key === 'count' || key === 'date' ? 'desc' : 'asc')
                };
                _rerenderCorrList();
                return;
            }
            var row = e.target.closest('tr.corr-row');
            if (!row || e.target.closest('a')) return;
            e.preventDefault();
            _setRowExpanded(row, !row.classList.contains('is-open'));
        });
    }

    /* ── list filter helpers ───────────────────────────────── */
    function _filterCorrList(attrId) {
        var bodyEl = document.getElementById('correlations-list-body');
        if (!bodyEl) return;
        var attrStr = String(attrId);
        bodyEl.querySelectorAll('tr.corr-row').forEach(function (row) {
            var ids = (row.getAttribute('data-ioc-keys') || '').split(',');
            var match = ids.indexOf(attrStr) !== -1;
            row.hidden = !match;
            var detail = row.nextElementSibling;
            if (!match) {
                if (detail) detail.hidden = true;
                return;
            }
            if (detail) {
                detail.querySelectorAll('.corr-attr-row').forEach(function (attrRow) {
                    attrRow.classList.toggle('is-faded', attrRow.getAttribute('data-ioc-key') !== attrStr);
                });
            }
            /* the highlight is worthless while the row is closed */
            _setRowExpanded(row, true);
        });
    }

    function _resetCorrList() {
        var bodyEl = document.getElementById('correlations-list-body');
        if (!bodyEl) return;
        bodyEl.querySelectorAll('tr.corr-row').forEach(function (row) {
            row.hidden = false;
            var detail = row.nextElementSibling;
            if (detail) {
                detail.querySelectorAll('.corr-attr-row').forEach(function (attrRow) {
                    attrRow.classList.remove('is-faded');
                });
            }
            _setRowExpanded(row, false);
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
            _syncOverview();
            /* the period filter follows the axis, and a graph drawn without
               the axis has no date column to slide into */
            if (!_rangeIsFull || (this.checked && !_dateZone)) {
                redraw();
                /* the list keeps to the period only while the axis draws it */
                if (!_rangeIsFull) _rerenderCorrList();
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
            var bag = {
                iocs: _excludedIocs, events: _excludedEvents,
                types: _excludedTypes, objects: _excludedObjects
            }[box.getAttribute('data-filter-item')];
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
    function renderSankey(data, eventDetails, filterIocKey, options) {
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

        var iocKeys;
        if (filterIocKey) {
            iocKeys = Object.keys(data).filter(function (id) { return id == filterIocKey; });
        } else {
            /* rank within the period, so zooming in can reach what the cap hides */
            var drawable = {};
            Object.keys(data).forEach(function (key) {
                drawable[key] = (data[key] || []).filter(relInRange).length;
            });
            iocKeys = Object.keys(drawable)
                .filter(function (key) { return drawable[key] > 0; })
                .sort(function (a, b) { return drawable[b] - drawable[a]; })
                .slice(0, 100);
        }

        var allowedTargetEventIds = null;
        if (latestEventsOnly) {
            var latestTargetEvents = [];
            var seen = {};
            iocKeys.forEach(function (key) {
                (data[key] || []).forEach(function (rel) {
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
        iocKeys.forEach(function (key) {
            (data[key] || []).forEach(function (rel) {
                if (allowedTargetEventIds && !allowedTargetEventIds[String(rel.id)]) return;
                if (!relInRange(rel)) return;
                eventLinkCounts[rel.id] = (eventLinkCounts[rel.id] || 0) + 1;
            });
        });

        iocKeys.forEach(function (key) {
            var relations = data[key] || [];
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

            var attrValue = _iocs[key].value;
            var attrLabel = attrValue;
            var attrTitle = attrValue;
            if (_iocWarninglisted(key)) {
                attrLabel = '\u26a0 ' + attrValue;
                attrTitle = attrValue + ' | ' + _wlLabel + ': ' + _iocWarninglistNames(key);
            }
            var attrIdx   = addNode(attrLabel, 'attribute', key, attrTitle);
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
        function isSankeyInteractiveNode(node) {
            return node && (node.type === 'target' || node.type === 'attribute' || node.type === 'org');
        }
        function handleSankeyNodeClick(node) {
            if (node.type === 'target' && node.id) {
                window.location.href = baseurl + '/events/view/' + node.id;
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
            svg.selectAll('.sankey-label')
                .classed('is-linked', function (n) {
                    return n.type === 'org'
                        && (an.type === 'attribute' ? sankeyNodeConnectedToAttribute(n, an) : sankeyNodeConnectedToTarget(n, an));
                })
                .transition().duration(200)
                .style('opacity', function (n) {
                    return (an.type === 'attribute' ? sankeyNodeConnectedToAttribute(n, an) : sankeyNodeConnectedToTarget(n, an)) ? 1 : 0.1;
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
            svg.selectAll('.sankey-label').classed('is-linked', false)
                .transition().duration(200)
                .style('opacity', 1)
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
                    .attr('class', 'sankey-grid-lane').attr('stroke-width', 1)
                    .append('title').text(<?= json_encode(__('Scroll to zoom, drag to pan')) ?>);
                gridGroup.append('line').attr('x1', dateLaneStart).attr('x2', dateLaneEnd)
                    .attr('y1', axisY).attr('y2', axisY)
                    .attr('class', 'sankey-grid-axis').attr('stroke-width', 2).attr('shape-rendering', 'geometricPrecision');
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
                .attr('class', function (d) { return 'sankey-grid-line' + (d.isEdge ? ' is-edge' : ''); })
                .attr('stroke-width', 1).attr('shape-rendering', 'crispEdges');
            tg.append('line')
                .attr('x1', function (d) { return d.x; }).attr('x2', function (d) { return d.x; })
                .attr('y1', tickTopY).attr('y2', axisY)
                .attr('class', 'sankey-grid-stub').attr('stroke-width', 1.4).attr('shape-rendering', 'crispEdges');
            tg.append('text')
                .attr('x', function (d) { return d.x; }).attr('y', laneTop - 38)
                .attr('text-anchor', 'start').attr('dx', '3px').attr('dy', '-2px')
                .attr('transform', function (d) { return 'rotate(-55,' + d.x + ',' + (laneTop - 38) + ')'; })
                .attr('class', 'sankey-grid-label')
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
                .attr('class', 'sankey-current-node').append('title').text(currentEventFullTitle);
            mg.append('text').attr('x', ceNX + ceNW / 2).attr('y', ceCY)
                .attr('text-anchor', 'middle').attr('dy', '0.35em')
                .attr('class', 'sankey-current-star')
                .text('★').append('title').text(currentEventFullTitle);
            mg.append('line').attr('x1', ceNX + ceNW).attr('x2', ceLX - 6)
                .attr('y1', ceCY).attr('y2', ceCY)
                .attr('class', 'sankey-leader').attr('stroke-width', 1)
                .attr('shape-rendering', 'crispEdges').attr('pointer-events', 'none');
            mg.append('text').attr('x', ceLX).attr('y', ceCY)
                .attr('text-anchor', 'start').attr('dy', '0.35em')
                .attr('class', 'sankey-current-label')
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
            .attr('class', 'sankey-node-bar')
            .attr('cursor', function (d) { return isSankeyInteractiveNode(d) ? 'pointer' : 'default'; })
            .on('click', handleSankeyNodeClick)
            .on('mouseover', function (d) { hoverNode(d, 0.7); })
            .on('mouseout', leaveNode)
            .style('opacity', function (d) { return d.type === 'org' ? 0.42 : 1; })
            .append('title').text(function (d) { return d.fullTitle || d.name; });

        /* ── draw links ───────────────────────────────────── */
        var link = svg.append('g').attr('fill', 'none').attr('stroke-opacity', 0.5)
            .selectAll('path').data(graph.links).enter().append('path')
            .attr('class', function (d) {
                var kind = '';
                if (d.source.type === 'source'    && d.target.type === 'attribute') kind = ' sankey-link-attribute';
                if (d.source.type === 'attribute' && d.target.type === 'target')    kind = ' sankey-link-target';
                if (d.source.type === 'target'    && d.target.type === 'org')       kind = ' sankey-link-org';
                return 'sankey-link' + kind;
            })
            .attr('d', function (d) {
                var x0 = d.source.x1, x1 = d.target.x0, xi = d3.interpolateNumber(x0, x1), x2 = xi(0.5), x3 = xi(0.5);
                return 'M' + x0 + ',' + d.y0 + 'C' + x2 + ',' + d.y0 + ' ' + x3 + ',' + d.y1 + ' ' + x1 + ',' + d.y1;
            })
            .attr('stroke-width', function (d) { return Math.max(1, d.width); });

        /* ── draw labels ──────────────────────────────────── */
        var leaderLines = svg.append('g').selectAll('line')
            .data(graph.nodes.filter(function (d) { return d.type === 'target'; })).enter().append('line')
            .attr('class', 'sankey-target-label-line sankey-leader')
            .attr('x1', function (d) { return d.x1; }).attr('x2', function (d) { return d.x1 + targetLabelGap - 6; })
            .attr('y1', function (d) { return (d.y0 + d.y1) / 2; }).attr('y2', function (d) { return (d.y0 + d.y1) / 2; })
            .attr('stroke-width', 1)
            .attr('shape-rendering', 'crispEdges').attr('pointer-events', 'none');

        var labelSelection = svg.append('g').attr('class', 'sankey-labels')
            .selectAll('text').data(graph.nodes).enter().append('text')
            .attr('class', function (d) { return 'sankey-label sankey-label-' + d.type; })
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

    /* ── the filter bar: its panel and its search ───────────── */
    (function () {
        var panel   = document.getElementById('sankey-filters');
        var openBtn = document.getElementById('sankey-filters-open');
        var search  = document.getElementById('corr-search');
        var clear   = document.getElementById('corr-search-clear');
        if (!panel || !openBtn) return;

        function showPanel(show) {
            panel.hidden = !show;
            openBtn.setAttribute('aria-expanded', show ? 'true' : 'false');
        }
        openBtn.addEventListener('click', function () { showPanel(panel.hidden); });
        document.addEventListener('click', function (e) {
            if (!panel.hidden && !panel.contains(e.target) && !openBtn.contains(e.target)) showPanel(false);
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && !panel.hidden) {
                showPanel(false);
                openBtn.focus();
            }
        });

        var chips = document.getElementById('corr-chips');
        if (chips) {
            chips.addEventListener('click', function (e) {
                var x = e.target.closest('[data-corr-chip]');
                if (x) {
                    e.preventDefault();
                    _removeFilterChip(x.getAttribute('data-corr-chip'),
                        x.hasAttribute('data-corr-chip-key') ? x.getAttribute('data-corr-chip-key') : null);
                    return;
                }
                if (e.target.closest('#corr-chips-clear')) _resetFilters();
            });
        }

        if (!search) return;
        var searchTimer = null;
        function apply(value, now) {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(function () {
                _setSearch(value);
                if (_rawCorrelationData) _refilter(true);
            }, now ? 0 : 200);
        }
        search.addEventListener('input', function () {
            var box = document.getElementById('corr-search-box');
            if (box) box.classList.toggle('has-value', search.value !== '');
            apply(search.value);
        });
        search.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && search.value !== '') {
                e.stopPropagation();
                search.value = '';
                apply('', true);
            }
        });
        if (clear) {
            clear.addEventListener('click', function () {
                search.value = '';
                apply('', true);
                search.focus();
            });
        }
    }());

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
