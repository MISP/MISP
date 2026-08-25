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
                <div class="d-flex align-items-center gap-2 flex-wrap mb-2" style="min-height:24px;">
                    <span id="sankey-filter-badge" class="badge text-bg-danger d-none">
                        <i class="fas fa-filter me-1"></i>
                        <span id="sankey-filter-label"></span>
                        <a href="#" class="text-white ms-1 text-decoration-none"
                           onclick="omResetCorrelationFilter();return false;"
                           title="<?= h(__('Remove filter')) ?>">
                            <i class="fas fa-times-circle"></i>
                        </a>
                    </span>
                    <span id="sankey-limit-msg" class="small text-muted"></span>
                    <div class="ms-auto d-flex align-items-center gap-3 flex-wrap">
                        <label for="sankey-date-align" class="sankey-toggle mb-0">
                            <span class="sankey-toggle-label"><?= h(__('Use timeline')) ?></span>
                            <input type="checkbox" id="sankey-date-align" checked>
                            <span class="sankey-toggle-switch" aria-hidden="true"></span>
                        </label>
                        <label for="sankey-latest-events" class="sankey-toggle mb-0">
                            <span class="sankey-toggle-label"><?= h(__('20 event limit')) ?></span>
                            <input type="checkbox" id="sankey-latest-events">
                            <span class="sankey-toggle-switch" aria-hidden="true"></span>
                        </label>
                        <label for="sankey-show-publisher" class="sankey-toggle mb-0">
                            <span class="sankey-toggle-label"><?= h(__('Show publisher')) ?></span>
                            <input type="checkbox" id="sankey-show-publisher" checked>
                            <span class="sankey-toggle-switch" aria-hidden="true"></span>
                        </label>
                    </div>
                </div>

                <!-- Graph -->
                <div style="display:flex;align-items:flex-start;justify-content:center;width:100%;">
                    <div id="sankey-shell" class="sankey-shell">
                        <div id="sankey" style="width:100%;height:400px;margin:0 auto;overflow-x:auto;"></div>
                    </div>
                </div>
            </div>

            <!-- Correlated-event timeline (shown below the graph) -->
            <div id="correlations-timeline" class="event-timeline" style="display:none;">
                <div class="event-timeline-header">
                    <span class="event-timeline-title">
                        <i class="fas fa-stream"></i>
                        <?= h(__('Correlated event timeline')) ?>
                    </span>
                    <span class="event-timeline-range" id="correlations-timeline-range"></span>
                </div>
                <div class="event-timeline-track">
                    <div class="event-timeline-ticks" aria-hidden="true"></div>
                    <div class="event-timeline-markers"></div>
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

<script>
(function () {

    /* ── PHP data ──────────────────────────────────────────── */
    var eventId   = <?= json_encode($eventId) ?>;
    var baseurl   = <?= json_encode($baseurl ?? '') ?>;
    var eventInfo = <?= json_encode($eventInfo) ?>;
    var eventDate = <?= json_encode($eventDate) ?>;

    /* ── state ─────────────────────────────────────────────── */
    var _correlationData         = null;
    var _correlationEventDetails = null;
    var _correlationsLoading     = false;
    var _currentEventDateTs      = eventDate ? Date.parse(eventDate + 'T00:00:00Z') : NaN;
    var _sankeyListenersReady    = false;
    var updateTargetPositionsOnly = function () {};   // set inside renderSankey

    /* ── helpers ───────────────────────────────────────────── */
    function formatTimelineDateUtc(ts) {
        var d   = new Date(ts);
        var y   = d.getUTCFullYear();
        var m   = String(d.getUTCMonth() + 1).padStart(2, '0');
        var day = String(d.getUTCDate()).padStart(2, '0');
        return y + '-' + m + '-' + day;
    }

    /* ── timeline ──────────────────────────────────────────── */
    function renderCorrelationsTimeline(detailsMap) {
        var timeline   = document.getElementById('correlations-timeline');
        if (!timeline) return;
        var markers    = timeline.querySelector('.event-timeline-markers');
        var ticks      = timeline.querySelector('.event-timeline-ticks');
        var rangeLabel = document.getElementById('correlations-timeline-range');
        if (!markers || !ticks) return;

        var items = Object.keys(detailsMap || {}).map(function (eid) {
            var det  = detailsMap[eid] || {};
            var date = det.date || '';
            var ts   = Date.parse(date + 'T00:00:00Z');
            if (!date || !isFinite(ts)) return null;
            return { id: eid, title: det.info || '', date: date, ts: ts };
        }).filter(Boolean);

        if (!items.length) { timeline.style.display = 'none'; return; }

        items.sort(function (a, b) { return a.ts - b.ts; });
        var itemMinTs = items[0].ts;
        var itemMaxTs = items[items.length - 1].ts;
        var minTs = itemMinTs, maxTs = itemMaxTs;
        if (isFinite(_currentEventDateTs)) {
            minTs = Math.min(minTs, _currentEventDateTs);
            maxTs = Math.max(maxTs, _currentEventDateTs);
        }
        var rawRange = maxTs - minTs;
        var range    = Math.max(rawRange, 1);

        ticks.innerHTML = '';
        var tickCount = rawRange === 0 ? 1 : Math.min(7, Math.max(3, items.length + 1));
        for (var i = 0; i < tickCount; i++) {
            var tick      = document.createElement('span');
            var pctTick   = tickCount === 1 ? 50 : (i / (tickCount - 1)) * 100;
            var isEdge    = i === 0 || i === tickCount - 1;
            tick.className = 'event-timeline-tick' + (isEdge ? ' event-timeline-tick-edge' : '');
            tick.style.left = pctTick + '%';
            var tickTs    = rawRange === 0 ? minTs : minTs + ((range * i) / Math.max(1, tickCount - 1));
            var label     = document.createElement('span');
            label.className = 'event-timeline-tick-label'
                + (i === 0               ? ' event-timeline-tick-label-start' : '')
                + (i === tickCount - 1   ? ' event-timeline-tick-label-end'   : '');
            label.textContent = formatTimelineDateUtc(tickTs);
            tick.appendChild(label);
            ticks.appendChild(tick);
        }

        markers.innerHTML = '';
        if (isFinite(_currentEventDateTs)) {
            var cm = document.createElement('span');
            cm.className = 'event-timeline-current-marker';
            cm.style.left = (range > 0 ? ((_currentEventDateTs - minTs) / range) * 100 : 50) + '%';
            cm.setAttribute('aria-hidden', 'true');
            markers.appendChild(cm);

            var cl = document.createElement('span');
            cl.className = 'event-timeline-current-label';
            cl.style.left = cm.style.left;
            cl.textContent = '★ ' + <?= json_encode(__('This Event')) ?>;
            cl.setAttribute('aria-hidden', 'true');
            markers.appendChild(cl);
        }
        items.forEach(function (item) {
            var mk = document.createElement('button');
            mk.type = 'button';
            mk.className = 'event-timeline-marker';
            mk.style.left = (range > 0 ? ((item.ts - minTs) / range) * 100 : 50) + '%';
            mk.title = (item.title || 'Event #' + item.id) + ' — ' + item.date;
            mk.setAttribute('data-event-id', item.id);
            markers.appendChild(mk);
        });

        if (rangeLabel) {
            var start = formatTimelineDateUtc(itemMinTs);
            var end   = formatTimelineDateUtc(maxTs);
            rangeLabel.textContent = start === end ? start : (start + ' → ' + end);
        }
        timeline.style.display = '';
    }

    /* ── fetch ─────────────────────────────────────────────── */
    function loadCorrelations() {
        if (_correlationData !== null || _correlationsLoading) return;
        _correlationsLoading = true;
        var loaderEl  = document.getElementById('correlations-loader');
        var contentEl = document.getElementById('correlations-content');
        var url = baseurl + '/correlations/eventCorrelations/' + eventId
                + '.json?include_attributes=1&include_org_names=1';

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

    /* ── process API response ──────────────────────────────── */
    function renderCorrelations(data) {
        _correlationData = data;
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

        var total   = Object.keys(eventDetails).length;
        var countEl = document.getElementById('sankey-count');
        if (countEl) {
            countEl.textContent = total === 0
                ? <?= json_encode(h(__('No correlations'))) ?>
                : total + ' ' + (total === 1
                    ? <?= json_encode(h(__('related event'))) ?>
                    : <?= json_encode(h(__('related events'))) ?>);
        }

        if (total === 0) {
            var stageEl = document.getElementById('sankey-stage');
            if (stageEl) {
                stageEl.style.display = '';
                stageEl.innerHTML =
                    '<div class="d-flex flex-column align-items-center text-muted pt-2 small">'
                    + '<i class="fas fa-link fa-2x mb-2 d-block opacity-50"></i>'
                    + <?= json_encode(h(__('No correlated events found.'))) ?>
                    + '</div>';
            }
            return;
        }

        renderCorrelationsTimeline(eventDetails);
        renderSankey(data, eventDetails, null, {});
        renderCorrelationsList(eventDetails, eventCounts, attributeMap);
        _registerToggleListeners();
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
            var count   = eventCounts[eid]  || 0;
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

            /* event link row */
            var link = document.createElement('a');
            link.href = baseurl + '/events/view2/' + eid;
            link.className =
                'd-flex align-items-start gap-3 px-3 py-2'
                + ' text-decoration-none text-dark corr-event-row';

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
            attrsEl.className = 'px-3 pb-2 pt-1 d-flex flex-column gap-1';

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

                attrsEl.appendChild(row);
            });

            card.appendChild(link);
            card.appendChild(attrsEl);
            bodyEl.appendChild(card);
        });

        listEl.style.display = '';
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
        });
    }

    function escapeHtml(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /* ── toggle listeners (once) ───────────────────────────── */
    function _registerToggleListeners() {
        if (_sankeyListenersReady) return;
        _sankeyListenersReady = true;

        document.getElementById('sankey-date-align').addEventListener('change', function () {
            updateTargetPositionsOnly(true);
        });
        document.getElementById('sankey-latest-events').addEventListener('change', function () {
            if (_correlationData && _correlationEventDetails) {
                renderSankey(_correlationData, _correlationEventDetails, null, {animateToggle: true});
            }
        });
        document.getElementById('sankey-show-publisher').addEventListener('change', function () {
            if (_correlationData && _correlationEventDetails) {
                renderSankey(_correlationData, _correlationEventDetails, null, {animateToggle: true});
            }
        });
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
        var latestEventsOnly = document.getElementById('sankey-latest-events').checked;
        var showPublisher    = document.getElementById('sankey-show-publisher').checked;
        var latestEventsLimit = 20;

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

        var parentIds = filterAttributeId
            ? Object.keys(data).filter(function (id) { return id == filterAttributeId; })
            : Object.keys(data).sort(function (a, b) { return data[b].length - data[a].length; });

        if (!filterAttributeId && parentIds.length > 100) {
            parentIds = parentIds.slice(0, 100);
        }

        var allowedTargetEventIds = null;
        if (latestEventsOnly) {
            var latestTargetEvents = [];
            var seen = {};
            parentIds.forEach(function (pid) {
                (data[pid] || []).forEach(function (rel) {
                    if (seen[rel.id]) return;
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
                eventLinkCounts[rel.id] = (eventLinkCounts[rel.id] || 0) + 1;
            });
        });

        parentIds.forEach(function (pid) {
            var relations = data[pid] || [];
            var filtered  = relations.filter(function (rel) {
                if (allowedTargetEventIds && !allowedTargetEventIds[String(rel.id)]) return false;
                if (filterOrgId) {
                    var relOrgId = rel.org_id || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].org) || 'unknown';
                    return String(relOrgId) === String(filterOrgId);
                }
                return true;
            });
            if (!filtered.length) return;

            var attrValue = (relations[0] && relations[0].value) ? relations[0].value : ('Attr #' + pid);
            var attrIdx   = addNode(attrValue, 'attribute', pid);
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

        if (links.length === 0) return;
        if (sankeyStageEl) sankeyStageEl.style.display = '';

        /* ── layout helpers (hoisted) ─────────────────────── */
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
            return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0');
        }
        function truncateSourceLabel(name) {
            return name.length > 30 ? name.substring(0, 30) + '...' : name;
        }
        function estimateLabelWidth(chars, charW, minW, maxW) {
            return Math.max(minW, Math.min(maxW, chars * charW));
        }

        /* ── sizing ───────────────────────────────────────── */
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

        var displayedAttrCount   = nodes.filter(function (n) { return n.type === 'attribute'; }).length;
        var displayedTargetCount = nodes.filter(function (n) { return n.type === 'target'; }).length;
        var estimatedRows = Math.max(displayedAttrCount, displayedTargetCount);
        var height = Math.max(280, Math.min(1800, 110 + (estimatedRows * 22)));

        if (sankeyEl) {
            sankeyEl.style.height  = height + 'px';
            sankeyEl.style.opacity = options.animateToggle ? '0.18' : '1';
        }
        height = height - margin.top - margin.bottom;

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

        var hasSpreadableDates = isFinite(targetDateExtents.min) && isFinite(targetDateExtents.max) && targetDateExtents.max > targetDateExtents.min;
        var sankeyDomainMinTs = targetDateExtents.min, sankeyDomainMaxTs = targetDateExtents.max;
        if (isFinite(currentEventDateTs)) {
            sankeyDomainMinTs = isFinite(sankeyDomainMinTs) ? Math.min(sankeyDomainMinTs, currentEventDateTs) : currentEventDateTs;
            sankeyDomainMaxTs = isFinite(sankeyDomainMaxTs) ? Math.max(sankeyDomainMaxTs, currentEventDateTs) : currentEventDateTs;
        }
        var useYearScale = isFinite(sankeyDomainMinTs) && isFinite(sankeyDomainMaxTs)
            && new Date(sankeyDomainMinTs).getUTCFullYear() !== new Date(sankeyDomainMaxTs).getUTCFullYear();
        var sankeyScaleMinTs = isFinite(sankeyDomainMinTs) ? (useYearScale ? startOfUtcYear(sankeyDomainMinTs) : startOfUtcMonth(sankeyDomainMinTs)) : sankeyDomainMinTs;
        var sankeyScaleMaxTs = isFinite(sankeyDomainMaxTs) ? (useYearScale ? addUtcYears(startOfUtcYear(sankeyDomainMaxTs), 1) : addUtcMonths(startOfUtcMonth(sankeyDomainMaxTs), 1)) : sankeyDomainMaxTs;

        var rightLabelPadding = showPublisher ? 16 : 10;
        var orgLabelReserve   = showPublisher ? 260 : 28;
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
        var targetFixedX0 = Math.max(targetLaneStart, targetLaneEnd - Math.max(42, Math.floor(width * 0.035)));
        var orgLabelGap   = 18, targetLabelGap = 18, targetHoverPad = 14, orgLabelMaxLength = 34;

        if (targetNodes.length > 0 && targetLaneEnd > targetLaneStart) {
            targetNodes.forEach(function (node) {
                node.fixedX0 = targetFixedX0;
                node.fixedX1 = node.fixedX0 + sankeyNodeWidth;
                if (hasSpreadableDates && isFinite(node.eventDateTs)) {
                    var ratio = Math.max(0, Math.min(1, (node.eventDateTs - sankeyScaleMinTs) / Math.max(1, (sankeyScaleMaxTs - sankeyScaleMinTs))));
                    node.alignedX0 = Math.max(alignedLaneStart, Math.min(alignedLaneEnd - sankeyNodeWidth, alignedLaneStart + ((alignedLaneEnd - alignedLaneStart - sankeyNodeWidth) * ratio)));
                } else {
                    node.alignedX0 = alignedLaneStart + ((alignedLaneEnd - alignedLaneStart - sankeyNodeWidth) / 2);
                }
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

        /* ── timeline grid ────────────────────────────────── */
        var gridGroup = null;
        function buildSankeyGridTicks(minTs, maxTs, laneStart, laneEnd) {
            var laneWidth = laneEnd - laneStart;
            if (!isFinite(minTs) || !isFinite(maxTs) || laneWidth <= 0) return [];
            var yr = new Date(minTs).getUTCFullYear() !== new Date(maxTs).getUTCFullYear();
            if (maxTs <= minTs) return [{x: laneStart + laneWidth / 2, label: formatSankeyGridDate(minTs, yr ? 'year' : 'month'), isEdge: true}];
            var ticks = [], cursor = minTs, idx = 0;
            while (cursor <= maxTs) {
                var ratio = (cursor - minTs) / Math.max(1, (maxTs - minTs));
                ticks.push({x: laneStart + laneWidth * ratio, label: formatSankeyGridDate(cursor, yr ? 'year' : 'month'), isEdge: idx === 0});
                cursor = yr ? addUtcYears(cursor, 1) : addUtcMonths(cursor, 1);
                idx++;
            }
            if (ticks.length) ticks[ticks.length - 1].isEdge = true;
            var maxT = yr ? 7 : 8;
            if (ticks.length > maxT) {
                var interval = Math.ceil((ticks.length - 1) / (maxT - 1));
                var limited  = ticks.filter(function (t, i) { return i === 0 || i === ticks.length - 1 || (i % interval) === 0; });
                if (limited[limited.length - 1].x !== ticks[ticks.length - 1].x) limited.push(ticks[ticks.length - 1]);
                ticks = limited;
                ticks[0].isEdge = true;
                ticks[ticks.length - 1].isEdge = true;
            }
            return ticks;
        }

        if (targetNodes.length > 0 && targetLaneEnd > targetLaneStart && alignToDate) {
            var gridTicks  = buildSankeyGridTicks(sankeyScaleMinTs, sankeyScaleMaxTs, targetLaneStart, targetLaneEnd);
            var laneTop    = Math.max(0, d3.min(targetNodes, function (d) { return d.y0; }) - 12);
            var laneBottom = Math.min(height, d3.max(targetNodes, function (d) { return d.y1; }) + 8);
            var laneHeight = Math.max(0, laneBottom - laneTop);

            if (laneHeight > 0) {
                gridGroup = svg.append('g').attr('class', 'sankey-target-grid');
                var axisY  = laneTop - 28, tickTopY = axisY - 12;

                gridGroup.append('rect').attr('x', targetLaneStart).attr('y', laneTop)
                    .attr('width', targetLaneEnd - targetLaneStart).attr('height', laneHeight)
                    .attr('fill', 'rgba(84,142,94,.035)').attr('stroke', 'rgba(71,109,79,.12)').attr('stroke-width', 1);
                gridGroup.append('line').attr('x1', targetLaneStart).attr('x2', targetLaneEnd)
                    .attr('y1', axisY).attr('y2', axisY)
                    .attr('stroke', 'rgba(63,88,70,.34)').attr('stroke-width', 2).attr('shape-rendering', 'geometricPrecision');

                var tg = gridGroup.selectAll('g').data(gridTicks).enter().append('g').attr('class', 'sankey-target-grid-tick');
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

                if (isFinite(currentEventDateTs) && sankeyScaleMaxTs > sankeyScaleMinTs) {
                    var ceRatio = Math.max(0, Math.min(1, (currentEventDateTs - sankeyScaleMinTs) / Math.max(1, (sankeyScaleMaxTs - sankeyScaleMinTs))));
                    var ceX     = targetLaneStart + ((targetLaneEnd - targetLaneStart) * ceRatio);
                    var ceNW    = sankeyNodeWidth;
                    var ceNX    = Math.max(targetLaneStart, Math.min(targetLaneEnd - ceNW, ceX - ceNW / 2));
                    var ceNY    = laneTop - 18, ceNH = 16;
                    var ceCY    = ceNY + ceNH / 2, ceLX = ceNX + ceNW + targetLabelGap;
                    var mg = gridGroup.append('g').attr('class', 'sankey-current-event-marker');
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
            }
        }

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
            .on('mouseover', function (d) { applySankeyHoverState(d, 0.7); })
            .on('mouseout', resetSankeyHoverState);

        nodeGroup.append('rect')
            .attr('x', function (d) { return d.x0; }).attr('y', function (d) { return d.y0; })
            .attr('height', function (d) { return d.y1 - d.y0; }).attr('width', function (d) { return d.x1 - d.x0; })
            .attr('fill', sankeyNodeFill)
            .attr('cursor', function (d) { return isSankeyInteractiveNode(d) ? 'pointer' : 'default'; })
            .on('click', handleSankeyNodeClick)
            .on('mouseover', function (d) { applySankeyHoverState(d, 0.7); })
            .on('mouseout', resetSankeyHoverState)
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
            .on('mouseover', function (d) { applySankeyHoverState(d, 0.5); })
            .on('mouseout', resetSankeyHoverState)
            .text(function (d) {
                if (d.type === 'source') return '★ ' + truncateSourceLabel(d.name);
                var maxLen = d.type === 'target' ? 60 : (d.type === 'org' ? orgLabelMaxLength : 50);
                return d.name.length > maxLen ? d.name.substring(0, maxLen - 3) + '...' : d.name;
            });

        svg.append('g').attr('class', 'sankey-target-label-hitboxes')
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
            .on('mouseover', function (d) { applySankeyHoverState(d, 0.5); })
            .on('mouseout', resetSankeyHoverState)
            .append('title').text(function (d) { return d.fullTitle || d.name; });

        /* ── date-align animation (exposed to toggle listener) */
        updateTargetPositionsOnly = function (animate) {
            var dur = animate ? 450 : 0;
            var useDate = document.getElementById('sankey-date-align').checked;

            graph.nodes.forEach(function (node) {
                if (node.type !== 'target') return;
                node.x0 = useDate ? node.alignedX0 : node.fixedX0;
                node.x1 = node.x0 + sankeyNodeWidth;
            });

            nodeGroup.filter(function (d) { return d.type === 'target'; })
                .selectAll('rect:not(.sankey-target-hitbox)').transition().duration(dur)
                .attr('x', function (d) { return d.x0; }).attr('width', function (d) { return d.x1 - d.x0; });

            nodeGroup.filter(function (d) { return d.type === 'target'; })
                .select('.sankey-target-hitbox').transition().duration(dur)
                .attr('x', function (d) { return Math.max(targetLaneStart - 4, d.x0 - targetHoverPad); })
                .attr('width', function (d) { return Math.max((d.x1 - d.x0) + targetHoverPad + targetLabelGap + 8, 42); });

            link.transition().duration(dur).attr('d', function (d) {
                var x0 = d.source.x1, x1 = d.target.x0, xi = d3.interpolateNumber(x0, x1), x2 = xi(0.5), x3 = xi(0.5);
                return 'M' + x0 + ',' + d.y0 + 'C' + x2 + ',' + d.y0 + ' ' + x3 + ',' + d.y1 + ' ' + x1 + ',' + d.y1;
            });

            leaderLines.transition().duration(dur)
                .attr('x1', function (d) { return d.x1; })
                .attr('x2', function (d) { return d.x1 + targetLabelGap - 6; });

            labelSelection.filter(function (d) { return d.type === 'target'; }).transition().duration(dur)
                .attr('x', function (d) { return d.x1 + targetLabelGap; });

            if (gridGroup) {
                gridGroup.transition().duration(dur).style('opacity', useDate ? 1 : 0);
            }
        };

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
