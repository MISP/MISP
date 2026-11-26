/**
 * Event timeline for the Overmind event view (the Timeline tab).
 *
 * The stock theme's js/event-timeline.js without jQuery: the same endpoint
 * (events/getEventTimeline, scope `seen` or `sightings`) drawn by the same
 * vis.js Timeline, fetched on first open since vis.js weighs 700 KB. An item
 * sits on its first_seen..last_seen, or on its timestamp (dashed) when it has
 * no first_seen; whoever may modify the event drags it to set them.
 *
 *   <div data-event-timeline data-event-id="12" data-suffix="/extended:1"
 *        data-may-modify="1"> … [data-timeline-*] parts … </div>
 *
 * A card is initialised the first time its tab is shown (vis measures its
 * container), and reloads on misp:attributes-changed / misp:sighting-change.
 */
(function () {
    'use strict';

    var HARD_LIMIT = 500;
    var SOFT_LIMIT = 200;
    var HEIGHT = 440;
    var visLoading = null;

    function root() {
        return typeof baseurl !== 'undefined' ? baseurl : '';
    }

    function csrfToken() {
        return typeof getCsrfToken === 'function' ? getCsrfToken() : (window.csrfToken || '');
    }

    function loadVis() {
        if (window.vis && window.vis.Timeline) {
            return Promise.resolve(window.vis);
        }
        if (!visLoading) {
            var inject = function (tag, attrs) {
                return new Promise(function (resolve, reject) {
                    var el = document.createElement(tag);
                    Object.keys(attrs).forEach(function (key) { el[key] = attrs[key]; });
                    el.onload = resolve;
                    el.onerror = reject;
                    document.head.appendChild(el);
                });
            };
            visLoading = Promise.all([
                inject('link', { rel: 'stylesheet', href: root() + '/css/vis.css' }),
                inject('script', { src: root() + '/js/vis.js' })
            ]).then(function () {
                return window.vis;
            }, function (error) {
                visLoading = null;
                throw error;
            });
        }
        return visLoading;
    }

    /* The endpoint h()'s every value: decode once, then escape what is drawn,
       or the character limit would cut an entity in half. */
    var decoder = document.createElement('textarea');
    function decode(value) {
        decoder.innerHTML = value == null ? '' : String(value);
        return decoder.value;
    }
    function esc(value) {
        return String(value).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function clip(value, max) {
        return value.length > max ? value.slice(0, max) + '…' : value;
    }

    /* vis names the current scale ('day', 'minute'…); moment wants its unit. */
    function momentUnit(scale) {
        return { millisecond: 'ms', minute: 'm', month: 'M', week: 'w', weekday: 'd' }[scale] || scale.charAt(0);
    }

    function initEventTimeline(card) {
        if (card.dataset.timelineReady === '1') {
            return;
        }
        card.dataset.timelineReady = '1';

        var part = function (name) { return card.querySelector('[data-timeline-' + name + ']'); };
        var canvas = part('canvas');
        var loading = part('loading');
        var message = part('message');
        var summary = part('summary');
        var chartBox = part('chart');
        var selectionBox = part('selection');
        var searchSelect = part('search');
        var charsInput = part('chars');
        var charsValue = part('chars-value');
        var hideInput = part('hide-unseen');
        var localInput = part('local-time');
        var tzLabel = part('tz');
        var legendSeen = part('legend-seen');
        var legendSightings = part('legend-sightings');
        var hintsSeen = part('hints-seen');
        var searchBox = part('search-box');

        var eventId = card.dataset.eventId;
        var suffix = card.dataset.suffix || '';
        var mayModify = card.dataset.mayModify === '1';
        var t = JSON.parse(part('strings').textContent);

        var state = { scope: 'seen', maxChars: 64, hideUnseen: false, localTime: true, forced: false };
        var timeline = null;
        var dataset = null;
        var rows = [];
        var groups = [];
        var chart = null;
        var search = null;

        function setLoading(on) {
            loading.classList.toggle('d-none', !on);
        }

        function say(html, variant) {
            message.innerHTML = html
                ? '<div class="alert alert-' + variant + ' small d-flex align-items-center gap-2 m-3 mb-0">' + html + '</div>'
                : '';
        }

        function height() {
            if (document.fullscreenElement === card) {
                return Math.max(HEIGHT, card.clientHeight - canvas.getBoundingClientRect().top + card.getBoundingClientRect().top - 60);
            }
            return HEIGHT;
        }

        function fetchItems() {
            return fetch(root() + '/events/getEventTimeline/' + eventId + suffix + '/event.json', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': csrfToken()
                },
                body: JSON.stringify({ scope: state.scope })
            }).then(function (r) {
                if (!r.ok) {
                    throw new Error(r.status + ' ' + r.statusText);
                }
                return r.json();
            }).then(function (data) {
                return data.items || [];
            });
        }

        /* ── items ─────────────────────────────────────────────── */

        function seenItem(item) {
            var hasFirst = item.first_seen != null && item.first_seen !== '';
            var hasLast = item.last_seen != null && item.last_seen !== '';
            var overwrite = !!(item.first_seen_overwrite || item.last_seen_overwrite);
            var row = {
                id: item.uuid,
                origId: item.id,
                kind: item.group,
                label: decode(item.content),
                isImage: !!item.is_image,
                firstSeen: hasFirst ? item.first_seen : null,
                lastSeen: hasLast ? item.last_seen : null,
                seen: hasFirst,
                overwrite: overwrite,
                timestamp: item.timestamp,
                dates: { sightings: item.date_sighting || [] },
                attributes: (item.Attribute || []).map(function (attr) {
                    return {
                        id: attr.id,
                        relation: decode(attr.contentType),
                        value: decode(attr.content),
                        isImage: !!attr.is_image
                    };
                }),
                content: '',
                className: item.group + (hasFirst ? '' : ' ov-no-seen')
            };
            if (hasFirst) {
                row.start = vis.moment(item.first_seen);
                if (hasLast && !vis.moment(item.last_seen).isSame(row.start)) {
                    row.end = vis.moment(item.last_seen);
                    row.type = 'range';
                } else {
                    row.type = 'box';
                }
            } else {
                row.start = vis.moment(item.timestamp * 1000);
                row.type = 'box';
            }
            if (mayModify) {
                row.editable = { updateTime: true, updateGroup: false, remove: hasFirst && !overwrite };
            }
            return row;
        }

        function sightingRows(items) {
            var seenGroups = {};
            groups = [];
            rows = items.map(function (item, i) {
                var label = decode(item.content);
                if (!seenGroups[item.attribute_id]) {
                    seenGroups[item.attribute_id] = true;
                    groups.push({ id: item.attribute_id, content: esc(clip(label, state.maxChars)), label: label });
                }
                var positive = item.group === 'sighting_positive';
                return {
                    id: 's' + i,
                    group: item.attribute_id,
                    kind: item.group,
                    label: label,
                    start: vis.moment(item.first_seen),
                    end: vis.moment(item.last_seen),
                    type: 'range',
                    content: '',
                    className: item.group,
                    title: label + ' · ' + (positive ? t.positive : t.falsePositive)
                };
            });
        }

        function picture(id) {
            return '<img class="rounded-1 d-block" loading="lazy" width="80" height="80" alt=""'
                + ' src="' + esc(root() + '/attributes/viewPicture/' + id + '/1') + '">';
        }

        function template(item) {
            if (!item.kind || item.kind.indexOf('sighting') === 0) {
                return '';
            }
            var max = state.maxChars;
            if (item.kind === 'object') {
                var pictures = item.attributes.filter(function (a) { return a.isImage; });
                var html = '<div class="fw-semibold">' + esc(clip(item.label, max))
                    + (item.overwrite ? ' <i class="fas fa-bolt text-warning" title="' + esc(t.overwrite) + '"></i>' : '')
                    + '</div>';
                if (pictures.length) {
                    html += '<div class="d-flex gap-1 my-1">' + pictures.map(function (a) { return picture(a.id); }).join('') + '</div>';
                }
                html += '<table class="ov-tl-attrs">';
                item.attributes.forEach(function (attr) {
                    var seenAttr = item.overwrite && (attr.relation === 'first-seen' || attr.relation === 'last-seen');
                    html += '<tr><td class="fst-italic opacity-75 pe-2">' + esc(attr.relation) + '</td><td>'
                        + esc(clip(attr.value, max))
                        + (seenAttr ? ' <i class="fas fa-bolt text-warning"></i>' : '')
                        + '</td></tr>';
                });
                return html + '</table>';
            }
            if (item.isImage) {
                return picture(item.origId);
            }
            return esc(clip(item.label, max));
        }

        function visible() {
            return state.hideUnseen && state.scope === 'seen'
                ? rows.filter(function (row) { return row.seen; })
                : rows;
        }

        function options() {
            return {
                template: template,
                moment: function (date) {
                    return state.localTime ? vis.moment(date) : vis.moment(date).utc();
                },
                verticalScroll: true,
                zoomKey: 'altKey',
                minHeight: height(),
                maxHeight: height(),
                multiselect: true,
                selectable: state.scope === 'seen',
                editable: mayModify && state.scope === 'seen'
                    ? { add: false, updateTime: true, updateGroup: false, remove: true }
                    : false,
                tooltipOnItemUpdateTime: true,
                onMove: onMove,
                onRemove: onRemove
            };
        }

        function draw(fit) {
            chartBox.classList.add('d-none');
            canvas.classList.remove('d-none');
            searchBox.classList.remove('d-none');
            var groupSet = state.scope === 'sightings' ? new vis.DataSet(groups) : null;
            if (!timeline) {
                dataset = new vis.DataSet(visible());
                timeline = groupSet
                    ? new vis.Timeline(canvas, dataset, groupSet, options())
                    : new vis.Timeline(canvas, dataset, options());
                timeline.on('select', function (props) { showSelection(props.items); });
                timeline.on('doubleClick', function (props) {
                    if (props.item && state.scope === 'seen') {
                        edit(dataset.get(props.item));
                    }
                });
            } else {
                // A focus() still animating redraws items the clear has removed:
                // pin the window, which ends the animation, before emptying.
                var current = timeline.getWindow();
                timeline.setWindow(current.start, current.end, { animation: false });
                timeline.setSelection([]);
                timeline.setOptions(options());
                dataset.clear();
                timeline.setGroups(groupSet);
                dataset.add(visible());
            }
            showSelection([]);
            fillSearch();
            if (fit) {
                timeline.fit();
            }
        }

        /* ── the summary line, the search, the legend ──────────── */

        function summarise() {
            legendSeen.classList.toggle('d-none', state.scope !== 'seen');
            legendSightings.classList.toggle('d-none', state.scope !== 'sightings');
            hintsSeen.classList.toggle('d-none', state.scope !== 'seen');
            if (state.scope === 'sightings') {
                summary.textContent = rows.length
                    ? t.sightingSummary.replace('%s', rows.length).replace('%s', groups.length)
                    : t.noSightings;
                return;
            }
            var attributes = rows.filter(function (r) { return r.kind === 'attribute'; }).length;
            var unseen = rows.filter(function (r) { return !r.seen; }).length;
            summary.textContent = rows.length
                ? t.seenSummary.replace('%s', attributes).replace('%s', rows.length - attributes).replace('%s', unseen)
                : t.empty;
        }

        function fillSearch() {
            if (!search && window.TomSelect) {
                search = new TomSelect(searchSelect, {
                    maxOptions: 50,
                    placeholder: searchSelect.dataset.placeholder,
                    onChange: function (value) {
                        if (!value || !timeline) {
                            return;
                        }
                        var ids = state.scope === 'sightings'
                            ? dataset.getIds({ filter: function (row) { return String(row.group) === value; } })
                            : [value];
                        if (state.scope === 'seen') {
                            timeline.setSelection(ids);
                            showSelection(ids);
                        }
                        timeline.focus(ids);
                        search.clear(true);
                    }
                });
            }
            if (!search) {
                return;
            }
            search.clear(true);
            search.clearOptions();
            var options = [];
            if (state.scope === 'sightings') {
                groups.forEach(function (group) {
                    options.push({ value: String(group.id), text: group.label });
                });
            } else {
                visible().forEach(function (row) {
                    options.push({ value: row.id, text: row.label + ' (' + row.kind + ' #' + row.origId + ')' });
                    row.attributes.forEach(function (attr) {
                        options.push({ value: row.id, text: attr.relation + ': ' + attr.value + ' (object #' + row.origId + ')' });
                    });
                });
            }
            search.addOptions(options);
        }

        /* ── more than the timeline can draw ───────────────────── */

        function drawChart(items) {
            canvas.classList.add('d-none');
            chartBox.classList.remove('d-none');
            if (typeof Chart === 'undefined') {
                return;
            }
            var day = function (value) { return vis.moment(value).format('YYYY-MM-DD'); };
            var series = { timestamp: {}, first: {}, last: {}, sightings: {} };
            var bump = function (bucket, key) { bucket[key] = (bucket[key] || 0) + 1; };
            items.forEach(function (item) {
                if (item.timestamp) { bump(series.timestamp, day(item.timestamp * 1000)); }
                if (item.first_seen) { bump(series.first, day(item.first_seen)); }
                if (item.last_seen) { bump(series.last, day(item.last_seen)); }
                (item.date_sighting || []).forEach(function (s) { bump(series.sightings, day(s * 1000)); });
            });
            var labels = Object.keys(Object.assign({}, series.timestamp, series.first, series.last, series.sightings)).sort();
            var style = getComputedStyle(card);
            var colour = function (name) { return 'rgb(' + style.getPropertyValue('--bs-' + name + '-rgb').trim() + ')'; };
            var dataOf = function (bucket) { return labels.map(function (l) { return bucket[l] || 0; }); };
            if (chart) {
                chart.destroy();
            }
            chart = new Chart(chartBox.querySelector('canvas'), {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        { label: t.chartTimestamp, data: dataOf(series.timestamp), backgroundColor: colour('secondary') },
                        { label: t.chartFirst, data: dataOf(series.first), backgroundColor: colour('attribute') },
                        { label: t.chartLast, data: dataOf(series.last), backgroundColor: colour('object') },
                        { label: t.chartSightings, data: dataOf(series.sightings), type: 'line', borderColor: colour('sighting'), backgroundColor: colour('sighting') }
                    ]
                },
                options: {
                    maintainAspectRatio: false,
                    scales: { y: { type: 'logarithmic', ticks: { callback: function (v) { return Number.isInteger(v) ? v : ''; } } } }
                }
            });
        }

        /* ── loading ───────────────────────────────────────────── */

        function load(fit) {
            setLoading(true);
            say('', '');
            return Promise.all([loadVis(), fetchItems()]).then(function (results) {
                var items = results[1];
                if (state.scope === 'sightings') {
                    sightingRows(items);
                } else {
                    rows = items.map(seenItem);
                    groups = [];
                }
                summarise();
                searchBox.classList.add('d-none');
                if (items.length > HARD_LIMIT) {
                    say('<i class="fas fa-chart-column"></i>' + esc(t.tooMany.replace('%s', items.length)), 'warning');
                    drawChart(items);
                    return;
                }
                if (items.length > SOFT_LIMIT && !state.forced) {
                    say('<i class="fas fa-triangle-exclamation"></i><span class="me-auto">' + esc(t.many.replace('%s', items.length)) + '</span>'
                        + '<button type="button" class="btn btn-sm btn-outline-secondary" data-timeline-force>' + esc(t.drawAnyway) + '</button>', 'warning');
                    canvas.classList.add('d-none');
                    return;
                }
                draw(fit);
            }).catch(function (error) {
                say('<i class="fas fa-triangle-exclamation"></i>' + esc(t.failed + ' ' + error.message), 'danger');
            }).then(function () {
                setLoading(false);
            });
        }

        /* ── selection ─────────────────────────────────────────── */

        function format(value) {
            if (!value) {
                return '—';
            }
            var m = vis.moment(value);
            return (state.localTime ? m : m.utc()).format('YYYY-MM-DD HH:mm:ss Z');
        }

        function showSelection(ids) {
            if (!ids || ids.length !== 1 || state.scope !== 'seen') {
                selectionBox.classList.add('d-none');
                selectionBox.innerHTML = '';
                return;
            }
            var row = dataset.get(ids[0]);
            if (!row) {
                return;
            }
            var buttons = '<button type="button" class="btn btn-sm btn-outline-secondary" data-timeline-action="edit"><i class="fas fa-pen-to-square me-1"></i>' + esc(t.edit) + '</button>';
            if (mayModify && row.seen && !row.overwrite) {
                buttons += row.lastSeen
                    ? '<button type="button" class="btn btn-sm btn-outline-secondary" data-timeline-action="collapse"><i class="fas fa-down-left-and-up-right-to-center me-1"></i>' + esc(t.collapse) + '</button>'
                    : '<button type="button" class="btn btn-sm btn-outline-secondary" data-timeline-action="expand"><i class="fas fa-left-right me-1"></i>' + esc(t.expand) + '</button>';
            }
            selectionBox.dataset.item = row.id;
            selectionBox.innerHTML = '<div class="d-flex align-items-center gap-3 flex-wrap px-3 py-2 border-top small">'
                + '<span class="badge text-bg-light border text-uppercase">' + esc(row.kind) + ' #' + esc(row.origId) + '</span>'
                + '<span class="fw-semibold text-truncate" style="max-width:24rem;">' + esc(row.label) + '</span>'
                + '<span class="text-body-secondary">' + esc(t.firstSeen) + ' <span class="text-body font-monospace">' + esc(format(row.firstSeen)) + '</span></span>'
                + '<span class="text-body-secondary">' + esc(t.lastSeen) + ' <span class="text-body font-monospace">' + esc(format(row.lastSeen)) + '</span></span>'
                + (row.seen ? '' : '<span class="text-warning-emphasis"><i class="fas fa-circle-info me-1"></i>' + esc(t.atTimestamp) + '</span>')
                + '<span class="ms-auto d-flex gap-2">' + buttons + '</span>'
                + '</div>';
            selectionBox.classList.remove('d-none');
        }

        function edit(row) {
            if (!row || typeof openModal !== 'function') {
                return;
            }
            openModal(root() + '/' + (row.kind === 'object' ? 'objects' : 'attributes') + '/edit/' + row.origId);
        }

        /* ── saving first/last seen ────────────────────────────── */

        /* The stock inline-edit pair: the field's small form carries the
           tokens, so it is fetched, filled and posted as it came. */
        function saveField(row, field, value) {
            var kind = row.kind === 'object' ? 'objects' : 'attributes';
            var headers = { 'X-Requested-With': 'XMLHttpRequest' };
            return fetch(root() + '/' + kind + '/fetchEditForm/' + row.origId + '/' + field, {
                credentials: 'same-origin',
                headers: headers
            }).then(function (r) {
                if (!r.ok) {
                    throw new Error(r.status + ' ' + r.statusText);
                }
                return r.text();
            }).then(function (html) {
                var form = new DOMParser().parseFromString(html, 'text/html').querySelector('form');
                var input = form && form.querySelector('input[name$="[' + field + ']"]');
                if (!input) {
                    throw new Error(t.noForm);
                }
                input.value = value;
                return fetch(form.getAttribute('action'), {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: headers,
                    body: new URLSearchParams(new FormData(form))
                });
            }).then(function (r) {
                return r.json();
            }).then(function (result) {
                var noChange = result.errors && result.errors.value === 'nochange';
                if (!result.saved && !noChange) {
                    throw new Error(typeof result.errors === 'string' ? result.errors : JSON.stringify(result.errors || result));
                }
            });
        }

        function saveAll(row, changes) {
            setLoading(true);
            return changes.reduce(function (chain, change) {
                return chain.then(function () { return saveField(row, change[0], change[1]); });
            }, Promise.resolve()).then(function () {
                if (typeof showToast === 'function') {
                    showToast(t.saved);
                }
                if (typeof notifyAttributesChanged === 'function') {
                    state.saving = true;
                    notifyAttributesChanged();
                    state.saving = false;
                }
            }, function (error) {
                if (typeof showToast === 'function') {
                    showToast(t.saveFailed + ' ' + error.message, 'danger');
                }
            }).then(function () {
                return load(false);
            });
        }

        function iso(value) {
            return vis.moment(value).toISOString();
        }

        function onMove(item, callback) {
            var row = rows.filter(function (r) { return r.id === item.id; })[0];
            if (!row) {
                callback(null);
                return;
            }
            var start = vis.moment(item.start);
            var end = item.end ? vis.moment(item.end) : null;
            var changes = [];
            if (!row.firstSeen || !vis.moment(row.firstSeen).isSame(start)) {
                changes.push(['first_seen', iso(start)]);
            }
            if (row.seen && row.lastSeen && end && !vis.moment(row.lastSeen).isSame(end)) {
                changes.push(['last_seen', iso(end)]);
            }
            callback(changes.length ? item : null);
            if (changes.length) {
                saveAll(row, changes);
            }
        }

        function onRemove(item, callback) {
            callback(null);
            var row = rows.filter(function (r) { return r.id === item.id; })[0];
            if (!row || !row.seen) {
                return;
            }
            var clear = function () {
                saveAll(row, [['first_seen', ''], ['last_seen', '']]);
            };
            if (typeof showConfirmModal === 'function') {
                showConfirmModal({
                    title: t.clearTitle,
                    body: esc(t.clearBody.replace('%s', clip(row.label, 80))),
                    confirmLabel: t.clearConfirm,
                    confirmClass: 'btn-danger',
                    onConfirm: clear
                });
            } else {
                clear();
            }
        }

        /* ── controls ──────────────────────────────────────────── */

        card.addEventListener('click', function (event) {
            if (event.target.closest('[data-timeline-force]')) {
                state.forced = true;
                load(true);
                return;
            }
            if (event.target.closest('[data-timeline-fit]')) {
                if (timeline) { timeline.fit(); }
                return;
            }
            if (event.target.closest('[data-timeline-fullscreen]')) {
                if (document.fullscreenElement === card) {
                    document.exitFullscreen();
                } else if (card.requestFullscreen) {
                    card.requestFullscreen();
                }
                return;
            }
            var action = event.target.closest('[data-timeline-action]');
            if (!action) {
                return;
            }
            var row = dataset && dataset.get(selectionBox.dataset.item);
            if (!row) {
                return;
            }
            var verb = action.getAttribute('data-timeline-action');
            if (verb === 'edit') {
                edit(row);
            } else if (verb === 'collapse') {
                saveAll(row, [['last_seen', '']]);
            } else if (verb === 'expand') {
                var unit = momentUnit(timeline.timeAxis.step.scale);
                saveAll(row, [['last_seen', iso(vis.moment(row.firstSeen).add(1, unit))]]);
            }
        });

        card.querySelectorAll('[data-timeline-scope]').forEach(function (radio) {
            radio.addEventListener('change', function () {
                if (radio.checked) {
                    state.scope = radio.value;
                    load(true);
                }
            });
        });

        charsInput.addEventListener('input', function () {
            charsValue.textContent = charsInput.value;
        });
        charsInput.addEventListener('change', function () {
            state.maxChars = parseInt(charsInput.value, 10) || 64;
            if (state.scope === 'sightings') {
                groups.forEach(function (group) { group.content = esc(clip(group.label, state.maxChars)); });
            }
            if (timeline) { draw(false); }
        });

        hideInput.addEventListener('change', function () {
            state.hideUnseen = hideInput.checked;
            if (timeline) { draw(true); }
        });

        localInput.addEventListener('change', function () {
            state.localTime = localInput.checked;
            if (timeline) { draw(false); }
        });

        document.addEventListener('fullscreenchange', function () {
            card.classList.toggle('rounded-0', document.fullscreenElement === card);
            if (timeline) {
                timeline.setOptions({ minHeight: height(), maxHeight: height() });
            }
        });

        document.addEventListener('misp:attributes-changed', function () {
            if (timeline && state.scope === 'seen' && !state.saving) { load(false); }
        });
        document.addEventListener('misp:sighting-change', function () {
            if (timeline && state.scope === 'sightings') { load(false); }
        });

        loadVis().then(function () {
            tzLabel.textContent = vis.moment().format('Z');
        }, function () {});
        load(true);
    }
    window.initEventTimeline = initEventTimeline;

    function initIn(scope) {
        (scope || document).querySelectorAll('[data-event-timeline]').forEach(function (card) {
            var pane = card.closest('.tab-pane');
            if (!pane || pane.classList.contains('active')) {
                initEventTimeline(card);
            }
        });
    }

    document.addEventListener('shown.bs.tab', function (event) {
        var target = event.target && event.target.getAttribute('href');
        var pane = target && target.charAt(0) === '#' ? document.querySelector(target) : null;
        if (pane) {
            initIn(pane);
        }
    });
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { initIn(); });
    } else {
        initIn();
    }
}());
