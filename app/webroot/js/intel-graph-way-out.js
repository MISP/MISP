/*
 * Ways out of the workspace: a selection of a collection made into an event,
 * or added to one, in a stepped dialog (what goes in, which event, review).
 * Its words come from the page's #ig-way-out-text block.
 *
 *   IntelGraphWayOut.open(mode, items, options)
 *     mode     'missing' | 'selection' | 'add'
 *     items    as IntelGraph.eventPlan takes them
 *     options  { collection, name, analysis, members, graph }: the collection's
 *              uuid, name, status and member count, and the graph laying it
 *              out (null when the user may not write it)
 */
(function () {
    'use strict';

    var IG = function () { return window.IntelGraph; };
    var NOT_TELLING = ['text', 'datetime', 'comment', 'float', 'port'];
    var ICON = { attribute: 'misp-icon-attribute', object: 'misp-icon-object', tag: 'misp-icon-galaxy', link: 'misp-icon-event' };

    var words = null;
    function text() {
        if (words) return words;
        var block = document.getElementById('ig-way-out-text');
        try { words = block ? JSON.parse(block.textContent) : {}; } catch (e) { words = {}; }
        return words;
    }
    function fill(s, args) {
        var i = 0;
        return String(s == null ? '' : s).replace(/%s/g, function () { var v = args[i++]; return v == null ? '' : String(v); });
    }
    function t(key) {
        var s = text()[key];
        if (Array.isArray(s)) s = s[0];
        return fill(s == null ? key : s, Array.prototype.slice.call(arguments, 1));
    }
    function tn(key, n) {
        var pair = text()[key];
        var s = Array.isArray(pair) ? pair[n === 1 ? 0 : 1] : pair;
        return fill(s == null ? key : s, [n].concat(Array.prototype.slice.call(arguments, 2)));
    }
    // The form for n, filled with the arguments after it (n itself not among them)
    function tp(key, n) {
        var pair = text()[key];
        var s = Array.isArray(pair) ? pair[n === 1 ? 0 : 1] : pair;
        return fill(s == null ? key : s, Array.prototype.slice.call(arguments, 2));
    }
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function baseurl() { return (window.IntelGraphConfig && window.IntelGraphConfig.baseurl) || ''; }
    function eventUrl(id) { return baseurl() + '/events/view/' + encodeURIComponent(id); }
    function lower(s) { return String(s == null ? '' : s).toLowerCase(); }

    function levelOf(level, group) {
        var d = IG().distribution(Number(level)) || { label: String(level) };
        return { label: Number(level) === 4 && group && group.name ? group.name : d.label, d: d };
    }
    function levelBadge(level, group) {
        var l = levelOf(level, group);
        var style = (l.d.bg ? 'background:' + l.d.bg + ';' : '') + (l.d.color ? 'color:' + l.d.color + ';' : '');
        return '<span class="badge igwo-level" style="' + esc(style) + '">'
            + (l.d.icon ? '<i class="' + esc(l.d.icon) + '" aria-hidden="true"></i> ' : '') + esc(l.label) + '</span>';
    }

    // What a row calls itself: a value's text, an object's name and telling value
    function labelOf(row) {
        if (row.kind === 'value' || row.kind === 'attribute' || (row.kind === 'answer' && row.becomes === 'attribute')) {
            return { main: row.value, mono: true };
        }
        if (row.kind === 'cluster') return { main: row.value, sub: row.galaxy };
        if (row.kind === 'event') return { main: row.info, sub: '#' + row.id };
        if (row.attributes) {
            var pick = row.attributes.filter(function (a) { return NOT_TELLING.indexOf(a.type) === -1; })[0] || row.attributes[0];
            return { main: row.name, sub: pick ? pick.value : '', subMono: true };
        }
        return { main: row.key || t('notARecord') };
    }
    function capLabel(row) {
        var r = row.source && row.source.reach;
        return r ? levelOf(r.distribution, r.sharing_group).label : '';
    }

    var current = null;

    function open(mode, items, options) {
        if (current) current.close();
        var o = options || {};
        var S = {
            mode: mode, items: items, plan: null, edits: {}, errors: {}, form: null,
            event: { info: o.name || '', date: '', distribution: 0, sharing_group_id: '', threat_level_id: 4, analysis: 0 },
            picked: null, choices: null, query: '', status: typeof o.analysis === 'number' ? o.analysis : null,
            done: null, busy: false, at: 0, seq: 0,
            order: mode === 'add' ? ['event', 'items', 'review'] : ['items', 'event', 'review']
        };
        S.statusWas = S.status;
        var el = document.createElement('div');
        el.className = 'modal fade igwo-modal';
        el.tabIndex = -1;
        el.setAttribute('aria-labelledby', 'igwo-title');
        el.innerHTML = '<div class="modal-dialog modal-xl modal-dialog-scrollable"><div class="modal-content" data-igwo-dialog="' + (mode === 'add' ? 'picking' : 'new') + '">'
            + '<div class="modal-header igwo-head"><div class="igwo-title"><span class="igwo-eyebrow">' + esc(t(mode === 'add' ? 'eyebrowAdd' : 'eyebrowCreate')) + '</span>'
            + '<h2 class="modal-title fs-5 mb-0" id="igwo-title" data-igwo="title"></h2></div>'
            + '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="' + esc(t('close')) + '"></button></div>'
            + '<nav class="igwo-stepper-wrap" aria-label="' + esc(t('steps')) + '"><ol class="igwo-stepper" data-igwo="stepper"></ol></nav>'
            + '<div class="modal-body igwo-body" data-igwo="body">'
            + '<section data-igwo-step="items" hidden></section><section data-igwo-step="event" hidden></section>'
            + '<section data-igwo-step="review" hidden></section><section data-igwo-step="done" hidden></section>'
            + '<div class="igwo-loading" data-igwo="loading">' + loader() + '</div></div>'
            + '<div class="modal-footer igwo-foot" data-igwo="foot"></div></div></div>';
        document.body.appendChild(el);
        var modal = new bootstrap.Modal(el);
        var api = { el: el, state: S, close: function () { modal.hide(); } };
        el.addEventListener('hidden.bs.modal', function () {
            modal.dispose();
            el.remove();
            if (current === api) current = null;
        });
        var content = el.querySelector('.modal-content');
        var $ = function (s) { return el.querySelector(s); };
        var section = function (n) { return el.querySelector('[data-igwo-step="' + n + '"]'); };

        function loader() {
            return '<div class="misp-loader" role="status"><span class="visually-hidden">' + esc(t('loading')) + '</span></div>';
        }
        function stepName() { return S.order[S.at]; }
        function reachable(i) {
            if (S.done) return false;
            var n = S.order[i];
            if (S.mode === 'add' && n !== 'event' && !S.picked) return false;
            return !!S.plan || n === 'event';
        }
        function going() {
            return S.plan ? S.plan.rows.filter(function (r) { return r.becomes; }) : [];
        }
        function rowOf(key) {
            return (S.plan ? S.plan.rows : []).filter(function (r) { return r.key === key; })[0] || null;
        }

        // The row an item became: a member by its key, an answer's value by its text
        function rowFor(it) {
            if (typeof it === 'string') return rowOf(it);
            if (!it || it.type !== 'Value' || !S.plan) return null;
            var text = IG().phpTrim(it.value == null ? '' : it.value);
            return S.plan.rows.filter(function (r) { return r.value === text && /^Value:/.test(r.key || ''); })[0] || null;
        }
        // The items as toEvent takes them, with what the value controls changed
        function itemsOut() {
            return S.items.map(function (it) {
                var row = rowFor(it);
                var e = row && S.edits[row.key];
                if (!e) return it;
                return typeof it === 'string' ? Object.assign({ key: it }, e) : Object.assign({}, it, e);
            });
        }
        function target() {
            if (S.mode === 'add') return { event_id: S.picked.id };
            var out = { distribution: Number(S.event.distribution) };
            if (out.distribution === 4 && S.event.sharing_group_id) out.sharing_group_id = Number(S.event.sharing_group_id);
            return out;
        }
        function ask(tgt) {
            return IG().eventPlan(S.items, tgt, { collection: o.collection });
        }
        function replan() {
            var seq = ++S.seq;
            return ask(target()).then(function (plan) {
                if (seq !== S.seq) return;
                S.plan = plan;
                if (plan.form) S.form = plan.form;
                renderItems();
                renderStepper();
                renderFoot();
                if (stepName() === 'review') renderReview();
            }, failed);
        }
        function failed(err) {
            var body = $('[data-igwo="loading"]');
            var message = '<div class="alert alert-danger m-0" data-igwo-error="plan">' + esc((err && err.message) || t('couldNotPlan')) + '</div>';
            if (body) body.outerHTML = message;
            else section(stepName()).insertAdjacentHTML('afterbegin', message);
        }

        /* ── head, stepper, foot ── */
        function renderTitle() {
            var n = S.items.length;
            $('[data-igwo="title"]').textContent = S.mode === 'add' ? tn('titleAdd', n) : tn('titleCreate', n);
        }
        function renderStepper() {
            var label = { items: t('stepItems'), event: t('stepEvent'), review: t('stepReview') };
            $('[data-igwo="stepper"]').innerHTML = S.order.map(function (n, i) {
                var cls = S.done ? 'is-done' : (i === S.at ? 'is-current' : (i < S.at ? 'is-done' : ''));
                var can = reachable(i) && i !== S.at;
                return '<li class="igwo-step ' + cls + '"' + (i === S.at && !S.done ? ' aria-current="step"' : '') + '>'
                    + '<button type="button" class="igwo-step-btn" data-igwo-go="' + i + '"' + (can ? '' : ' disabled') + '>'
                    + '<span class="igwo-step-num">' + (cls === 'is-done' ? '<i class="fas fa-check" aria-hidden="true"></i>' : (i + 1)) + '</span>'
                    + '<span class="igwo-step-label">' + esc(label[n]) + '</span></button></li>';
            }).join('<li class="igwo-step-bar" aria-hidden="true"></li>');
        }
        function renderFoot() {
            var foot = $('[data-igwo="foot"]');
            if (S.done) {
                foot.innerHTML = '<button type="button" class="btn btn-primary" data-bs-dismiss="modal">' + esc(t('close')) + '</button>';
                return;
            }
            var n = stepName();
            var last = S.at === S.order.length - 1;
            var go = going().length;
            var nextOff = S.busy || !S.plan && n !== 'event' || (n === 'items' && S.plan && !go) || (n === 'event' && S.mode === 'add' && !S.picked);
            var submit = S.mode === 'add' ? (S.picked ? t('submitAddTo', S.picked.id) : t('submitAdd')) : t('submitCreate');
            foot.innerHTML = '<button type="button" class="btn btn-link text-body-secondary me-auto" data-bs-dismiss="modal">' + esc(t('cancel')) + '</button>'
                + '<button type="button" class="btn btn-outline-secondary" data-igwo-back' + (S.at === 0 || S.busy ? ' disabled' : '') + '>'
                + '<i class="fas fa-arrow-left me-1" aria-hidden="true"></i>' + esc(t('back')) + '</button>'
                + (last
                    ? '<button type="button" class="btn btn-primary" data-igwo-submit' + (S.busy || !go ? ' disabled' : '') + '>'
                        + (S.busy ? '<span class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>' + esc(t('working'))
                            : '<i class="fas fa-calendar-plus me-1" aria-hidden="true"></i>' + esc(submit)) + '</button>'
                    : '<button type="button" class="btn btn-primary" data-igwo-next' + (nextOff ? ' disabled' : '') + '>'
                        + esc(t('next')) + '<i class="fas fa-arrow-right ms-1" aria-hidden="true"></i></button>');
        }
        function show(i) {
            S.at = i;
            var n = stepName();
            ['items', 'event', 'review'].forEach(function (s) { section(s).hidden = s !== n; });
            if (n === 'review') renderReview();
            renderStepper();
            renderFoot();
            $('[data-igwo="body"]').scrollTop = 0;
        }

        /* ── what goes in ── */
        function valueControls(row) {
            var e = S.edits[row.key] || {};
            var type = e.attribute_type || row.type;
            var info = (S.plan.type_info || {})[type] || { categories: [row.category], to_ids: row.to_ids };
            var cat = e.category || row.category;
            var cats = info.categories.indexOf(cat) === -1 ? [cat].concat(info.categories) : info.categories;
            var ids = e.to_ids !== undefined ? e.to_ids : row.to_ids;
            var id = 'igwo-' + Math.random().toString(36).slice(2, 8);
            return '<div class="igwo-controls">'
                + '<label class="igwo-ctl" for="' + id + 't"><span>' + esc(t('type')) + '</span>'
                + '<select id="' + id + 't" class="form-select form-select-sm font-monospace" data-igwo-type>'
                + (row.types || [type]).map(function (x) { return '<option' + (x === type ? ' selected' : '') + '>' + esc(x) + '</option>'; }).join('')
                + '</select></label>'
                + '<label class="igwo-ctl" for="' + id + 'c"><span>' + esc(t('category')) + '</span>'
                + '<select id="' + id + 'c" class="form-select form-select-sm" data-igwo-category>'
                + cats.map(function (c) { return '<option' + (c === cat ? ' selected' : '') + '>' + esc(c) + '</option>'; }).join('')
                + '</select></label>'
                + '<label class="igwo-ids form-check form-switch"><input type="checkbox" class="form-check-input" role="switch" data-igwo-ids'
                + (ids ? ' checked' : '') + '><span class="form-check-label">' + esc(t('forIds')) + '</span></label></div>';
        }
        function rowHtml(row) {
            var key = row.key ? ' data-igwo-row="' + esc(row.key) + '"' : '';
            var l = labelOf(row);
            var item = '<div class="igwo-item' + (l.mono ? ' font-monospace' : '') + '">' + esc(l.main)
                + (l.sub ? ' <small class="text-body-secondary' + (l.subMono ? ' font-monospace' : '') + '">' + esc(l.sub) + '</small>' : '') + '</div>';
            if (!row.becomes) {
                return '<li class="igwo-row is-out"' + key + '><div class="igwo-line"><span class="igwo-glyph"><i class="fas fa-ban" aria-hidden="true"></i></span>'
                    + '<div class="igwo-what">' + item + '<div class="igwo-note" data-igwo-left-out><strong>' + esc(t('leftOut')) + '</strong> ' + esc(row.reason || '') + '</div></div></div></li>';
            }
            var becomes = row.becomes === 'object' && row.template ? t('becomesObjectOf', row.template.name)
                : (row.becomes === 'link' ? t('becomesLink', row.relationship || 'related-to') : t('becomes_' + row.becomes));
            var tags = '<span class="badge igwo-becomes igwo-b-' + row.becomes + '" data-igwo-becomes>' + esc(becomes) + '</span>';
            if (row.gives_way) tags += '<span class="badge igwo-place" data-igwo-gives-way><i class="fas fa-right-left" aria-hidden="true"></i> ' + esc(t('givesWay')) + '</span>';
            if (row.joins) tags += '<span class="badge igwo-place" data-igwo-joins><i class="fas fa-plus" aria-hidden="true"></i> ' + esc(t('joins')) + '</span>';
            if (row.capped) tags += '<span class="badge igwo-cap" data-igwo-capped><i class="fas fa-lock" aria-hidden="true"></i> ' + esc(t('capped', capLabel(row))) + '</span>';
            var more = '';
            if ((row.kind === 'value' || row.kind === 'answer') && row.becomes === 'attribute') {
                more = valueControls(row);
            } else if (row.attributes && row.attributes.length) {
                more = '<ul class="igwo-attrs">' + row.attributes.slice(0, 3).map(function (a) {
                    return '<li><span class="text-body-secondary">' + esc(a.relation) + '</span> <span class="font-monospace">' + esc(a.value) + '</span></li>';
                }).join('') + (row.attributes.length > 3 ? '<li class="text-body-secondary">' + esc(t('more', row.attributes.length - 3)) + '</li>' : '') + '</ul>';
            }
            var src = row.source ? t('fromEvent', row.source.event.id, row.source.event.info)
                : (row.origin ? t('fromModule', row.origin.module, row.origin.value) : '');
            return '<li class="igwo-row"' + key + '><div class="igwo-line"><span class="igwo-glyph"><i class="misp-icon ' + ICON[row.becomes] + ' misp-simple" aria-hidden="true"></i></span>'
                + '<div class="igwo-what">' + item
                + (src ? '<div class="igwo-src text-truncate">' + esc(src) + '</div>' : '')
                + (row.why ? '<div class="igwo-src fst-italic">' + esc(row.why) + '</div>' : '') + more + '</div>'
                + '<div class="igwo-tags">' + tags + '</div></div></li>';
        }
        function intoBand() {
            if (S.mode === 'add') {
                if (!S.picked) return '';
                var e = S.picked;
                return '<div class="igwo-band"><i class="misp-icon misp-icon-event misp-simple" aria-hidden="true"></i><span class="text-truncate">'
                    + esc(t('intoEvent')) + ' <a href="' + esc(eventUrl(e.id)) + '" target="_blank" rel="noopener">#' + esc(e.id) + '</a> ' + esc(e.info) + '</span>'
                    + levelBadge(e.distribution, e.sharing_group) + '</div>';
            }
            return '<div class="igwo-band"><i class="misp-icon misp-icon-event misp-simple" aria-hidden="true"></i><span class="text-truncate">' + esc(t('intoNew')) + '</span>'
                + levelBadge(S.event.distribution, groupOf(S.event.sharing_group_id)) + '<span class="text-body-secondary ms-auto small">' + esc(t('capsFollow')) + '</span></div>';
        }
        function narrowerHtml() {
            var values = (S.plan.narrower || []).map(function (k) { var r = rowOf(k); return r ? r.value : null; }).filter(Boolean);
            if (!values.length) return '';
            return '<div class="alert alert-warning igwo-narrower" role="status" data-igwo-narrower><i class="fas fa-triangle-exclamation" aria-hidden="true"></i><div>'
                + '<strong>' + esc(tn('narrowerCount', values.length)) + '</strong> ' + esc(t('narrower'))
                + '<div class="igwo-vals">' + values.map(function (v) { return '<code>' + esc(v) + '</code>'; }).join('') + '</div></div></div>';
        }
        function renderItems() {
            var c = S.plan.counts || {};
            var bits = [];
            if (c.attribute) bits.push(tn('nAttributes', c.attribute));
            if (c.object) bits.push(tn('nObjects', c.object));
            if (c.tag) bits.push(tn('nTags', c.tag));
            if (c.link) bits.push(tn('nLinks', c.link));
            var sub = bits.length ? t('willBeMade', bits.join(', ')) : t('nothingGoes');
            if (c.left_out) sub += ' ' + tn('nLeftOut', c.left_out);
            section('items').innerHTML = '<div class="igwo-sec-head"><h3 class="igwo-h">' + esc(t('stepItems')) + '</h3><p class="igwo-sub">' + esc(sub) + '</p></div>'
                + intoBand() + narrowerHtml() + '<ol class="igwo-rows">' + S.plan.rows.map(rowHtml).join('') + '</ol>';
        }

        /* ── which event ── */
        function groupOf(id) {
            var groups = (S.form && S.form.sharing_groups) || {};
            return id && groups[id] ? { id: Number(id), name: groups[id] } : null;
        }
        function field(name, label, control) {
            var err = S.errors[name];
            return '<div class="igwo-field"><label class="igwo-label">' + label + '</label>' + control
                + (err ? '<div class="invalid-feedback d-block" data-igwo-error="' + esc(name) + '">' + esc(err) + '</div>' : '') + '</div>';
        }
        function optionList(list, selected) {
            return list.map(function (x) {
                return '<option value="' + esc(x[0]) + '"' + (String(x[0]) === String(selected) ? ' selected' : '') + '>' + esc(x[1]) + '</option>';
            }).join('');
        }
        function pairs(map) {
            return Array.isArray(map) ? map.map(function (v, i) { return [i, v]; }) : Object.keys(map || {}).map(function (k) { return [k, map[k]]; });
        }
        function renderEventNew() {
            var f = S.form || { distributions: {}, sharing_groups: {}, threat_levels: {}, analysis_levels: {} };
            var e = S.event, err = S.errors;
            var star = ' <span class="text-danger">*</span>';
            var invalid = function (n) { return err[n] ? ' is-invalid' : ''; };
            section('event').innerHTML = '<div class="igwo-sec-head"><h3 class="igwo-h">' + esc(t('stepEvent')) + '</h3><p class="igwo-sub">' + esc(t('newEventSub')) + '</p></div>'
                + '<div class="igwo-form">'
                + field('info', esc(t('fieldInfo')) + star, '<textarea class="form-control' + invalid('info') + '" rows="2" data-igwo-field="info">' + esc(e.info) + '</textarea>')
                + '<div class="igwo-grid">'
                + field('date', esc(t('fieldDate')) + star, '<input type="date" class="form-control' + invalid('date') + '" value="' + esc(e.date) + '" data-igwo-field="date">')
                + field('distribution', esc(t('fieldDistribution')), '<select class="form-select' + invalid('distribution') + '" data-igwo-field="distribution">'
                    + optionList(pairs(f.distributions), e.distribution) + '</select>')
                + (Number(e.distribution) === 4 ? field('sharing_group_id', esc(t('fieldGroup')), '<select class="form-select' + invalid('sharing_group_id') + '" data-igwo-field="sharing_group_id">'
                    + '<option value="">' + esc(t('pickGroup')) + '</option>' + optionList(pairs(f.sharing_groups), e.sharing_group_id) + '</select>') : '')
                + field('threat_level_id', esc(t('fieldThreat')), '<select class="form-select' + invalid('threat_level_id') + '" data-igwo-field="threat_level_id">'
                    + optionList(pairs(f.threat_levels), e.threat_level_id) + '</select>')
                + field('analysis', esc(t('fieldAnalysis')), '<select class="form-select' + invalid('analysis') + '" data-igwo-field="analysis">'
                    + optionList(pairs(f.analysis_levels), e.analysis) + '</select>')
                + '</div></div>';
        }
        function eventRow(ev) {
            var org = ev.Orgc && ev.Orgc.name;
            return '<button type="button" class="igwo-ev' + (S.picked && S.picked.id === ev.id ? ' is-picked' : '') + '" data-igwo-event="' + esc(ev.id) + '">'
                + '<span class="igwo-ev-main"><span class="igwo-ev-info">' + esc(ev.info) + '</span>'
                + '<span class="igwo-ev-meta"><span class="font-monospace">#' + esc(ev.id) + '</span><span>' + esc(ev.date) + '</span>' + (org ? '<span>' + esc(org) + '</span>' : '') + '</span></span>'
                + levelBadge(ev.distribution, ev.sharing_group) + '</button>';
        }
        function renderPicker() {
            var ch = S.choices;
            var html = '<div class="igwo-sec-head"><h3 class="igwo-h">' + esc(t('stepEvent')) + '</h3><p class="igwo-sub">' + esc(t('pickSub')) + '</p></div>'
                + '<div data-igwo-picker><div class="igwo-search"><i class="fas fa-magnifying-glass" aria-hidden="true"></i>'
                + '<input type="search" class="form-control" placeholder="' + esc(t('searchPlaceholder')) + '" value="' + esc(S.query) + '" data-igwo-search aria-label="' + esc(t('searchLabel')) + '"></div>';
            if (!ch) {
                html += '<div class="igwo-loading-inline">' + loader() + '</div>';
            } else {
                var tiedIds = ch.tied.map(function (e) { return e.id; });
                var found = ch.found.filter(function (e) { return tiedIds.indexOf(e.id) === -1; });
                if (ch.tied.length) html += '<h4 class="igwo-group">' + esc(t('inWorkspace')) + '</h4><div class="igwo-evs">' + ch.tied.map(eventRow).join('') + '</div>';
                if (found.length) html += '<h4 class="igwo-group">' + esc(t(S.query ? 'matching' : 'otherEvents')) + '</h4><div class="igwo-evs">' + found.map(eventRow).join('') + '</div>';
                if (!ch.tied.length && !found.length) html += '<p class="text-body-secondary mt-3">' + esc(t('noEvent')) + '</p>';
            }
            section('event').innerHTML = html + '</div>';
            return section('event').querySelector('[data-igwo-search]');
        }
        var searchSeq = 0;
        function search(q) {
            var seq = ++searchSeq;
            S.query = q;
            return IG().eventChoices(q, { collection: o.collection }).then(function (ch) {
                if (seq !== searchSeq) return;
                S.choices = ch;
                var had = document.activeElement && document.activeElement.hasAttribute && document.activeElement.hasAttribute('data-igwo-search');
                var input = renderPicker();
                if (had) {
                    input.focus();
                    input.setSelectionRange(input.value.length, input.value.length);
                }
            });
        }

        /* ── review ── */
        function andList(a) { return a.length < 2 ? a.join('') : a.slice(0, -1).join(', ') + ' ' + t('and') + ' ' + a[a.length - 1]; }
        // Made from every member: an investigation tends to end here
        function wholeCollection() {
            if (!o.members) return false;
            var members = S.items.filter(function (it) { var r = typeof it === 'string' ? rowOf(it) : null; return r && r.member; });
            return members.length >= o.members;
        }
        function renderReview() {
            var p = S.plan;
            if (!p) { section('review').innerHTML = ''; return; }
            var go = going();
            var by = function (b) { return go.filter(function (r) { return r.becomes === b; }).length; };
            var a = by('attribute'), ob = by('object'), tg = by('tag'), lk = by('link');
            var into = S.mode === 'add'
                ? t('intoEventShort', '<strong>#' + esc(S.picked.id) + '</strong> ' + esc(S.picked.info))
                : t('intoNewShort', '<strong>' + esc(levelOf(S.event.distribution, groupOf(S.event.sharing_group_id)).label) + '</strong>');
            var made = [];
            if (a) made.push(tn('nAttributes', a));
            if (ob) made.push(tn('nObjects', ob));
            var lines = [];
            if (made.length) lines.push(['fa-circle-plus', tp('reviewMade', a + ob, '<strong>' + esc(andList(made)) + '</strong>', into)]);
            if (tg) lines.push(['fa-tag', esc(tn('reviewTags', tg))]);
            if (lk) lines.push(['fa-link', esc(tn('reviewLinks', lk))]);
            var caps = {};
            go.forEach(function (r) { if (r.capped) { var c = capLabel(r); caps[c] = (caps[c] || 0) + 1; } });
            Object.keys(caps).forEach(function (c) { lines.push(['fa-lock', tn('reviewCapped', caps[c], '<strong>' + esc(c) + '</strong>')]); });
            var narrow = (p.narrower || []).length;
            if (narrow) lines.push(['fa-triangle-exclamation', esc(tn('reviewNarrower', narrow))]);
            var gw = go.filter(function (r) { return r.gives_way; }).length;
            var jn = go.filter(function (r) { return r.joins; }).length;
            if (gw) lines.push(['fa-right-left', esc(tn('reviewGivesWay', gw))]);
            if (jn) lines.push(['fa-plus', esc(tn('reviewJoins', jn))]);
            var out = p.rows.filter(function (r) { return !r.becomes; }).length;
            if (out) lines.push(['fa-ban', esc(tn('reviewLeftOut', out))]);
            if (!go.length) lines.push(['fa-ban', esc(t('nothingGoes'))]);

            var card = '';
            if (S.mode !== 'add') {
                var f = S.form || { threat_levels: {}, analysis_levels: {} };
                card = '<div class="igwo-card"><div class="igwo-card-head"><span class="igwo-card-title">' + esc(S.event.info) + '</span>'
                    + '<button type="button" class="btn btn-sm btn-link p-0" data-igwo-go="' + S.order.indexOf('event') + '">' + esc(t('edit')) + '</button></div>'
                    + '<div class="igwo-card-meta">' + levelBadge(S.event.distribution, groupOf(S.event.sharing_group_id)) + '<span>' + esc(S.event.date) + '</span>'
                    + '<span>' + esc(t('threat', (f.threat_levels || {})[S.event.threat_level_id] || '')) + '</span>'
                    + '<span>' + esc((f.analysis_levels || {})[S.event.analysis] || '') + '</span></div></div>';
            }
            var ongoing = '';
            if (S.mode !== 'add' && wholeCollection()) {
                ongoing = '<div class="igwo-ongoing" data-igwo-ongoing role="radiogroup" aria-labelledby="igwo-ongoing-q"><div class="igwo-ongoing-q" id="igwo-ongoing-q">' + esc(t('ongoing')) + '</div>'
                    + '<p class="igwo-sub mb-2">' + esc(t('ongoingSub')) + '</p><div class="btn-group" role="group">'
                    + ['statusInitial', 'statusOngoing', 'statusCompleted'].map(function (k, i) {
                        return '<input type="radio" class="btn-check" name="igwo-ongoing" id="igwo-on-' + i + '" value="' + i + '"' + (S.status === i ? ' checked' : '') + '>'
                            + '<label class="btn btn-outline-primary" for="igwo-on-' + i + '">' + esc(t(k)) + '</label>';
                    }).join('') + '</div></div>';
            }
            var itemsErr = S.errors.items ? '<div class="alert alert-danger" data-igwo-error="items">' + esc(S.errors.items) + '</div>' : '';
            section('review').innerHTML = '<div class="igwo-sec-head"><h3 class="igwo-h">' + esc(t('stepReview')) + '</h3><p class="igwo-sub">' + esc(t('reviewSub')) + '</p></div>'
                + itemsErr + card + '<ul class="igwo-sentences">'
                + lines.map(function (s) { return '<li><i class="fas ' + s[0] + '" aria-hidden="true"></i><span>' + s[1] + '</span></li>'; }).join('')
                + '</ul>' + ongoing;
        }

        /* ── done ── */
        function renderDone(report, statusFailed) {
            var bad = report.rows.filter(function (r) { return r.state === 'failed'; });
            var c = report.counts || {};
            var ev = report.event;
            section('done').innerHTML = '<div data-igwo-done class="igwo-done"><div class="igwo-done-head">'
                + '<span class="igwo-done-ico' + (bad.length ? ' is-warn' : '') + '"><i class="fas ' + (bad.length ? 'fa-triangle-exclamation' : 'fa-check') + '" aria-hidden="true"></i></span>'
                + '<div><div class="igwo-done-lead">' + esc(t(report.created ? 'doneMade' : 'doneAdded')) + ' <a href="' + esc(eventUrl(ev.id)) + '">' + esc(ev.info) + '</a>'
                + ' <span class="text-body-secondary font-monospace">#' + esc(ev.id) + '</span></div>'
                + '<ul class="igwo-done-list"><li>' + esc(tn('doneRecords', c.saved || 0)) + '</li>'
                + '<li>' + esc(tn('doneReplaced', c.replaced || 0)) + '</li>'
                + (c.existing ? '<li>' + esc(tn('doneExisting', c.existing)) + '</li>' : '') + '</ul></div></div>'
                + (bad.length ? '<div class="igwo-failed"><div class="igwo-failed-head">' + esc(tn('doneFailed', bad.length)) + '</div><ul>'
                    + bad.map(function (f) {
                        var l = labelOf(rowOf(f.key) || { key: f.key });
                        return '<li data-igwo-failed="' + esc(f.key) + '"><span class="igwo-item">' + esc(l.main) + (l.sub ? ' <small class="text-body-secondary">' + esc(l.sub) + '</small>' : '') + '</span>'
                            + '<span class="igwo-failmsg">' + esc(f.message || t('notSaved')) + '</span></li>';
                    }).join('') + '</ul></div>' : '')
                + (statusFailed ? '<div class="alert alert-warning mt-3">' + esc(t('statusFailed')) + '</div>' : '') + '</div>';
        }

        /* ── acting ── */
        function submit() {
            if (S.busy) return;
            S.busy = true;
            S.errors = {};
            renderFoot();
            var tgt = S.mode === 'add' ? { event_id: S.picked.id } : { event: {
                info: S.event.info, date: S.event.date, distribution: Number(S.event.distribution),
                threat_level_id: Number(S.event.threat_level_id), analysis: Number(S.event.analysis)
            } };
            if (tgt.event && tgt.event.distribution === 4) tgt.event.sharing_group_id = S.event.sharing_group_id ? Number(S.event.sharing_group_id) : null;
            IG().toEvent(itemsOut(), tgt, { collection: o.collection, graph: o.graph || null }).then(function (report) {
                var status = S.status !== null && S.status !== S.statusWas && wholeCollection()
                    ? IG().request('POST', '/collections/analysis/' + encodeURIComponent(o.collection) + '.json', { analysis: S.status })
                        .then(function () { return false; }, function () { return true; })
                    : Promise.resolve(false);
                return status.then(function (statusFailed) {
                    S.done = report;
                    S.busy = false;
                    renderDone(report, statusFailed);
                    ['items', 'event', 'review'].forEach(function (s) { section(s).hidden = true; });
                    section('done').hidden = false;
                    $('[data-igwo="body"]').scrollTop = 0;
                    renderStepper();
                    renderFoot();
                });
            }, function (err) {
                S.busy = false;
                var errs = (err && err.body && err.body.errors) || { items: (err && err.message) || t('notMade') };
                S.errors = errs;
                var onField = Object.keys(errs).some(function (k) { return k !== 'items'; });
                if (S.mode !== 'add' && onField) {
                    renderEventNew();
                    show(S.order.indexOf('event'));
                } else {
                    renderReview();
                    show(S.order.indexOf('review'));
                }
            });
        }
        function pick(id) {
            var ev = ((S.choices && S.choices.tied) || []).concat((S.choices && S.choices.found) || []).filter(function (e) { return e.id === id; })[0];
            if (!ev) return Promise.resolve();
            S.picked = ev;
            content.setAttribute('data-igwo-dialog', 'existing');
            return replan().then(function () { if (S.plan) show(S.order.indexOf('items')); });
        }

        el.addEventListener('click', function (e) {
            var go = e.target.closest('[data-igwo-go]');
            if (go) {
                var i = Number(go.getAttribute('data-igwo-go'));
                if (reachable(i)) show(i);
                return;
            }
            if (e.target.closest('[data-igwo-next]')) { show(S.at + 1); return; }
            if (e.target.closest('[data-igwo-back]')) { show(S.at - 1); return; }
            if (e.target.closest('[data-igwo-submit]')) { submit(); return; }
            var ev = e.target.closest('[data-igwo-event]');
            if (ev) pick(Number(ev.getAttribute('data-igwo-event')));
        });
        el.addEventListener('input', function (e) {
            var x = e.target;
            if (x.hasAttribute('data-igwo-search')) {
                clearTimeout(S.searchTimer);
                S.searchTimer = setTimeout(function () { search(x.value); }, 150);
                return;
            }
            var f = x.getAttribute && x.getAttribute('data-igwo-field');
            if (f === 'info' || f === 'date') {
                S.event[f] = x.value;
                delete S.errors[f];
            }
        });
        el.addEventListener('change', function (e) {
            var x = e.target;
            var f = x.getAttribute('data-igwo-field');
            if (f) {
                S.event[f] = x.value;
                delete S.errors[f];
                if (f === 'distribution' || f === 'sharing_group_id') {
                    if (f === 'distribution') renderEventNew();
                    replan();
                }
                return;
            }
            if (x.name === 'igwo-ongoing') { S.status = Number(x.value); return; }
            var row = x.closest('[data-igwo-row]');
            if (!row || !S.plan) return;
            var key = row.getAttribute('data-igwo-row');
            var ed = S.edits[key] = S.edits[key] || {};
            if (x.hasAttribute('data-igwo-type')) {
                ed.attribute_type = x.value;
                var info = (S.plan.type_info || {})[x.value];
                if (info) {
                    ed.category = info.categories[0];
                    ed.to_ids = !!info.to_ids;
                }
                var tmp = document.createElement('div');
                tmp.innerHTML = rowHtml(rowOf(key));
                row.replaceWith(tmp.firstChild);
            } else if (x.hasAttribute('data-igwo-category')) {
                ed.category = x.value;
            } else if (x.hasAttribute('data-igwo-ids')) {
                ed.to_ids = x.checked;
            }
        });

        renderTitle();
        // A new event is planned at the instance's default distribution; an add
        // waits for the event picked
        var first = mode === 'add'
            ? IG().eventChoices('', { collection: o.collection }).then(function (ch) { S.choices = ch; renderPicker(); })
            : ask({}).then(function (plan) {
                S.plan = plan;
                S.form = plan.form;
                var d = plan.form.defaults;
                S.event = { info: o.name || d.info, date: d.date, distribution: d.distribution, sharing_group_id: '', threat_level_id: d.threat_level_id, analysis: d.analysis };
                renderEventNew();
                renderItems();
            });
        api.ready = first.then(function () {
            var loading = $('[data-igwo="loading"]');
            if (loading) loading.remove();
            show(0);
        }, failed);
        current = api;
        modal.show();
        return api;
    }

    window.IntelGraphWayOut = { open: open };
}());
