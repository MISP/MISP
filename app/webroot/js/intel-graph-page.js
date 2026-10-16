// An analyst graph's own page (AnalystGraphs/view.ctp): the graph mounted at
// full size through IntelGraph, the bar that says what is not saved yet, and
// the fork and settings dialogs.
//
// What a save keeps: positions and pins, nodes kept from a pivot, nodes
// removed, links hidden in this graph, and how the canvas is grouped. The
// canvas carries the same Save as the bar. Adds made from other pages are saved
// as they land and reach this page in place. A save on a version saved
// elsewhere since is refused (409); the bar offers to lay this canvas over
// the newer version, or to reload it.

(function () {
    'use strict';

    // assetLoader puts this script above the markup it reads.
    function start() {
        var config = JSON.parse(document.getElementById('ig-page-config').textContent);
        var graph = config.graph;
        var canEdit = !!config.canEdit;
        var handle = null;
        var saving = false;
        var conflict = null;
        var savedAt = graph.modified;
        var changes = {};

        function find(sel) { return document.querySelector(sel); }
        function el(tag, cls, text) {
            var e = document.createElement(tag);
            if (cls) e.className = cls;
            if (text != null) e.textContent = text;
            return e;
        }
        function icon(cls) {
            var i = el('i', cls);
            i.setAttribute('aria-hidden', 'true');
            return i;
        }
        function baseurl() { return (window.IntelGraphConfig && window.IntelGraphConfig.baseurl) || ''; }
        function message(err) {
            var body = err && err.body;
            if (body && body.errors) {
                if (typeof body.errors === 'string') return body.errors;
                var first = Object.keys(body.errors)[0];
                var v = body.errors[first];
                return Array.isArray(v) ? v[0] : String(v);
            }
            return (err && err.message) || 'error';
        }
        function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

        function ago(datetime) {
            // Analyst data stores its times in UTC, with no zone
            var iso = String(datetime).replace(' ', 'T');
            var t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + 'Z');
            if (isNaN(t)) return '';
            var s = Math.round((Date.now() - t) / 1000);
            if (s < 45) return 'just now';
            var m = Math.round(s / 60);
            if (m < 60) return m + ' min ago';
            var h = Math.round(m / 60);
            if (h < 48) return h + ' h ago';
            return new Date(t).toLocaleDateString();
        }

        /* ── the bar ───────────────────────────────────────────── */
        var statusEl = find('[data-ig-page-status]');
        var saveBtn = find('[data-ig-page-save]');
        var discardBtn = find('[data-ig-page-discard]');
        var keepBtn = find('[data-ig-page-keep]');
        var hiddenWrap = find('[data-ig-page-hidden-wrap]');
        var hiddenMenu = find('[data-ig-page-hidden-menu]');
        var conflictEl = find('[data-ig-page-conflict]');
        var sizeWrap = find('[data-ig-page-size-wrap]');
        var sizeToggle = find('[data-ig-page-size-toggle]');
        var sizeMenu = find('[data-ig-page-size-menu]');
        var size = null;
        var sizeTimer = null;

        var REASONS = {
            moved: 'moved', kept: 'kept from a pivot', removed: 'removed',
            hidden: 'links hidden', shown: 'links shown again', grouped: 'grouping changed',
            noted: 'notes changed'
        };

        function dirty() { return !!handle && handle.isDirty(); }

        function renderStatus() {
            statusEl.textContent = '';
            if (!handle) return;
            if (saving) {
                statusEl.appendChild(el('span', 'spinner-border spinner-border-sm me-1'));
                statusEl.appendChild(document.createTextNode('Saving…'));
            } else if (dirty() && canEdit) {
                statusEl.appendChild(icon('fas fa-circle text-warning me-1'));
                var what = Object.keys(changes).map(function (k) { return REASONS[k] || k; });
                statusEl.appendChild(el('strong', null, 'Not saved'));
                statusEl.appendChild(document.createTextNode(what.length ? ': ' + what.join(', ') + '.' : '.'));
            } else {
                statusEl.appendChild(icon('fas fa-check text-success me-1'));
                statusEl.appendChild(document.createTextNode('Saved ' + ago(savedAt) + ' · revision ' + handle.revision()));
            }
            if (dirty() && canEdit && tooLarge()) {
                statusEl.appendChild(el('div', 'text-danger', handle.kit().size.text(size) + '.'));
            }
            if (saveBtn) {
                saveBtn.disabled = saving || !dirty() || !!conflict || tooLarge();
                saveBtn.title = tooLarge() ? handle.kit().size.text(size) : '';
            }
            if (discardBtn) discardBtn.hidden = saving || !dirty();
        }

        /* ── the size of what a save would write ───────────────── */
        function tooLarge() { return !!size && size.state === 'over'; }

        function measureSoon() {
            if (sizeTimer) clearTimeout(sizeTimer);
            sizeTimer = setTimeout(function () {
                sizeTimer = null;
                measure();
            }, 500);
        }

        function limitBar(label, value, max, text) {
            var row = el('div', 'mb-2');
            var head = el('div', 'd-flex justify-content-between gap-2 small');
            head.appendChild(el('span', 'fw-semibold', label));
            head.appendChild(el('span', 'text-body-secondary', text));
            row.appendChild(head);
            var share = max ? value / max : 0;
            var track = el('div', 'progress');
            track.setAttribute('role', 'progressbar');
            track.setAttribute('aria-label', label);
            track.setAttribute('aria-valuemin', '0');
            track.setAttribute('aria-valuemax', String(max));
            track.setAttribute('aria-valuenow', String(value));
            var fill = el('div', 'progress-bar' + (share > 1 ? ' bg-danger' : share >= 0.75 ? ' bg-warning' : ''));
            fill.style.width = Math.min(100, share * 100) + '%';
            track.appendChild(fill);
            row.appendChild(track);
            return row;
        }

        // The viewer's own document only: what they would save, never the
        // stored size, which counts what they cannot see.
        function measure() {
            if (!handle || !sizeWrap) return;
            var kit = handle.kit().size;
            var limits = (window.IntelGraphConfig && window.IntelGraphConfig.limits) || null;
            var measured = handle.measure();
            size = kit.of(measured.document, limits);
            var groups = kit.largeGroups(handle.graph(), measured.sizes, size.bytes);
            sizeWrap.hidden = false;
            find('[data-ig-page-size-label]').textContent = kit.text(size);
            sizeToggle.className = 'btn btn-sm dropdown-toggle '
                + ({ near: 'btn-outline-warning', over: 'btn-outline-danger' }[size.state] || 'btn-outline-secondary');
            sizeMenu.textContent = '';
            var body = el('div', 'px-3 py-2');
            body.appendChild(limitBar('Nodes', size.nodes, size.limits.nodes,
                size.nodes.toLocaleString() + ' of ' + size.limits.nodes.toLocaleString()));
            body.appendChild(limitBar('Size', size.bytes, size.limits.bytes,
                '≈ ' + kit.formatBytes(size.bytes) + ' of ' + kit.formatBytes(size.limits.bytes)));
            if (size.limits.document_bytes && size.limits.bytes < size.limits.document_bytes) {
                body.appendChild(el('div', 'small text-body-secondary mb-2', 'This server takes a save of up to '
                    + kit.formatBytes(size.limits.bytes) + '; a graph can hold up to '
                    + kit.formatBytes(size.limits.document_bytes) + '.'));
            }
            body.appendChild(el('h6', 'dropdown-header px-0', groups.length ? 'Large groups' : 'No large group'));
            groups.forEach(function (gr) {
                var row = el('div', 'd-flex align-items-center gap-2 py-1');
                var text = el('div', 'small flex-grow-1 ig-page-size-group');
                text.appendChild(el('div', 'text-truncate', gr.label));
                text.appendChild(el('div', 'text-body-secondary text-truncate', (gr.via ? gr.via + ' · ' : '') + kit.groupLine(gr)));
                text.title = gr.label + (gr.via ? ' · ' + gr.via : '');
                row.appendChild(text);
                var show = el('button', 'btn btn-sm btn-outline-secondary py-0', 'Show');
                show.type = 'button';
                show.addEventListener('click', function () { kit.showGroup(handle.graph(), gr.info); });
                row.appendChild(show);
                body.appendChild(row);
            });
            sizeMenu.appendChild(body);
            renderStatus();
        }

        function renderPivoted() {
            var n = handle ? handle.pivoted().length : 0;
            keepBtn.hidden = !canEdit || !n;
            find('[data-ig-page-keep-label]').textContent = 'Keep ' + plural(n, 'pivoted-in node', 'pivoted-in nodes');
        }

        function nodeLabel(id) {
            var g = handle && handle.graph();
            var n = g && g.getMutableNode(id);
            var d = n && n.getData ? n.getData() : null;
            return (d && (d.label || d.value)) || id;
        }

        function renderHidden() {
            var list = handle ? handle.hiddenEdges() : [];
            hiddenWrap.hidden = !list.length;
            find('[data-ig-page-hidden-label]').textContent = plural(list.length, 'hidden link', 'hidden links');
            hiddenMenu.textContent = '';
            hiddenMenu.appendChild(el('h6', 'dropdown-header', 'Hidden in this graph'));
            list.forEach(function (e) {
                var row = el('div', 'd-flex align-items-center gap-2 px-3 py-1');
                row.setAttribute('data-ig-edge', e.id);
                var text = el('span', 'small text-truncate flex-grow-1');
                text.textContent = nodeLabel(e.from) + ' → ' + ((e.data && e.data.label) || e.data.kind || 'link') + ' → ' + nodeLabel(e.to);
                text.title = text.textContent;
                row.appendChild(text);
                if (canEdit) {
                    var show = el('button', 'btn btn-sm btn-outline-secondary py-0', 'Show');
                    show.type = 'button';
                    show.addEventListener('click', function () { handle.showEdge(e.id); });
                    row.appendChild(show);
                }
                hiddenMenu.appendChild(row);
            });
        }

        function render() {
            renderStatus();
            renderPivoted();
            renderHidden();
        }

        function onChange(h, reason) {
            if (reason && canEdit) changes[reason] = true;
            render();
            measureSoon();
        }

        /* ── saving ────────────────────────────────────────────── */
        function showConflict(revision) {
            conflict = { revision: revision };
            conflictEl.hidden = false;
            conflictEl.textContent = '';
            conflictEl.appendChild(el('strong', null, 'Not saved: this graph was saved elsewhere since it opened here'
                + (revision != null ? ' (it is now at revision ' + revision + ')' : '') + '. '));
            conflictEl.appendChild(document.createTextNode('Save your changes over that version — what it added is kept — or reload it and drop them.'));
            var acts = el('div', 'mt-2 d-flex gap-2');
            var over = el('button', 'btn btn-sm btn-danger', 'Save my changes over it');
            over.type = 'button';
            over.addEventListener('click', function () {
                over.disabled = true;
                handle.rebase().then(function () {
                    conflict = null;
                    conflictEl.hidden = true;
                    save();
                }, function (err) {
                    over.disabled = false;
                    conflictEl.appendChild(el('div', 'mt-1', 'Could not read the newer version: ' + message(err)));
                });
            });
            var reload = el('button', 'btn btn-sm btn-outline-danger', 'Reload the graph');
            reload.type = 'button';
            reload.addEventListener('click', function () { window.removeEventListener('beforeunload', guard); window.location.reload(); });
            acts.appendChild(over);
            acts.appendChild(reload);
            conflictEl.appendChild(acts);
            render();
        }

        // The page bar sits outside a fullscreen canvas: there, a failure is
        // also said on the canvas.
        function notifyCanvas(title, text) {
            var g = handle && handle.graph();
            if (document.fullscreenElement && g && g.notifier) g.notifier.warning(title, text);
        }

        // Resolves once settled, saved or not: the canvas pill waits on it.
        function save() {
            if (!handle || saving || tooLarge()) return Promise.resolve();
            saving = true;
            render();
            return handle.save().then(function (report) {
                saving = false;
                changes = {};
                savedAt = report.modified || savedAt;
                render();
                measureSoon();
            }, function (err) {
                saving = false;
                if (err && err.status === 409) {
                    showConflict(err.body && err.body.revision);
                    notifyCanvas('Not saved', 'This graph was saved elsewhere since it opened here.');
                    return;
                }
                render();
                statusEl.appendChild(el('div', 'text-danger', 'Not saved: ' + message(err)));
                notifyCanvas('Not saved', message(err));
            });
        }

        function saveFromBar() {
            save().then(function () { if (handle) handle.refreshControls(); });
        }

        function guard(e) {
            if (!dirty() || !canEdit) return;
            e.preventDefault();
            e.returnValue = '';
        }

        /* ── forking ───────────────────────────────────────────── */
        function modal(id) {
            var m = document.getElementById(id);
            return m && window.bootstrap ? window.bootstrap.Modal.getOrCreateInstance(m) : null;
        }

        window.igGraphPageFork = function () {
            var form = find('[data-ig-page-fork-form]');
            var list = form.querySelector('[data-ig-page-fork-targets]');
            var error = form.querySelector('[data-ig-page-fork-error]');
            form.querySelector('#ig-page-fork-name').value = graph.name;
            error.textContent = '';
            list.textContent = '';
            if (!config.forkTargets.length) {
                list.appendChild(el('p', 'small text-body-secondary', 'Your organisation has no collection to attach a fork to. Open the event, collection or galaxy cluster your copy should hang off, and fork the graph from its dock there.'));
            }
            config.forkTargets.forEach(function (t, i) {
                var wrap = el('div', 'form-check');
                var input = el('input', 'form-check-input');
                input.type = 'radio';
                input.name = 'ig-fork-target';
                input.id = 'ig-fork-target-' + i;
                input.value = String(i);
                input.checked = i === 0;
                var label = el('label', 'form-check-label', (config.targetTypes[t.type] || t.type) + ' · ' + t.label);
                label.htmlFor = input.id;
                if (i === 0 && graph.target && t.uuid === graph.target.uuid) {
                    label.appendChild(el('span', 'badge text-bg-secondary ms-2', 'this graph’s'));
                }
                wrap.appendChild(input);
                wrap.appendChild(label);
                list.appendChild(wrap);
            });
            form.querySelector('[type="submit"]').disabled = !config.forkTargets.length;
            var m = modal('ig-page-fork');
            if (m) m.show();
        };

        function bindFork() {
            var form = find('[data-ig-page-fork-form]');
            if (!form) return;
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                var error = form.querySelector('[data-ig-page-fork-error]');
                var picked = form.querySelector('input[name="ig-fork-target"]:checked');
                var name = form.querySelector('#ig-page-fork-name').value.trim();
                if (!name) { error.textContent = 'A graph needs a name.'; return; }
                if (!picked) { error.textContent = 'Pick what the fork attaches to.'; return; }
                var t = config.forkTargets[+picked.value];
                var submit = form.querySelector('[type="submit"]');
                submit.disabled = true;
                window.IntelGraph.fork(graph.uuid, { name: name, target: { type: t.type, uuid: t.uuid } }).then(function (fork) {
                    window.removeEventListener('beforeunload', guard);
                    window.location.href = baseurl() + '/analyst_graphs/view/' + encodeURIComponent(fork.uuid);
                }, function (err) {
                    submit.disabled = false;
                    error.textContent = 'Could not fork: ' + message(err);
                });
            });
        }

        /* ── settings ──────────────────────────────────────────── */
        function sharing() {
            return (config.explorer && config.explorer.analystSharing) || { levels: [], sharingGroups: [] };
        }

        window.igGraphPageSettings = function () {
            var form = find('[data-ig-page-settings-form]');
            form.querySelector('#ig-page-settings-name').value = graph.name;
            form.querySelector('#ig-page-settings-description').value = graph.description || '';
            var dist = form.querySelector('#ig-page-settings-distribution');
            var sg = form.querySelector('#ig-page-settings-sg');
            dist.textContent = '';
            sharing().levels.forEach(function (l) {
                var o = el('option', null, l[1]);
                o.value = String(l[0]);
                o.selected = l[0] === graph.distribution;
                dist.appendChild(o);
            });
            sg.textContent = '';
            sharing().sharingGroups.forEach(function (g) {
                var o = el('option', null, g[1]);
                o.value = String(g[0]);
                o.selected = g[0] === graph.sharing_group_id;
                sg.appendChild(o);
            });
            sg.hidden = dist.value !== '4';
            form.querySelector('[data-ig-page-settings-error]').textContent = '';
            var m = modal('ig-page-settings');
            if (m) m.show();
        };

        function bindSettings() {
            var form = find('[data-ig-page-settings-form]');
            if (!form) return;
            var dist = form.querySelector('#ig-page-settings-distribution');
            var sg = form.querySelector('#ig-page-settings-sg');
            var error = form.querySelector('[data-ig-page-settings-error]');
            dist.addEventListener('change', function () { sg.hidden = dist.value !== '4'; });
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                var name = form.querySelector('#ig-page-settings-name').value.trim();
                if (!name) { error.textContent = 'A graph needs a name.'; return; }
                var body = { Graph: {
                    name: name,
                    description: form.querySelector('#ig-page-settings-description').value,
                    distribution: +dist.value,
                    sharing_group_id: dist.value === '4' ? +sg.value : null
                } };
                if (dist.value === '4' && !sg.value) { error.textContent = 'Pick the sharing group to share it with.'; return; }
                window.IntelGraph.request('POST', '/analystData/edit/Graph/' + graph.id + '.json', body).then(function () {
                    window.removeEventListener('beforeunload', guard);
                    window.location.reload();
                }, function (err) {
                    error.textContent = 'Not saved: ' + message(err);
                });
            });
            form.querySelector('[data-ig-page-delete]').addEventListener('click', function () {
                if (!window.confirm('Delete “' + graph.name + '”? The records it shows stay in MISP; the graph and its layout are gone, here and wherever it was shared.')) return;
                window.IntelGraph.request('POST', '/analystData/delete/Graph/' + graph.id + '.json', {}).then(function () {
                    window.removeEventListener('beforeunload', guard);
                    var t = graph.target;
                    window.location.href = baseurl() + (t && t.id ? config.targetPaths[t.type] + t.id : '/analystData/index/Graph');
                }, function (err) {
                    error.textContent = 'Not deleted: ' + message(err);
                });
            });
        }

        /* ── boot ──────────────────────────────────────────────── */
        function boot() {
            bindFork();
            bindSettings();
            if (saveBtn) saveBtn.addEventListener('click', saveFromBar);
            if (discardBtn) discardBtn.addEventListener('click', function () {
                window.removeEventListener('beforeunload', guard);
                window.location.reload();
            });
            keepBtn.addEventListener('click', function () { if (handle) handle.keep(handle.pivoted()); });
            window.addEventListener('beforeunload', guard);
            var container = document.getElementById('ig-page-graph');
            window.IntelGraph.mount(container, Object.assign({}, canEdit ? config.explorer : { labelPlan: config.explorer.labelPlan, permitted: config.explorer.permitted }, {
                graph: graph.uuid,
                loaderEl: document.getElementById('ig-page-loader'),
                cardEl: document.getElementById('ig-page-card'),
                fitHeight: true,
                menus: canEdit,
                saveControls: canEdit ? { save: save } : null,
                onChange: onChange
            })).then(function (h) {
                handle = h;
                window.IntelGraphPage = { handle: function () { return handle; }, save: save };
                return h.ready;
            }).then(function (h) {
                try {
                    h.graph().onVisibleChange(function () {
                        renderPivoted();
                        renderHidden();
                        measureSoon();
                    });
                } catch (e) { /* counted on edits only */ }
                render();
                measure();
            }).catch(function (err) {
                statusEl.textContent = 'The graph could not be drawn: ' + message(err);
            });
        }

        boot();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
}());
