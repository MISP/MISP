// IntelGraph — the analyst graph "Add to graph" feeds, and the way any page
// reaches analyst graphs. Loaded on every Overmind page that has the navbar's
// graph slot (Elements/intel_graph_boot.ctp), so it stays small: the graph
// itself — Pivotick, the explorer and analyst-graph.js — loads on the first
// mount() only.
//
// window.IntelGraphConfig, read once at load:
//   baseurl    MISP $baseurl
//   active     the active graph's summary, or null
//   page       the record on screen a graph can hang off, { type, uuid, label }, or null
//   shown      the uuid of the graph the page draws in full, or null
//   distributionLevels  DistributionLevel::all(), for badges drawn here
//   assets     { js: [{ global, url }], css: [{ path, url }] }, in load order
//   explorer   options handed to every mounted graph (labelPlan, orgUuid, …)
//   text       { none }
//   transport  optional: (method, path, body) → Promise<data>, replacing HTTP
//
// An item may carry a `label`, what it is called on screen; it stays here.
//
// Events, on document, each with the details in event.detail:
//   intel-graph:active   { graph }                        the active graph changed
//   intel-graph:added    { graph, report, items, undo }   addNodes went through
//   intel-graph:refused  { graph, items, status, message } addNodes was refused
//   intel-graph:removed  { graph, report, items }         removeNodes went through
//   intel-graph:drawn    { graph, report, handle }        a mounted graph drew an add or a removal
//   intel-graph:pick     { items }                        an add with no graph to go to

(function () {
    'use strict';

    var config = Object.assign({ baseurl: '', active: null, assets: {}, explorer: {}, text: {} },
                               window.IntelGraphConfig || {});
    var text = Object.assign({ none: 'No graph' }, config.text);
    var active = config.active || null;
    var dock = null;

    /* ── requests ──────────────────────────────────────────── */
    function failure(status, body) {
        var err = new Error((body && (body.message || body.name)) || ('HTTP ' + status));
        err.status = status;
        err.body = body;
        return err;
    }

    function httpTransport(method, path, body) {
        return fetch(config.baseurl + path, {
            method: method,
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': window.csrfToken || ''
            },
            body: body === undefined ? undefined : JSON.stringify(body)
        }).then(function (r) {
            return r.text().then(function (raw) {
                var data = null;
                try { data = raw ? JSON.parse(raw) : null; } catch (e) { data = raw; }
                if (!r.ok) throw failure(r.status, data);
                return data;
            });
        });
    }

    function request(method, path, body) {
        return (config.transport || httpTransport)(method, path, body);
    }

    function graphPath(action, uuid) {
        return '/analyst_graphs/' + action + (uuid ? '/' + encodeURIComponent(uuid) : '') + '.json';
    }

    function emit(name, detail) {
        document.dispatchEvent(new CustomEvent('intel-graph:' + name, { detail: detail }));
    }

    /* ── the navbar slot ───────────────────────────────────── */
    function renderSlot() {
        document.querySelectorAll('[data-intel-graph-slot]').forEach(function (slot) {
            slot.setAttribute('data-state', active ? 'active' : 'none');
            var name = slot.querySelector('[data-intel-graph-name]');
            var count = slot.querySelector('[data-intel-graph-count]');
            if (name) name.textContent = active ? active.name : text.none;
            if (count) {
                count.textContent = active ? String(active.node_count) : '';
                count.hidden = !active;
            }
            var title = (active ? active.name + ' (' + active.node_count + ')' : text.none)
                + (dock && dock.shortcut ? ' — ' + dock.shortcut.toUpperCase() + ' shows or hides it' : '');
            slot.title = title;
            slot.querySelectorAll('[data-intel-graph-toggle]').forEach(function (b) {
                b.title = title;
                if (dock && dock.shortcut) b.setAttribute('aria-keyshortcuts', dock.shortcut.toUpperCase());
            });
        });
    }

    function bindSlot() {
        document.querySelectorAll('[data-intel-graph-toggle]').forEach(function (button) {
            button.addEventListener('click', function (e) {
                e.preventDefault();
                toggleDock();
            });
        });
        renderSlot();
    }

    function setActiveState(graph) {
        active = graph || null;
        renderSlot();
        emit('active', { graph: active });
        return active;
    }

    // An add or a removal moved the active graph's count and revision.
    function touchActive(uuid, report) {
        if (!active || active.uuid !== uuid || !report) return;
        active = Object.assign({}, active, { node_count: report.node_count, revision: report.revision });
        renderSlot();
    }

    /* ── the API ───────────────────────────────────────────── */
    function getActive() {
        return active;
    }

    function refreshActive() {
        return request('GET', graphPath('active')).then(function (out) {
            return setActiveState(out && out.Graph);
        });
    }

    function setActive(uuid) {
        return request('POST', graphPath('active'), { graph_uuid: uuid || null }).then(function (out) {
            return setActiveState(out && out.Graph);
        });
    }

    // { graphs, active } — the organisation's graphs the user may edit; with
    // scope 'mine', only those listing the user among their authors.
    function list(scope) {
        return request('GET', graphPath('editable') + (scope === 'mine' ? '?scope=mine' : '')).then(function (out) {
            return { graphs: (out && out.Graph) || [], active: (out && out.active) || null };
        });
    }

    function removeFrom(uuid, items) {
        return request('POST', graphPath('removeNodes', uuid), { items: items }).then(function (report) {
            touchActive(uuid, report);
            emit('removed', { graph: uuid, report: report, items: items });
            return report;
        });
    }

    function bare(item) {
        var out = {};
        Object.keys(item || {}).forEach(function (k) { if (k !== 'label') out[k] = item[k]; });
        return out;
    }

    // One undo per add, whoever calls it: a second call answers the first
    // one's promise.
    function undoOnce(uuid, added) {
        var done = null;
        return function () {
            if (!done) {
                done = removeFrom(uuid, added);
                done.catch(function () { done = null; });
            }
            return done;
        };
    }

    // items: [{ type, uuid } | { type: 'Value', value }]. Resolves
    // { status: 'added' | 'unchanged' | 'no-graph', graph, report, undo };
    // a refusal rejects, after intel-graph:refused.
    // options.graph adds to that graph instead of the active one.
    function add(items, options) {
        var uuid = (options && options.graph) || (active && active.uuid);
        if (!uuid) {
            emit('pick', { items: items });
            return Promise.resolve({ status: 'no-graph', graph: null, report: null, undo: null });
        }
        return request('POST', graphPath('addNodes', uuid), { items: items.map(bare) }).then(function (report) {
            var added = report.added || [];
            var undo = added.length ? undoOnce(uuid, added) : null;
            touchActive(uuid, report);
            emit('added', { graph: uuid, report: report, items: items, undo: undo });
            return {
                status: report.changed ? 'added' : 'unchanged',
                graph: uuid,
                report: report,
                undo: undo
            };
        }, function (err) {
            emit('refused', { graph: uuid, items: items, status: err && err.status, message: err && err.message });
            throw err;
        });
    }

    // graph: { name, description?, target: { type, uuid }, distribution?,
    // sharing_group_id?, content? }: content, a document, is the graph's
    // first revision. options.activate (default true) makes it the active
    // graph.
    function create(graph, options) {
        var target = graph.target || {};
        var body = { Graph: {
            name: graph.name,
            description: graph.description,
            distribution: graph.distribution,
            sharing_group_id: graph.sharing_group_id
        } };
        if (graph.content) body.Graph.content = graph.content;
        var path = '/analyst_data/add/Graph/' + encodeURIComponent(target.uuid) + '/' + encodeURIComponent(target.type) + '.json';
        return request('POST', path, body).then(function (out) {
            var created = out && out.Graph;
            if (!created || (options && options.activate === false)) return created;
            return setActive(created.uuid).then(function () { return created; });
        });
    }

    // options: { target: { type, uuid }, name }
    function fork(uuid, options) {
        return request('POST', graphPath('fork', uuid), options || {}).then(function (out) {
            return out && out.Graph;
        });
    }

    function data(uuid) {
        return request('GET', graphPath('data', uuid));
    }

    // Resolves the save's report; a stale base rejects with err.status 409
    // and err.body.revision the stored one. A save that changed the graph is
    // announced, so a copy drawn elsewhere on the page follows it.
    function save(uuid, doc, revision) {
        return request('POST', graphPath('save', uuid), { content: doc, revision: revision }).then(function (report) {
            touchActive(uuid, report);
            if (report && report.changed) emit('saved', { graph: uuid, report: report });
            return report;
        });
    }

    /* ── the lazy loader ───────────────────────────────────── */
    var _loading = null;

    function hasStylesheet(path) {
        return Array.prototype.some.call(document.querySelectorAll('link[rel="stylesheet"]'), function (l) {
            try { return new URL(l.href, window.location.href).pathname === path; } catch (e) { return false; }
        });
    }

    function loadStylesheet(asset) {
        if (hasStylesheet(asset.path)) return;
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = asset.url;
        document.head.appendChild(link);
    }

    // Inserted together with async off, so they run in list order while
    // they download side by side.
    function loadScript(asset) {
        if (window[asset.global]) return Promise.resolve();
        return new Promise(function (resolve, reject) {
            var script = document.createElement('script');
            script.src = asset.url;
            script.async = false;
            script.onload = function () { resolve(); };
            script.onerror = function () { reject(new Error('Failed to load ' + asset.url)); };
            document.head.appendChild(script);
        });
    }

    function load() {
        if (_loading) return _loading;
        (config.assets.css || []).forEach(loadStylesheet);
        _loading = Promise.all((config.assets.js || []).map(loadScript)).then(function () {
            if (!window.MispAnalystGraph) throw new Error('The graph host did not load.');
        });
        _loading.catch(function () { _loading = null; });
        return _loading;
    }

    /* ── mounting ──────────────────────────────────────────── */
    // options: { graph: uuid, payload?, loaderEl?, … }, handed to
    // MispAnalystGraph.mount. Resolves its handle. An add to the mounted
    // graph reaches it in place.
    function mount(containerEl, options) {
        return load().then(function () {
            var handle = window.MispAnalystGraph.mount(Object.assign({}, config.explorer, {
                containerEl: containerEl,
                baseurl: config.baseurl,
                request: request
            }, options));
            function onChange(e) {
                if (!e.detail || e.detail.graph !== handle.uuid()) return;
                var report = e.detail.report;
                handle.followed(report).then(function () {
                    emit('drawn', { graph: handle.uuid(), report: report, handle: handle });
                }, function () { /* never drawn: nothing to point at */ });
            }
            function onSaved(e) {
                if (!e.detail || e.detail.graph !== handle.uuid()) return;
                var report = e.detail.report;
                handle.adopt(report).then(function () {
                    emit('drawn', { graph: handle.uuid(), report: report, handle: handle });
                }, function () { /* never drawn: nothing to point at */ });
            }
            document.addEventListener('intel-graph:added', onChange);
            document.addEventListener('intel-graph:removed', onChange);
            document.addEventListener('intel-graph:saved', onSaved);
            var destroy = handle.destroy;
            handle.destroy = function () {
                document.removeEventListener('intel-graph:added', onChange);
                document.removeEventListener('intel-graph:removed', onChange);
                document.removeEventListener('intel-graph:saved', onSaved);
                destroy();
            };
            return handle;
        });
    }

    /* ── the dock seam ─────────────────────────────────────── */
    // dock: { toggle(), shortcut? }. Whatever registers last is the one the
    // slot opens; its shortcut is named in the slot's title.
    function registerDock(d) {
        dock = d;
        renderSlot();
    }

    function toggleDock() {
        if (dock && typeof dock.toggle === 'function') {
            dock.toggle();
        }
    }

    function on(name, fn) {
        var listener = function (e) { fn(e.detail); };
        document.addEventListener('intel-graph:' + name, listener);
        return function () { document.removeEventListener('intel-graph:' + name, listener); };
    }

    function configure(c) {
        Object.assign(config, c || {});
        if (c && c.text) text = Object.assign(text, c.text);
        if (c && 'active' in c) setActiveState(c.active);
    }

    function page() {
        return config.page || null;
    }

    /* ── thumbnails ────────────────────────────────────────── */
    // What a thumbnail draws of a graph for this user: { uuid, revision,
    // nodes: [{ key, type, x?, y?, pinned? }], edges: [[from, to, kind]], total }.
    // Kept for the page's life per uuid and revision, so pass the revision
    // the summary carries; a few at a time, so a long list does not queue
    // every request at once. IntelGraphThumb.layout() places it.
    var thumbs = {};
    var thumbQueue = [];
    var thumbsInFlight = 0;
    var THUMBS_AT_ONCE = 4;

    function nextThumb() {
        while (thumbsInFlight < THUMBS_AT_ONCE && thumbQueue.length) {
            var job = thumbQueue.shift();
            thumbsInFlight++;
            request('GET', graphPath('thumbnail', job.uuid)).then(job.resolve, job.reject).then(function () {
                thumbsInFlight--;
                nextThumb();
            });
        }
    }

    function thumbnail(uuid, revision) {
        var key = String(uuid).toLowerCase() + '@' + (revision === undefined ? '' : revision);
        if (!thumbs[key]) {
            thumbs[key] = new Promise(function (resolve, reject) {
                thumbQueue.push({ uuid: uuid, resolve: resolve, reject: reject });
                nextThumb();
            });
            thumbs[key].catch(function () { delete thumbs[key]; });
        }
        return thumbs[key];
    }

    // { label, sub, bg, color, icon } of a distribution level, or null.
    function distribution(level) {
        var levels = config.distributionLevels || {};
        return levels[level] || null;
    }

    window.IntelGraph = {
        active: getActive,
        page: page,
        distribution: distribution,
        refreshActive: refreshActive,
        setActive: setActive,
        list: list,
        add: add,
        create: create,
        fork: fork,
        data: data,
        thumbnail: thumbnail,
        save: save,
        load: load,
        mount: mount,
        registerDock: registerDock,
        toggleDock: toggleDock,
        on: on,
        configure: configure,
        request: request
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindSlot);
    } else {
        bindSlot();
    }
}());
