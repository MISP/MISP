// IntelGraph — the workspace, and the way any page reaches saved graphs. The
// workspace is the collection "Add to workspace" feeds, with the graph of the
// user's organisation laying it out, or none. Loaded on every Overmind page
// that has the navbar's workspace slot (Elements/intel_graph_boot.ctp), so it
// stays small: the graph itself — Pivotick, the explorer and analyst-graph.js
// — loads on the first mount() only.
//
// window.IntelGraphConfig, read once at load:
//   baseurl    MISP $baseurl
//   user       the user's id: a switch made in another tab names it
//   active     the workspace, { Collection, Graph }, either null
//   page       the record on screen a graph can hang off, { type, uuid, label }, or null
//   shown      the uuid of the graph the page draws in full, or null
//   distributionLevels  DistributionLevel::all(), for badges drawn here
//   collectionTypes     [[type, label]], what a new collection can be
//   canSaveGraph        the user may save a graph
//   assets     { js: [{ global, url }], css: [{ path, url }] }, in load order
//   explorer   options handed to every mounted graph (labelPlan, orgUuid, …)
//   text       { none }
//   transport  optional: (method, path, body) → Promise<data>, replacing HTTP
//
// An item may carry a `label`, what it is called on screen; it stays here.
//
// Events, on document, each with the details in event.detail:
//   intel-graph:active   { workspace }                         the workspace changed, here or in another tab
//   intel-graph:count    { collection, element_count, state }  its member count moved; state
//                        { withheld, changes } says what partners lack yet
//   intel-graph:added    { collection, report, items, undo, origin }  addItems went through
//   intel-graph:refused  { collection, items, status, message } addItems was refused
//   intel-graph:removed  { collection, report, items }         removeItems went through
//   intel-graph:described { collection, key, description }     a member's why was said
//   intel-graph:saved    { graph, report }                     a graph was saved from this page
//   intel-graph:drawn    { graph, report, handle }             a mounted graph drew a save made elsewhere
//   intel-graph:pick     { items }                             an add with no workspace to go to
//   intel-graph:held     { collection, keys }                  what the workspace is known to hold moved;
//                        keys null when all of it was forgotten (a switch)
//   intel-graph:reveal   { keys, labels, items }               show these records in the dock

(function () {
    'use strict';

    var config = Object.assign({ baseurl: '', active: null, assets: {}, explorer: {}, text: {} },
                               window.IntelGraphConfig || {});
    var text = Object.assign({ none: 'No workspace' }, config.text);
    var active = usable(config.active);
    var dock = null;
    // What the workspace's collection is known to hold: key → true | false,
    // keys as addItems answers them (Type:address).
    var held = {};
    var heldOf = active ? lower(active.Collection.uuid) : null;
    var asking = {};
    // When an add or a removal last said where a key stands: an answer to
    // a question asked before then is stale for it.
    var clock = 0;
    var learnt = {};

    // { Collection, Graph } while there is a collection, else null.
    function usable(workspace) {
        return workspace && workspace.Collection ? { Collection: workspace.Collection, Graph: workspace.Graph || null } : null;
    }

    function lower(s) { return String(s || '').toLowerCase(); }

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

    function elementsPath(action, uuid) {
        return '/collection_elements/' + action + '/' + encodeURIComponent(uuid) + '.json';
    }

    function emit(name, detail) {
        document.dispatchEvent(new CustomEvent('intel-graph:' + name, { detail: detail }));
    }

    /* ── the navbar slot ───────────────────────────────────── */
    function renderSlot() {
        var c = active && active.Collection;
        document.querySelectorAll('[data-intel-graph-slot]').forEach(function (slot) {
            slot.setAttribute('data-state', c ? 'active' : 'none');
            var name = slot.querySelector('[data-intel-graph-name]');
            var count = slot.querySelector('[data-intel-graph-count]');
            if (name) name.textContent = c ? c.name : text.none;
            if (count) {
                count.textContent = c ? String(c.element_count) : '';
                count.hidden = !c;
            }
            var shared = slot.querySelector('[data-intel-graph-shared]');
            if (shared) {
                shared.hidden = !c || !c.distribution;
                shared.toggleAttribute('data-pending', !!(c && c.distribution && c.withheld));
            }
            var title = (c ? 'Workspace: ' + c.name + ' (collection)' + sharing(c) : text.none)
                + (dock && dock.shortcut ? ' — ' + dock.shortcut.toUpperCase() + ' shows or hides it' : '');
            slot.title = title;
            slot.querySelectorAll('[data-intel-graph-toggle]').forEach(function (b) {
                b.title = title;
                b.setAttribute('aria-label', c ? 'Workspace: ' + c.name + ' (collection), ' + c.element_count
                    + (c.element_count === 1 ? ' member' : ' members') : text.none);
                if (dock && dock.shortcut) b.setAttribute('aria-keyshortcuts', dock.shortcut.toUpperCase());
            });
        });
    }

    // What partners hold of a collection shared beyond the organisation.
    function sharing(c) {
        if (!c || !c.distribution) return '';
        if (!c.withheld) return ' · shared with partners';
        var n = c.changes ? c.changes.added + c.changes.removed : 0;
        var what = n ? n + (n === 1 ? ' change' : ' changes') : 'Changes';
        return ' · shared with partners once published: ' + (n ? what : what.toLowerCase())
            + (c._canPublish === false ? ' waiting for a publisher' : ' not yet published');
    }
    function publishState(c) {
        return c ? { withheld: !!c.withheld, changes: c.changes || null, published: !!c.published, last_published: c.last_published || null } : null;
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

    function setActiveState(workspace) {
        var was = active && lower(active.Collection.uuid);
        active = usable(workspace);
        renderSlot();
        if ((active && lower(active.Collection.uuid)) !== was) forgetHeld();
        emit('active', { workspace: active });
        return active;
    }

    // An add or a removal moved the workspace's member count.
    function touchCount(uuid, count, state) {
        if (!active || lower(active.Collection.uuid) !== lower(uuid) || typeof count !== 'number') return;
        active = { Collection: Object.assign({}, active.Collection, { element_count: count }, state || {}), Graph: active.Graph };
        renderSlot();
        emit('count', { collection: lower(uuid), element_count: count, state: state || null });
    }

    /* ── the other tabs of this browser ───────────────────── */
    // A switch or a new count reaches them as a message between tabs: no
    // polling, nothing asked of the server. One user's tabs only, so a tab
    // left open by someone who logged out ignores the next one's.
    var CHANNEL = 'misp-workspace';
    var channel = null;
    try {
        if (window.BroadcastChannel) channel = new window.BroadcastChannel(CHANNEL);
    } catch (e) { channel = null; }

    function broadcast(message) {
        message.user = config.user;
        if (channel) {
            try { channel.postMessage(message); } catch (e) { /* this tab only */ }
            return;
        }
        try {
            window.localStorage.setItem(CHANNEL, JSON.stringify(Object.assign({ sent: Date.now() + Math.random() }, message)));
        } catch (e) { /* this tab only */ }
    }

    function hear(message) {
        if (!message || config.user == null || message.user !== config.user) return;
        if (message.kind === 'active') setActiveState(message.workspace);
        else if (message.kind === 'count') touchCount(message.collection, message.element_count, message.state);
        else if (message.kind === 'held') moveHeld(message.collection, message['in'] || [], message.out || []);
    }

    if (channel) {
        channel.onmessage = function (e) { hear(e.data); };
    } else {
        window.addEventListener('storage', function (e) {
            if (e.key !== CHANNEL || !e.newValue) return;
            try { hear(JSON.parse(e.newValue)); } catch (err) { /* not ours */ }
        });
    }

    /* ── what the workspace holds ──────────────────────────── */
    // A record's key as addItems answers it; a value's is the SHA-256 of its
    // trimmed text, so it resolves later. Null for what cannot be a member.
    var valueKeys = {};
    var valueKeysDone = {};
    function keyOf(item) {
        if (!item || typeof item.type !== 'string') return Promise.resolve(null);
        if (item.type !== 'Value') return Promise.resolve(keyNow(item));
        if (item.sha256) return Promise.resolve(keyNow(item));
        var text = String(item.value == null ? '' : item.value).trim();
        if (!text || !(window.crypto && window.crypto.subtle && window.TextEncoder)) return Promise.resolve(null);
        if (!valueKeys[text]) {
            valueKeys[text] = window.crypto.subtle.digest('SHA-256', new window.TextEncoder().encode(text)).then(function (buf) {
                valueKeysDone[text] = 'Value:' + Array.prototype.map.call(new Uint8Array(buf), function (b) {
                    return ('0' + b.toString(16)).slice(-2);
                }).join('');
                return valueKeysDone[text];
            }, function () { return null; });
        }
        return valueKeys[text];
    }
    // The key when it needs no digest, or its digest is done; else null.
    function keyNow(item) {
        if (!item || typeof item.type !== 'string') return null;
        if (item.type !== 'Value') return item.uuid ? item.type + ':' + lower(item.uuid) : null;
        if (item.sha256) return 'Value:' + lower(item.sha256);
        return valueKeysDone[String(item.value == null ? '' : item.value).trim()] || null;
    }

    function forgetHeld() {
        held = {};
        asking = {};
        learnt = {};
        heldOf = active ? lower(active.Collection.uuid) : null;
        emit('held', { collection: heldOf, keys: null });
    }

    // Keys now known in or out of a collection; only the workspace's are
    // kept. askedAt: the clock when the lookup answering them was sent.
    function moveHeld(uuid, inKeys, outKeys, askedAt) {
        if (!heldOf || lower(uuid) !== heldOf) return [];
        var moved = [];
        [[inKeys, true], [outKeys, false]].forEach(function (pair) {
            (pair[0] || []).forEach(function (key) {
                if (askedAt !== undefined && (learnt[key] || 0) > askedAt) return;
                if (askedAt === undefined) learnt[key] = ++clock;
                if (held[key] !== pair[1]) moved.push(key);
                held[key] = pair[1];
            });
        });
        if (moved.length) emit('held', { collection: heldOf, keys: moved });
        return moved;
    }

    function shareHeld(uuid, inKeys, outKeys) {
        if (moveHeld(uuid, inKeys, outKeys).length) {
            broadcast({ kind: 'held', collection: lower(uuid), 'in': inKeys, out: outKeys });
        }
    }

    // true, false, or undefined while nobody asked.
    function holds(key) {
        return key ? held[key] : undefined;
    }

    // What the workspace now holds, learnt some other way than an add or a
    // removal made here.
    function markHeld(inKeys, outKeys) {
        if (heldOf) shareHeld(heldOf, inKeys || [], outKeys || []);
    }

    // Asks which of these records the workspace holds, those not known yet,
    // in as few requests as the server allows. Resolves when known.
    var LOOKUP_LIMIT = 2000;
    function lookup(items) {
        if (!heldOf) return Promise.resolve(null);
        var uuid = heldOf;
        return Promise.all((items || []).map(keyOf)).then(function (keys) {
            var ask = [];
            keys.forEach(function (key) {
                if (!key || key in held || asking[key]) return;
                asking[key] = true;
                ask.push(key);
            });
            var chunks = [];
            for (var i = 0; i < ask.length; i += LOOKUP_LIMIT) chunks.push(ask.slice(i, i + LOOKUP_LIMIT));
            var askedAt = clock;
            return Promise.all(chunks.map(function (chunk) {
                return request('POST', elementsPath('contains', uuid), { items: chunk }).then(function (out) {
                    chunk.forEach(function (k) { delete asking[k]; });
                    moveHeld(uuid, (out && out.present) || [], (out && out.absent) || [], askedAt);
                }, function () {
                    chunk.forEach(function (k) { delete asking[k]; });
                });
            }));
        });
    }

    // Opens the dock on these records.
    function reveal(items) {
        items = items || [];
        return Promise.all(items.map(keyOf)).then(function (keys) {
            var labels = {};
            keys.forEach(function (key, i) {
                if (key && (items[i].label || items[i].value)) {
                    labels[key] = { type: items[i].type, title: String(items[i].label || items[i].value), value: items[i].value };
                }
            });
            keys = keys.filter(Boolean);
            if (keys.length) emit('reveal', { keys: keys, labels: labels, items: items });
        });
    }

    /* ── the API ───────────────────────────────────────────── */
    function getActive() {
        return active;
    }

    function refreshActive() {
        return request('GET', '/collections/active.json').then(function (out) {
            return setActiveState(out);
        });
    }

    // Make a collection the workspace, laid out by graphUuid, one of the
    // organisation's graphs on it, or by none when it is null; left out, the
    // newest of them. A null collection ends it. Every other tab of the
    // browser follows.
    function setActive(collectionUuid, graphUuid) {
        var body = { collection_uuid: collectionUuid || null };
        if (graphUuid !== undefined) body.graph_uuid = graphUuid || null;
        return request('POST', '/collections/active.json', body).then(function (out) {
            var workspace = setActiveState(out);
            broadcast({ kind: 'active', workspace: workspace });
            return workspace;
        });
    }

    // { collections, active } — the collections the user may make their
    // workspace, those used last first (each carries `used`); with scope
    // 'mine', only those they created.
    function list(scope) {
        return request('GET', '/collections/editable.json' + (scope === 'mine' ? '?scope=mine' : '')).then(function (out) {
            return { collections: (out && out.Collection) || [], active: (out && out.active) || null };
        });
    }

    function countMoved(uuid, report) {
        if (!report || typeof report.element_count !== 'number') return;
        var state = publishState(report.Collection);
        touchCount(uuid, report.element_count, state);
        broadcast({ kind: 'count', collection: lower(uuid), element_count: report.element_count, state: state });
    }

    function removeFrom(uuid, items) {
        return request('POST', elementsPath('removeItems', uuid), { items: items }).then(function (report) {
            countMoved(uuid, report);
            shareHeld(uuid, [], (report.removed || []).concat(report.absent || []));
            emit('removed', { collection: lower(uuid), report: report, items: items });
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

    // Where on screen an add was made from, taken before the request: the
    // control may be gone by the time it answers.
    function originOf(o) {
        if (!o) return null;
        if (o.getBoundingClientRect) {
            var r = o.getBoundingClientRect();
            return r.width || r.height ? { x: r.left + r.width / 2, y: r.top + r.height / 2 } : null;
        }
        return typeof o.x === 'number' && typeof o.y === 'number' ? { x: o.x, y: o.y } : null;
    }

    // items: [{ type, uuid } | { type: 'Value', value }]. Resolves
    // { status: 'added' | 'unchanged' | 'no-workspace', collection, report,
    // undo }; a refusal rejects, after intel-graph:refused.
    // options.collection adds to that collection instead of the workspace.
    // options.origin, the element or { x, y } point the add was made from,
    // is where the dock draws it leaving from.
    function add(items, options) {
        var uuid = lower((options && options.collection) || (active && active.Collection.uuid));
        var origin = originOf(options && options.origin);
        if (!uuid) {
            emit('pick', { items: items });
            return Promise.resolve({ status: 'no-workspace', collection: null, report: null, undo: null });
        }
        return request('POST', elementsPath('addItems', uuid), { items: items.map(bare) }).then(function (report) {
            var added = report.added || [];
            var undo = added.length ? undoOnce(uuid, added) : null;
            countMoved(uuid, report);
            shareHeld(uuid, added.concat(report.present || []), []);
            emit('added', { collection: uuid, report: report, items: items, undo: undo, origin: origin });
            return {
                status: report.changed ? 'added' : 'unchanged',
                collection: uuid,
                report: report,
                undo: undo
            };
        }, function (err) {
            emit('refused', { collection: uuid, items: items, status: err && err.status, message: err && err.message });
            throw err;
        });
    }

    // Takes records (items as add() takes them, or their keys) out of the
    // workspace, or out of options.collection.
    function remove(items, options) {
        var uuid = lower((options && options.collection) || (active && active.Collection.uuid));
        if (!uuid) return Promise.reject(new Error('There is no workspace to remove it from.'));
        return removeFrom(uuid, (items || []).map(function (item) { return typeof item === 'string' ? item : bare(item); }));
    }

    // Says why the workspace, or options.collection, holds a record (an item
    // as add() takes it, or its key): one line, '' to clear it.
    function describe(item, text, options) {
        var uuid = lower((options && options.collection) || (active && active.Collection.uuid));
        if (!uuid) return Promise.reject(new Error('There is no workspace holding it.'));
        return request('POST', elementsPath('describe', uuid), { item: typeof item === 'string' ? item : bare(item), description: text }).then(function (report) {
            countMoved(uuid, report);
            emit('described', { collection: uuid, key: report.key, description: report.description });
            return report;
        });
    }

    // collection: { name, type?, distribution?, sharing_group_id?,
    // description? }, research and for the organisation only unless it says
    // otherwise. options.activate (default true) makes it the workspace.
    // options.items, as add() takes them, join it in the same request: the
    // collection resolved then carries the add's `report`, announced as an
    // add is (options.origin as add() takes it).
    function createCollection(collection, options) {
        var activate = !(options && options.activate === false);
        var items = (options && options.items) || [];
        var body = {
            name: collection.name,
            type: collection.type || 'research',
            distribution: collection.distribution == null ? 0 : collection.distribution,
            sharing_group_id: collection.sharing_group_id || null,
            description: collection.description || '',
            workspace: activate
        };
        if (items.length) body.items = items.map(bare);
        var origin = originOf(options && options.origin);
        return request('POST', '/collections/quickAdd.json', body).then(function (out) {
            var created = out && out.Collection;
            if (!created || !created.uuid) throw new Error('The collection was not created.');
            if (activate && out.workspace) {
                broadcast({ kind: 'active', workspace: setActiveState(out.workspace) });
            }
            if (out.report) {
                var uuid = lower(created.uuid);
                var report = Object.assign({ collection_uuid: created.uuid, element_count: created.element_count, Collection: created }, out.report);
                var added = report.added || [];
                countMoved(uuid, report);
                shareHeld(uuid, added.concat(report.present || []), []);
                emit('added', { collection: uuid, report: report, items: items, undo: added.length ? undoOnce(uuid, added) : null, origin: origin });
                created = Object.assign({}, created, { report: report });
            }
            return created;
        });
    }

    // graph: { name, description?, target: { type, uuid }, distribution?,
    // sharing_group_id?, content? }: content, a document, is the graph's
    // first revision. options.activate, on a graph kept on a collection,
    // makes that collection the workspace, laid out by the new graph.
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
            if (!created || !(options && options.activate) || target.type !== 'Collection') return created;
            return setActive(target.uuid, created.uuid).then(function () { return created; });
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

    // What the workspace draws of a collection: the graph's nodes, then
    // every member the graph lacks.
    function workingPath(collectionUuid, graphUuid) {
        return graphPath('working', collectionUuid) + (graphUuid ? '?graph=' + encodeURIComponent(graphUuid) : '');
    }

    // Resolves the save's report; a stale base rejects with err.status 409
    // and err.body.revision the stored one. A save that changed the graph is
    // announced, so a copy drawn elsewhere on the page follows it.
    function save(uuid, doc, revision) {
        return request('POST', graphPath('save', uuid), { content: doc, revision: revision }).then(function (report) {
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
    // options: { graph: uuid, source?, payload?, loaderEl?, … }, handed to
    // MispAnalystGraph.mount. Resolves its handle. A save of the mounted
    // graph made elsewhere on the page reaches it in place.
    function mount(containerEl, options) {
        return load().then(function () {
            var handle = window.MispAnalystGraph.mount(Object.assign({}, config.explorer, {
                containerEl: containerEl,
                baseurl: config.baseurl,
                request: request
            }, options));
            function onSaved(e) {
                if (!e.detail || e.detail.graph !== handle.uuid()) return;
                var report = e.detail.report;
                handle.adopt(report).then(function () {
                    emit('drawn', { graph: handle.uuid(), report: report, handle: handle });
                }, function () { /* never drawn: nothing to point at */ });
            }
            document.addEventListener('intel-graph:saved', onSaved);
            var destroy = handle.destroy;
            handle.destroy = function () {
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
        if (c && 'user' in c) config.user = c.user;
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
        collectionTypes: function () { return config.collectionTypes || []; },
        refreshActive: refreshActive,
        setActive: setActive,
        list: list,
        add: add,
        remove: remove,
        describe: describe,
        keyOf: keyOf,
        keyNow: keyNow,
        holds: holds,
        markHeld: markHeld,
        lookup: lookup,
        reveal: reveal,
        createCollection: createCollection,
        workingPath: workingPath,
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
