// The Saved graphs card on a collection, an event or a galaxy cluster
// (Elements/AnalystGraphs/graphs_card.ctp): the graphs kept on the record, to
// open or fork; on a collection, to lay the workspace out. As "In
// investigations", on events and clusters, the collections holding the
// record come first, and the graph the record's graph card opens on leads
// its graphs. Graphs are made in a Pivot Explorer. Reading needs nothing but
// the page; the writes go through IntelGraph, which every user who may make
// them has.

(function () {
    'use strict';

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
    function plural(n, one, more) { return n + ' ' + (n === 1 ? one : more); }
    function lower(s) { return String(s || '').toLowerCase(); }
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
    function toast(text, variant) {
        if (typeof window.showToast === 'function') window.showToast(text, variant || 'success');
    }
    // A link to the page's Pivot Explorer tab, where graphs are made.
    function explorerLink(text) {
        var a = el('a', null, text);
        a.href = '#tab-pivot-explorer';
        a.addEventListener('click', function (e) {
            var tab = document.querySelector('.nav-link[href="#tab-pivot-explorer"]');
            if (!tab || !window.bootstrap || !window.bootstrap.Tab) return;
            e.preventDefault();
            window.bootstrap.Tab.getOrCreateInstance(tab).show();
            tab.scrollIntoView({ block: 'nearest' });
        });
        return a;
    }

    function card(root) {
        var config = JSON.parse(root.querySelector('[data-ig-card-config]').textContent);
        var body = root.querySelector('[data-ig-card-body]');
        var countEl = root.querySelector('[data-ig-card-count]');
        var target = config.target;
        var noun = config.targetName;
        var last = null;

        function getJson(path) {
            return fetch(config.baseurl + path, {
                credentials: 'same-origin',
                headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
            }).then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            });
        }

        function badge(level) {
            var d = config.distributionLevels[level];
            if (!d) return null;
            var b = el('span', 'badge d-inline-flex align-items-center px-2 py-1');
            var tone = function (role, value) {
                return d.token ? 'var(--misp-' + d.token + '-' + role + ', ' + value + ')' : value;
            };
            b.style.backgroundColor = tone('bg', d.bg);
            b.style.color = tone('fg', d.color);
            b.style.border = '1px solid ' + tone('border', d.color + '20');
            b.style.fontWeight = '500';
            b.title = d.label;
            b.appendChild(icon(d.icon));
            b.appendChild(el('span', 'ms-1', d.label));
            return b;
        }

        function tool(iconCls, title, onClick) {
            var b = el('button', 'btn btn-sm btn-link text-body-secondary px-1 py-0');
            b.type = 'button';
            b.title = title;
            b.setAttribute('aria-label', title);
            b.appendChild(icon(iconCls));
            b.addEventListener('click', function () { onClick(b); });
            return b;
        }

        function workspacePill(title) {
            var on = el('span', 'badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-semibold flex-shrink-0');
            on.setAttribute('data-ig-active-pill', '');
            on.title = title;
            on.appendChild(icon('fas fa-bullseye me-1'));
            on.appendChild(document.createTextNode('Workspace'));
            return on;
        }

        // Where the graph's picture goes (intel-graph-thumbs.js)
        function thumbHolder(g, surface) {
            var h = el('span');
            h.setAttribute('data-intel-graph-thumb', g.uuid);
            h.setAttribute('data-revision', String(g.revision));
            h.setAttribute('data-surface', surface);
            h.setAttribute('data-name', g.name);
            return h;
        }

        function section(title, count) {
            var h = el('div', 'ig-card-section d-flex align-items-baseline gap-2 px-3 pt-2 pb-1');
            h.appendChild(el('span', 'small text-uppercase fw-semibold text-body-secondary', title));
            h.appendChild(el('span', 'small text-body-tertiary', String(count)));
            return h;
        }

        function emptyLine(text, withExplorer) {
            var p = el('div', 'small text-body-secondary px-3 pb-2 border-bottom ig-card-none', text);
            if (withExplorer) {
                p.appendChild(document.createTextNode(' '));
                p.appendChild(explorerLink('Save one from the Pivot Explorer'));
                p.appendChild(document.createTextNode('.'));
            }
            return p;
        }

        function graphRow(g, active) {
            var r = el('div', 'd-flex align-items-start gap-2 px-3 py-2 border-bottom');
            r.setAttribute('data-ig-graph', g.uuid);
            r.appendChild(icon('misp-icon misp-icon-analyst-graph misp-simple text-analystGraph mt-1 flex-shrink-0'));
            var main = el('div', 'flex-grow-1');
            main.style.minWidth = '0';
            var top = el('div', 'd-flex align-items-center gap-2');
            var a = el('a', 'fw-semibold text-truncate', g.name);
            a.href = config.baseurl + '/analyst_graphs/view/' + encodeURIComponent(g.uuid);
            if (g.description) a.title = g.description;
            top.appendChild(a);
            if (active) top.appendChild(workspacePill('It lays out your workspace'));
            main.appendChild(top);
            var sub = el('div', 'small text-body-secondary d-flex flex-wrap align-items-center gap-2 mt-1');
            sub.appendChild(el('span', null, (g.Orgc && g.Orgc.name) || ''));
            var bd = badge(g.distribution);
            if (bd) sub.appendChild(bd);
            sub.appendChild(el('span', null, plural(g.node_count, 'node', 'nodes')));
            if (g.forked_from_uuid) {
                var f = el('span', 'text-truncate');
                f.appendChild(icon('fas fa-code-fork me-1'));
                if (g.forked_from) {
                    f.appendChild(document.createTextNode('fork of '));
                    var p = el('a', 'link-secondary', g.forked_from.name);
                    p.href = config.baseurl + '/analyst_graphs/view/' + encodeURIComponent(g.forked_from.uuid);
                    f.appendChild(p);
                } else {
                    f.appendChild(document.createTextNode('fork'));
                }
                sub.appendChild(f);
            }
            if (!g._canEdit) {
                var ro = el('span', null);
                ro.appendChild(icon('fas fa-lock me-1'));
                ro.appendChild(document.createTextNode('read-only'));
                sub.appendChild(ro);
            }
            main.appendChild(sub);
            r.setAttribute('data-intel-graph-row', '');
            main.appendChild(thumbHolder(g, 'card'));
            r.appendChild(main);

            var tools = el('div', 'd-flex flex-shrink-0');
            var ours = lower(g.orgc_uuid) === config.orgUuid;
            if (config.canWorkspace && ours && !active && window.IntelGraph) {
                tools.appendChild(tool('fas fa-bullseye', 'Make this collection my workspace, laid out by this graph', function (b) {
                    b.disabled = true;
                    window.IntelGraph.setActive(target.uuid, g.uuid).then(function () {
                        toast('“' + target.label + '” is your workspace, laid out by “' + g.name + '”.');
                    }, function (err) {
                        b.disabled = false;
                        toast('Could not make it your workspace: ' + message(err), 'danger');
                    });
                }));
            }
            if (config.canFork) {
                tools.appendChild(tool('fas fa-code-fork', 'Fork it onto this ' + noun, function (b) {
                    b.disabled = true;
                    window.IntelGraph.fork(g.uuid, { target: { type: target.type, uuid: target.uuid } }).then(function (fork) {
                        window.location.href = config.baseurl + '/analyst_graphs/view/' + encodeURIComponent(fork.uuid);
                    }, function (err) {
                        b.disabled = false;
                        toast('Could not fork: ' + message(err), 'danger');
                    });
                }));
            }
            r.appendChild(tools);
            return r;
        }

        function collectionRow(c, workspace) {
            var mine = !!workspace && lower(c.uuid) === lower(workspace);
            var r = el('div', 'd-flex align-items-start gap-2 px-3 py-2 border-bottom');
            r.setAttribute('data-ig-collection', c.uuid);
            r.appendChild(icon((mine ? 'fas fa-folder-open' : 'fas fa-folder') + ' text-accent mt-1 flex-shrink-0'));
            var main = el('div', 'flex-grow-1');
            main.style.minWidth = '0';
            var top = el('div', 'd-flex align-items-center gap-2');
            var a = el('a', 'fw-semibold text-truncate', c.name);
            a.href = config.baseurl + '/collections/view/' + encodeURIComponent(c.id);
            top.appendChild(a);
            if (mine) top.appendChild(workspacePill('It is your workspace'));
            main.appendChild(top);
            var sub = el('div', 'small text-body-secondary d-flex flex-wrap align-items-center gap-2 mt-1');
            sub.appendChild(el('span', null, (c.Orgc && c.Orgc.name) || ''));
            sub.appendChild(el('span', null, config.collectionTypes[c.type] || c.type));
            sub.appendChild(el('span', null, plural(c.element_count, 'member', 'members')));
            var bd = badge(c.distribution);
            if (bd) sub.appendChild(bd);
            var joined = c.element && c.element.created;
            if (joined) {
                var when = el('span', null, 'added ' + String(joined).slice(0, 10));
                when.title = 'This ' + noun + ' joined it on ' + joined;
                sub.appendChild(when);
            }
            main.appendChild(sub);
            r.appendChild(main);
            var tools = el('div', 'd-flex flex-shrink-0');
            if (config.canChooseWorkspace && c._canEdit && !mine && window.IntelGraph) {
                tools.appendChild(tool('fas fa-bullseye', 'Make it my workspace', function (b) {
                    b.disabled = true;
                    window.IntelGraph.setActive(c.uuid).then(function () {
                        toast('“' + c.name + '” is your workspace.');
                    }, function (err) {
                        b.disabled = false;
                        toast('Could not make it your workspace: ' + message(err), 'danger');
                    });
                }));
            }
            r.appendChild(tools);
            return r;
        }

        function say(collections, graphs) {
            if (!config.investigations) {
                countEl.textContent = graphs.length
                    ? plural(graphs.length, 'saved graph', 'saved graphs') + ' on this ' + noun
                    : 'No saved graph on this ' + noun;
                return;
            }
            countEl.textContent = (collections.length ? plural(collections.length, 'collection', 'collections') : 'No collection')
                + ' · ' + (graphs.length ? plural(graphs.length, 'graph', 'graphs') : 'no graph');
        }

        function render() {
            if (!last) return;
            var graphs = last.graphs, collections = last.collections;
            var workspace = window.IntelGraph && window.IntelGraph.active ? window.IntelGraph.active() : null;
            say(collections, graphs);
            body.textContent = '';
            if (!graphs.length && !collections.length) {
                var empty = el('div', 'd-flex flex-column align-items-center justify-content-center text-muted py-4 px-3 text-center');
                empty.appendChild(icon((config.investigations ? 'fas fa-folder-tree' : 'misp-icon misp-icon-analyst-graph misp-simple') + ' fa-2x mb-2 opacity-50'));
                empty.appendChild(el('p', 'mb-1 small fw-semibold', config.investigations
                    ? 'Not in an investigation yet'
                    : 'No saved graph on this ' + noun + ' yet'));
                var hint = el('p', 'mb-0 small', config.investigations
                    ? 'No collection holds this ' + noun + ' and no saved graph is kept on it. Graphs are saved from the '
                    : 'Graphs are saved from the ');
                hint.appendChild(explorerLink('Pivot Explorer'));
                hint.appendChild(document.createTextNode('.'));
                empty.appendChild(hint);
                body.appendChild(empty);
                return;
            }
            if (config.investigations) {
                body.appendChild(section('Collections', collections.length));
                if (!collections.length) body.appendChild(emptyLine('No collection holds this ' + noun + '.'));
                collections.forEach(function (c) { body.appendChild(collectionRow(c, workspace && workspace.Collection.uuid)); });
                body.appendChild(section('Saved graphs', graphs.length));
                if (!graphs.length) body.appendChild(emptyLine('None kept on this ' + noun + '.', true));
            }
            graphs.forEach(function (g) { body.appendChild(graphRow(g, last.activeGraph === g.uuid)); });
        }

        function graphsOf(out) {
            var graphs = (out && out.Graph) || [];
            // The graph the record's graph card opens on leads.
            if (config.investigations && out && out.pick) {
                graphs = graphs.filter(function (g) { return g.uuid === out.pick; })
                    .concat(graphs.filter(function (g) { return g.uuid !== out.pick; }));
            }
            return graphs;
        }

        function load() {
            var path = '/analyst_graphs/forTarget/' + encodeURIComponent(target.type) + '/' + encodeURIComponent(target.uuid) + '.json';
            var holding = config.investigations
                ? getJson('/collections/holding/' + encodeURIComponent(target.type) + '/' + encodeURIComponent(target.uuid) + '.json')
                : Promise.resolve(null);
            return Promise.all([getJson(path), holding]).then(function (both) {
                last = {
                    graphs: graphsOf(both[0]),
                    activeGraph: both[0] && both[0].active,
                    collections: (both[1] && both[1].Collection) || []
                };
                render();
            }).catch(function () {
                countEl.textContent = '';
                body.textContent = '';
                var err = el('div', 'text-center text-muted py-4 small');
                err.appendChild(icon('fas fa-exclamation-triangle me-2'));
                err.appendChild(document.createTextNode(config.investigations
                    ? 'Could not load the investigations.'
                    : 'Could not load the saved graphs.'));
                body.appendChild(err);
            });
        }

        var key = target.type + ':' + lower(target.uuid);
        function concerns(e) {
            var r = (e.detail && e.detail.report) || {};
            return [].concat(r.added || [], r.removed || []).indexOf(key) !== -1;
        }
        if (config.investigations) {
            ['intel-graph:added', 'intel-graph:removed'].forEach(function (name) {
                document.addEventListener(name, function (e) { if (concerns(e)) load(); });
            });
            // The collection modal saves in place.
            document.addEventListener('misp:collection-element-added', function (e) {
                var d = e.detail || {};
                if (d.type === target.type && lower(d.uuid) === lower(target.uuid)) load();
            });
        }
        document.addEventListener('intel-graph:graphs', function (e) {
            var t = e.detail && e.detail.target;
            if (t && t.type === target.type && lower(t.uuid) === lower(target.uuid)) load();
        });
        document.addEventListener('intel-graph:active', function () { load(); });

        load();
        root.igReload = load;
    }

    function boot() {
        document.querySelectorAll('[data-ig-graphs-card]').forEach(card);
    }

    // assetLoader puts this script above the card it reads.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
}());
