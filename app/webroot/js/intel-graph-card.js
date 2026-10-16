// The Graphs card on a collection, an event or a galaxy cluster
// (Elements/AnalystGraphs/graphs_card.ctp): the graphs hung off the record,
// to open, fork or make active, and "New graph" on it. Reading needs nothing
// but the page; the writes go through IntelGraph, which every user who may
// make them has.

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
        var span = el('span', null, text);
        if (typeof window.showToast === 'function') window.showToast(span.outerHTML, variant || 'success');
    }

    function card(root) {
        var config = JSON.parse(root.querySelector('[data-ig-card-config]').textContent);
        var body = root.querySelector('[data-ig-card-body]');
        var countEl = root.querySelector('[data-ig-card-count]');
        var target = config.target;

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

        // Where the graph's picture goes (intel-graph-thumbs.js)
        function thumbHolder(g, surface) {
            var h = el('span');
            h.setAttribute('data-intel-graph-thumb', g.uuid);
            h.setAttribute('data-revision', String(g.revision));
            h.setAttribute('data-surface', surface);
            h.setAttribute('data-name', g.name);
            return h;
        }

        function row(g, active) {
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
            if (active) {
                var on = el('span', 'badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-semibold flex-shrink-0');
                on.setAttribute('data-ig-active-pill', '');
                on.title = '“Add to graph” feeds this graph';
                on.appendChild(icon('fas fa-bullseye me-1'));
                on.appendChild(document.createTextNode('Active'));
                top.appendChild(on);
            }
            main.appendChild(top);
            var sub = el('div', 'small text-body-secondary d-flex flex-wrap align-items-center gap-2 mt-1');
            sub.appendChild(el('span', null, (g.Orgc && g.Orgc.name) || ''));
            var bd = badge(g.distribution);
            if (bd) sub.appendChild(bd);
            sub.appendChild(el('span', null, g.node_count + (g.node_count === 1 ? ' node' : ' nodes')));
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
            if (config.canCreate && g._canEdit && !active) {
                tools.appendChild(tool('fas fa-bullseye', 'Make it my active graph', function (b) {
                    b.disabled = true;
                    window.IntelGraph.setActive(g.uuid).then(function () {
                        toast('“Add to graph” now feeds “' + g.name + '”.');
                        load();
                    }, function (err) {
                        b.disabled = false;
                        toast('Could not make it active: ' + message(err), 'danger');
                    });
                }));
            }
            if (config.canFork) {
                tools.appendChild(tool('fas fa-code-fork', 'Fork it onto this ' + config.targetName, function (b) {
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

        function load() {
            return getJson('/analyst_graphs/forTarget/' + encodeURIComponent(target.type) + '/' + encodeURIComponent(target.uuid) + '.json')
                .then(function (out) {
                    var graphs = (out && out.Graph) || [];
                    // Kept on the record, its target: not the graphs it is a node of.
                    countEl.textContent = graphs.length
                        ? graphs.length + (graphs.length === 1 ? ' graph' : ' graphs') + ' kept on this ' + config.targetName
                        : 'No graph kept on this ' + config.targetName;
                    body.textContent = '';
                    if (!graphs.length) {
                        var empty = el('div', 'd-flex flex-column align-items-center justify-content-center text-muted py-4 px-3 text-center');
                        empty.appendChild(icon('misp-icon misp-icon-analyst-graph misp-simple fa-2x mb-2 opacity-50'));
                        empty.appendChild(el('p', 'mb-0 small fw-semibold', config.canCreate
                            ? 'Start one with +, then send records to it with “Add to graph”.'
                            : 'No graph hangs off this ' + config.targetName + ' yet.'));
                        body.appendChild(empty);
                        return;
                    }
                    graphs.forEach(function (g) { body.appendChild(row(g, out.active === g.uuid)); });
                })
                .catch(function () {
                    countEl.textContent = '';
                    body.textContent = '';
                    var err = el('div', 'text-center text-muted py-4 small');
                    err.appendChild(icon('fas fa-exclamation-triangle me-2'));
                    err.appendChild(document.createTextNode('Could not load the graphs.'));
                    body.appendChild(err);
                });
        }

        function bindCreate() {
            var button = root.querySelector('[data-ig-card-new]');
            var modalEl = root.querySelector('[data-ig-card-modal]');
            if (!button || !modalEl || !config.create) return;
            // Inside the card the modal would sit under the page's stacking.
            document.body.appendChild(modalEl);
            var form = modalEl.querySelector('[data-ig-card-form]');
            var error = form.querySelector('[data-ig-card-error]');
            var dist = form.elements.distribution;
            var sg = form.elements.sharing_group_id;
            var uid = 'ig-card-' + Math.random().toString(36).slice(2, 8);
            form.querySelectorAll('[data-ig-for]').forEach(function (label) {
                var input = form.elements[label.getAttribute('data-ig-for')];
                input.id = uid + '-' + input.name;
                label.htmlFor = input.id;
            });
            config.create.levels.forEach(function (l) {
                var o = el('option', null, l[1]);
                o.value = String(l[0]);
                o.selected = l[0] === config.create.default;
                dist.appendChild(o);
            });
            config.create.sharingGroups.forEach(function (g) {
                var o = el('option', null, g[1]);
                o.value = String(g[0]);
                sg.appendChild(o);
            });
            dist.addEventListener('change', function () { sg.hidden = dist.value !== '4'; });
            var modal = window.bootstrap.Modal.getOrCreateInstance(modalEl);
            modalEl.addEventListener('shown.bs.modal', function () { form.elements.name.focus(); });
            button.addEventListener('click', function () {
                form.reset();
                dist.value = String(config.create.default);
                sg.hidden = dist.value !== '4';
                error.textContent = '';
                modal.show();
            });
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                var name = form.elements.name.value.trim();
                if (!name) { error.textContent = 'A graph needs a name.'; return; }
                if (dist.value === '4' && !sg.value) { error.textContent = 'Pick the sharing group to share it with.'; return; }
                var submit = form.querySelector('[type="submit"]');
                submit.disabled = true;
                window.IntelGraph.create({
                    name: name,
                    description: form.elements.description.value,
                    target: { type: target.type, uuid: target.uuid },
                    distribution: +dist.value,
                    sharing_group_id: dist.value === '4' ? +sg.value : null
                }, { activate: form.elements.activate.checked }).then(function (created) {
                    submit.disabled = false;
                    modal.hide();
                    toast('“' + name + '” created' + (form.elements.activate.checked ? ', and active.' : '.'));
                    load();
                    return created;
                }, function (err) {
                    submit.disabled = false;
                    error.textContent = 'Not created: ' + message(err);
                });
            });
        }

        bindCreate();
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
