// The Overmind event overview (General tab of /events/view2): lazy cards,
// the lead report and its modal, the object graph, and the inventory's
// filters into the Objects and Attributes tabs.
(function () {
    'use strict';

    function base() {
        return typeof window.baseurl === 'string' ? window.baseurl : '';
    }

    function fmt(template, values) {
        var i = 0;
        return String(template || '').replace(/%(\d+\$)?s/g, function (m, pos) {
            var at = pos ? parseInt(pos, 10) - 1 : i++;
            return values[at] === undefined ? '' : values[at];
        });
    }

    function fetchText(url) {
        return fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.text();
            });
    }

    function fetchJson(url) {
        return fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            });
    }

    function failure(el) {
        el.innerHTML = '<div class="eo-empty"><span><i class="fas fa-exclamation-triangle me-1"></i>'
            + 'Could not load this part of the event.</span></div>';
    }

    /* ── lazy cards ─────────────────────────────────────────── */
    function loadFragment(el) {
        var url = el.getAttribute('data-eo-fragment') || el.getAttribute('data-eo-fragment-lazy');
        if (!url) return Promise.resolve();
        return fetchText(url).then(function (html) {
            el.innerHTML = html;
            el.setAttribute('data-eo-loaded', '');
            afterFragment(el);
        }, function () { failure(el); });
    }

    function afterFragment(el) {
        var inventory = el.querySelector('.eo-inventory');
        if (inventory) {
            fillNarrower(
                parseInt(inventory.getAttribute('data-eo-narrower-count'), 10) || 0,
                inventory.getAttribute('data-eo-narrower-tab') || 'objects'
            );
        }
        document.dispatchEvent(new CustomEvent('misp:overview-fragment', { detail: { el: el } }));
    }

    function fillNarrower(count, tab) {
        var link = document.querySelector('[data-eo-narrower]');
        if (!link) return;
        link.setAttribute('data-eo-narrower-tab', tab);
        if (!count) {
            link.classList.add('d-none');
            return;
        }
        var label = count === 1 ? link.getAttribute('data-eo-label-one') : link.getAttribute('data-eo-label-many');
        link.textContent = fmt(label, [count]);
        var icon = document.createElement('i');
        icon.className = 'fas fa-filter me-1';
        link.prepend(icon);
        link.classList.remove('d-none');
    }

    // Hovering a group row, one of its types or a bar segment marks that group.
    function focusGroup(inventory, group) {
        if (inventory.getAttribute('data-eo-focus') === (group || null)) return;
        if (group) inventory.setAttribute('data-eo-focus', group);
        else inventory.removeAttribute('data-eo-focus');
        inventory.querySelectorAll('.eo-bar-seg, .eo-group').forEach(function (el) {
            el.classList.toggle('is-focus', !!group && el.getAttribute('data-eo-group') === group);
        });
    }

    function onHover(e) {
        var inventory = e.target.closest && e.target.closest('.eo-inventory');
        if (!inventory) return;
        var marked = e.target.closest('.eo-bar-seg, .eo-group');
        focusGroup(inventory, marked ? marked.getAttribute('data-eo-group') : null);
    }

    function onLeave(e) {
        var inventory = e.target.closest && e.target.closest('.eo-inventory');
        if (inventory && !inventory.contains(e.relatedTarget)) focusGroup(inventory, null);
    }

    function onFilterLabels(e) {
        var input = e.target.closest && e.target.closest('[data-eo-label-filter]');
        if (!input) return;
        var q = input.value.trim().toLowerCase();
        var card = input.closest('.eo-context');
        card.querySelectorAll('.eo-rows .hg-unit, .eo-rows .eo-techniques li, .eo-rows .eo-absent').forEach(function (el) {
            el.classList.toggle('d-none', q !== '' && el.textContent.toLowerCase().indexOf(q) === -1);
        });
        card.querySelectorAll('.eo-rows .hg-group').forEach(function (group) {
            group.classList.toggle('d-none', q !== '' && !group.querySelector('.hg-unit:not(.d-none)'));
        });
    }

    function reloadCards() {
        document.querySelectorAll('#eo-context-card, #eo-inventory-card, #eo-object-views, .eo-details-activity[data-eo-loaded]')
            .forEach(loadFragment);
    }

    /* ── tabs and filters ───────────────────────────────────── */
    function showTab(id) {
        var link = document.querySelector('.nav-link[href="#tab-' + id + '"]');
        if (!link || !window.bootstrap) return;
        window.bootstrap.Tab.getOrCreateInstance(link).show();
        var strip = link.closest('.nav');
        if (strip) strip.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function tabContainer(id) {
        var pane = document.getElementById('tab-' + id);
        return pane ? pane.querySelector('.ajax-tab-content[data-url]') : null;
    }

    function unfilteredUrl(container) {
        if (!container.hasAttribute('data-eo-base-url')) {
            container.setAttribute('data-eo-base-url', container.getAttribute('data-url'));
        }
        return container.getAttribute('data-eo-base-url');
    }

    // filter: named params to append, e.g. { type: 'domain,url' } or { narrower: 1 }
    function openFiltered(tab, filter) {
        var container = tabContainer(tab);
        if (container) {
            var url = unfilteredUrl(container);
            Object.keys(filter || {}).forEach(function (key) {
                url += '/' + key + ':' + encodeURIComponent(filter[key]);
            });
            if (container.getAttribute('data-url') !== url) {
                container.setAttribute('data-url', url);
                delete container.dataset.loaded;
                if (typeof window.loadAjaxContainer === 'function') window.loadAjaxContainer(container);
            }
        }
        showTab(tab);
    }

    function onClick(e) {
        var keepTab = e.target.closest('a[data-eo-keep-tab]');
        if (keepTab) {
            // A #tab-<id> hash would make the browser scroll to that pane on load.
            var tabId = (window.location.hash.match(/^#tab-(.+)$/) || [])[1];
            keepTab.href = keepTab.href.split('#')[0] + (tabId ? '#open-tab-' + tabId : '');
            return;
        }
        var filter = e.target.closest('[data-eo-filter-types]');
        if (filter) {
            e.preventDefault();
            openFiltered(filter.getAttribute('data-eo-filter-tab') || 'objects', { type: filter.getAttribute('data-eo-filter-types') });
            return;
        }
        var narrower = e.target.closest('[data-eo-narrower]');
        if (narrower) {
            e.preventDefault();
            openFiltered(narrower.getAttribute('data-eo-narrower-tab') || 'objects', { narrower: 1 });
            return;
        }
        var rollup = e.target.closest('[data-eo-rollup]');
        if (rollup) {
            var card = rollup.closest('[data-eo-fragment]');
            if (!card) return;
            rollup.disabled = true;
            card.setAttribute('data-eo-fragment', rollup.getAttribute('data-eo-rollup'));
            loadFragment(card).then(function () {
                document.dispatchEvent(new CustomEvent('misp:overview-rolled-up', { detail: { source: 'context' } }));
            });
            return;
        }
        var tab = e.target.closest('[data-eo-tab]');
        if (tab) {
            showTab(tab.getAttribute('data-eo-tab'));
            return;
        }
        var open = e.target.closest('[data-eo-report-open]');
        if (open) {
            var modal = document.getElementById('eo-report-modal');
            if (modal && window.bootstrap) window.bootstrap.Modal.getOrCreateInstance(modal).show();
        }
    }

    /* ── report ─────────────────────────────────────────────── */
    var mermaidReady = null;

    function loadMermaid() {
        if (window.mermaid) return Promise.resolve(window.mermaid);
        if (mermaidReady) return mermaidReady;
        mermaidReady = new Promise(function (resolve, reject) {
            var s = document.createElement('script');
            s.src = base() + '/js/mermaid.js';
            s.onload = function () { window.mermaid ? resolve(window.mermaid) : reject(new Error('mermaid')); };
            s.onerror = reject;
            document.head.appendChild(s);
        });
        return mermaidReady;
    }

    function isMermaid(code) {
        if (code.classList.contains('language-mermaid')) return true;
        var first = (code.textContent || '').trim().split(/\n/)[0].trim();
        return /^(gantt|sequenceDiagram|classDiagram|stateDiagram|erDiagram|journey|pie|mindmap|timeline|flowchart|graph (TB|BT|RL|LR|TD))\b/.test(first);
    }

    var mermaidSeq = 0;
    function drawMermaid(root) {
        var blocks = Array.prototype.filter.call(root.querySelectorAll('pre > code'), isMermaid);
        if (!blocks.length) return Promise.resolve();
        return loadMermaid().then(function (mermaid) {
            var dark = document.documentElement.getAttribute('data-misp-mode') === 'dark';
            mermaid.initialize({ startOnLoad: false, theme: dark ? 'dark' : 'neutral' });
            return blocks.reduce(function (chain, code) {
                return chain.then(function () {
                    var id = 'eo-mermaid-' + (++mermaidSeq);
                    return mermaid.mermaidAPI.render(id, code.textContent).then(function (out) {
                        var div = document.createElement('div');
                        div.className = 'mermaid eo-mermaid';
                        div.innerHTML = out.svg;
                        code.parentNode.replaceWith(div);
                    }, function () { /* an unparsable diagram stays as source */ });
                });
            }, Promise.resolve());
        }, function () { /* no mermaid: the source stays readable */ });
    }

    function initReport() {
        var card = document.getElementById('eo-report-card');
        if (!card || !card.hasAttribute('data-eo-report-id')) return;
        var raw = card.getAttribute('data-eo-report-content') || '';
        var preview = card.querySelector('[data-eo-report-preview]');
        var full = document.querySelector('[data-eo-report-full]');
        var renderer = null;

        function render(target) {
            if (!window.MispReportMarkdown) {
                target.textContent = raw;
                return Promise.resolve();
            }
            if (!renderer) {
                renderer = window.MispReportMarkdown.create({
                    reportId: parseInt(card.getAttribute('data-eo-report-id'), 10),
                    eventId: parseInt(card.getAttribute('data-eo-event-id'), 10)
                });
            }
            return renderer.ready.then(function () {
                renderer.render(raw, target);
                return drawMermaid(target);
            });
        }

        render(preview).then(function () {
            var clamp = card.querySelector('.eo-report-clamp');
            if (clamp && clamp.scrollHeight > clamp.clientHeight + 4) card.classList.add('is-clamped');
        });

        var modal = document.getElementById('eo-report-modal');
        if (modal && full) {
            modal.addEventListener('show.bs.modal', function () {
                if (full.getAttribute('data-eo-rendered')) return;
                full.setAttribute('data-eo-rendered', '1');
                render(full);
            });
        }
    }

    /* ── graph ──────────────────────────────────────────────── */
    function readJson(raw, fallback) {
        try { return JSON.parse(raw || fallback); } catch (e) { return JSON.parse(fallback); }
    }

    function explorerConfig(eventId) {
        var pe = document.getElementById('pe-card');
        var d = pe ? pe.dataset : {};
        return {
            eventId: String(eventId),
            baseurl: base(),
            canEdit: false,
            canAnalyst: false,
            uiPriorities: readJson(d.peUiPriorities, '{}'),
            labelPlan: readJson(d.peLabelPlan, 'null'),
            permitted: readJson(d.pePermitted, 'null'),
            valueCard: d.peValueCard === '1',
            canEnrich: false,
            orgUuid: d.peOrgUuid || '',
            siteAdmin: d.peSiteAdmin === '1'
        };
    }

    // A handful of nodes can afford the room a heavy graph cannot.
    var ROOMY_GRAPH_MAX = 12;

    // Fewer alike nodes than this stay drawn one by one.
    var FOLD_MIN_SIZE = 3;

    function viewerOptions(opts, kit, seed) {
        var nodes = (seed && seed.data && seed.data.nodes) || [];
        opts.UI.mode = 'viewer';
        opts.UI.extraPanels = [];
        opts.UI.sidebar = { collapsed: true };
        // Alike objects hanging off the same nodes fold into one group; a
        // double-click opens it.
        opts.UI.simplify.rules = [
            { kind: 'neighbours', minSize: FOLD_MIN_SIZE },
            { kind: 'chains', minSize: FOLD_MIN_SIZE }
        ];
        opts.simulation.layout = { type: 'structured', gap: nodes.length <= ROOMY_GRAPH_MAX ? 30 : 10 };
        opts.render.maxZoom = 1.5;
    }

    // The palette's colours lean on CSS variables, which a canvas cannot read.
    function resolvedOrigins(origins, host) {
        if (!origins) return null;
        var probe = document.createElement('span');
        host.appendChild(probe);
        var out = {};
        Object.keys(origins).forEach(function (id) {
            probe.style.color = '';
            probe.style.color = origins[id].color;
            out[id] = Object.assign({}, origins[id], { color: getComputedStyle(probe).color });
        });
        probe.remove();
        return out;
    }

    function initGraph() {
        var card = document.getElementById('eo-graph-card');
        if (!card) return;
        var loader = card.querySelector('[data-eo-graph-loader]');
        var canvases = {
            structure: card.querySelector('[data-eo-graph-canvas="structure"]'),
            saved: card.querySelector('[data-eo-graph-canvas="saved"]')
        };
        var stage = card.querySelector('.eo-graph-stage');
        var message = card.querySelector('[data-eo-graph-message]');
        var blank = card.querySelector('[data-eo-graph-empty]');
        // What the structure view shows instead of a graph: 'message', 'blank' or nothing.
        var instead = null;
        var mode = 'structure';
        var sub = card.querySelector('[data-eo-graph-sub]');
        var buttons = card.querySelectorAll('[data-eo-graph-mode]');
        var structureSub = '';
        var saved = null;
        var savedCount = 0;
        var savedShown = null;
        var savedHandle = null;
        var savedToken = 0;
        var pick = card.querySelector('[data-eo-graph-pick]');
        var strip = card.parentElement.querySelector('[data-eo-graph-strip]');
        var reportCol = document.querySelector('[data-eo-col="report"]');
        var structureEmpty = card.getAttribute('data-eo-structure-empty') === '1';
        var foldable = card.getAttribute('data-eo-graph-foldable') === '1';
        var savedDrawn = false;

        // With nothing to draw, the card folds into a strip under a full-width report.
        function layout() {
            var compact = foldable && structureEmpty && !savedDrawn;
            card.classList.toggle('d-none', compact);
            if (strip) strip.classList.toggle('d-none', !compact);
            if (reportCol) reportCol.classList.toggle('col-xl-5', !compact);
            card.parentElement.classList.toggle('col-xl-7', !compact);
        }

        function noStructure() {
            structureEmpty = true;
            showBlank();
            layout();
        }

        function showInstead() {
            var structure = mode === 'structure';
            stage.classList.toggle('is-empty', structure && !!instead);
            message.classList.toggle('d-none', !structure || instead !== 'message');
            if (blank) blank.classList.toggle('d-none', !structure || instead !== 'blank');
        }

        function say(text) {
            if (loader) loader.classList.add('d-none');
            message.textContent = text;
            instead = 'message';
            showInstead();
        }

        function showBlank() {
            if (loader) loader.classList.add('d-none');
            instead = 'blank';
            showInstead();
        }

        function select(next) {
            mode = next;
            buttons.forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-eo-graph-mode') === mode); });
            Object.keys(canvases).forEach(function (k) { canvases[k].classList.toggle('d-none', k !== mode); });
            showInstead();
            sub.textContent = mode === 'saved' && saved
                ? fmt(card.getAttribute('data-eo-text-saved'), [saved.name || saved.uuid])
                    + (savedCount > 1 ? ' · ' + fmt(card.getAttribute('data-eo-text-saved-count'), [savedCount]) : '')
                : structureSub;
            if (mode === 'saved') mountSaved();
        }

        function mountSaved() {
            if (!saved || savedShown === saved.uuid || !window.IntelGraph) return;
            savedShown = saved.uuid;
            if (savedHandle) savedHandle.destroy();
            savedHandle = null;
            canvases.saved.textContent = '';
            var token = ++savedToken;
            window.IntelGraph.mount(canvases.saved, { graph: saved.uuid, ui: { mode: 'viewer' } }).then(function (handle) {
                if (token === savedToken) savedHandle = handle;
                else handle.destroy();
            }, function () {
                if (token === savedToken) canvases.saved.textContent = card.getAttribute('data-eo-text-failed');
            });
        }

        function fillPick(graphs) {
            pick.textContent = '';
            graphs.forEach(function (g) {
                var item = document.createElement('button');
                item.type = 'button';
                item.className = 'dropdown-item';
                item.setAttribute('aria-current', g === saved ? 'true' : 'false');
                var mark = document.createElement('span');
                mark.className = 'eo-graph-pick-mark';
                if (g === saved) {
                    var check = document.createElement('i');
                    check.className = 'fas fa-check';
                    mark.appendChild(check);
                }
                var name = document.createElement('span');
                name.className = 'eo-graph-pick-name';
                name.textContent = g.name || g.uuid;
                var size = document.createElement('span');
                size.className = 'badge rounded-pill text-bg-secondary';
                size.textContent = String(g.node_count || 0);
                size.title = fmt(card.getAttribute('data-eo-text-node-count'), [g.node_count || 0]);
                item.append(mark, name, size);
                item.addEventListener('click', function () {
                    saved = g;
                    fillPick(graphs);
                    select('saved');
                });
                var li = document.createElement('li');
                li.appendChild(item);
                pick.appendChild(li);
            });
        }

        buttons.forEach(function (b) {
            b.addEventListener('click', function () {
                if (!b.disabled && !b.hasAttribute('data-bs-toggle')) select(b.getAttribute('data-eo-graph-mode'));
            });
        });

        if (structureEmpty) showBlank();
        else fetchJson(card.getAttribute('data-eo-graph-url')).then(function (res) {
            if (!res.graph) {
                if (res.total > 0) say(fmt(card.getAttribute('data-eo-text-summary'), [res.total]));
                else noStructure();
                return;
            }
            var objects = res.graph.Event.Object || [];
            var refs = objects.reduce(function (n, o) { return n + (o.ObjectReference || []).length; }, 0);
            if (!refs) {
                noStructure();
                return;
            }
            structureSub = fmt(card.getAttribute('data-eo-text-counts'), [objects.length, refs]);
            if (!saved) sub.textContent = structureSub;
            if (!window.MispPivotExplorer || typeof window.Pivotick !== 'function') {
                say(card.getAttribute('data-eo-text-failed'));
                return;
            }
            var explorer = window.MispPivotExplorer.create({
                containerEl: canvases.structure,
                loaderEl: loader,
                fitHeight: false,
                provenance: false,
                chips: false,
                origins: resolvedOrigins(res.origins, card),
                event: res.graph,
                config: explorerConfig(card.getAttribute('data-eo-event-id')),
                options: viewerOptions,
                afterMount: function () {}
            });
            card.eoExplorer = explorer;
            explorer.init();
        }, function () { say(card.getAttribute('data-eo-text-failed')); });

        var uuid = card.getAttribute('data-eo-event-uuid');
        if (uuid) {
            fetchJson(base() + '/analyst_graphs/forTarget/Event/' + encodeURIComponent(uuid) + '.json').then(function (res) {
                var graphs = (res && res.Graph) || [];
                if (!graphs.length) return;
                var drawn = graphs.filter(function (g) { return (g.node_count || 0) > 0; });
                saved = drawn[0] || graphs[0];
                var button = card.querySelector('[data-eo-graph-mode="saved"]');
                button.disabled = false;
                button.title = button.getAttribute('data-eo-title-ready');
                savedCount = graphs.length;
                if (graphs.length > 1 && pick) {
                    button.title = button.getAttribute('data-eo-title-pick');
                    button.setAttribute('data-bs-toggle', 'dropdown');
                    button.setAttribute('aria-expanded', 'false');
                    card.querySelector('[data-eo-graph-caret]').classList.remove('d-none');
                    fillPick(graphs);
                }
                // An empty saved graph stays one click away rather than hiding the structure.
                if (drawn.length) {
                    savedDrawn = true;
                    layout();
                    select('saved');
                }
            }, function () { /* no saved graphs to offer */ });
        }
    }

    /* ── boot ───────────────────────────────────────────────── */
    function reopenTab() {
        var tabId = (window.location.hash.match(/^#open-tab-(.+)$/) || [])[1];
        if (!tabId) return;
        var link = document.querySelector('.nav-link[href="#tab-' + CSS.escape(tabId) + '"]');
        if (link && window.bootstrap) bootstrap.Tab.getOrCreateInstance(link).show();
        // Chrome still scrolls to a fragment that turns up before load.
        var settle = function () {
            setTimeout(function () {
                history.replaceState(null, '', window.location.pathname + window.location.search + '#tab-' + tabId);
            }, 0);
        };
        if (document.readyState === 'complete') {
            settle();
        } else {
            window.addEventListener('load', settle, { once: true });
        }
    }

    window.MispEventOverview = { openFiltered: openFiltered };

    function boot() {
        reopenTab();
        if (!document.querySelector('.eo-band')) return;
        document.querySelectorAll('#eo-context-card, #eo-inventory-card, #eo-object-views')
            .forEach(loadFragment);
        document.querySelectorAll('[data-eo-fragment-lazy]').forEach(function (el) {
            var holder = el.closest('.collapse');
            if (!holder) return;
            holder.addEventListener('show.bs.collapse', function once() {
                holder.removeEventListener('show.bs.collapse', once);
                loadFragment(el);
            });
        });
        document.addEventListener('click', onClick);
        document.addEventListener('input', onFilterLabels);
        document.addEventListener('mouseover', onHover);
        document.addEventListener('mouseout', onLeave);
        document.addEventListener('misp:attributes-changed', reloadCards);
        document.addEventListener('misp:overview-rolled-up', function (e) {
            if (e.detail && e.detail.source !== 'context') {
                document.querySelectorAll('#eo-context-card').forEach(loadFragment);
            }
        });
        initReport();
        initGraph();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
