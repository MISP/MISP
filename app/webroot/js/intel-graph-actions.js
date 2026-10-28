// The add control. A record offers it in one of two forms:
//
// - a split button ([data-intel-graph-split]): its main part adds the record
//   to the workspace or, once the workspace holds it, opens the menu its
//   caret opens; that menu is drawn here, from the record's state.
// - entries in a menu the record has already, each its own element.
//
// Each element carries the records it acts on as JSON, a list of items as
// IntelGraph.add() takes them, each with a label:
//   data-intel-graph-add      Add to workspace
//   data-intel-graph-reveal   Show in the dock
//   data-intel-graph-remove   Remove from workspace
//   data-intel-graph-other    Add to another collection…
//   data-intel-graph-new      New collection with this…
//
// An add naming one record says whether the workspace holds it:
// data-intel-graph-in="true", its label (.ig-add-lbl, or the launch bar's)
// replaced by data-intel-graph-label-in. Clicked then, an entry shows the
// record in the dock. An element marked data-intel-graph-when="in" (or
// "out") shows only while the workspace holds its record (or does not).
// The page asks once which of its records the workspace holds, and again
// for rows drawn later.
//
// A control carrying data-intel-graph-workspace, a collection's uuid, makes
// that collection the workspace, and says so while it is.
//
//   IntelGraphActions.add(items, origin)      Add to workspace, from code
//   IntelGraphActions.other(items, origin)    Add to another collection…
//   IntelGraphActions.newWith(items, origin)  New collection with this…
//   IntelGraphActions.state(items)            'in' | 'out' | null (unknown, or several)
//   IntelGraphActions.lookup(items)           asks the workspace about them
//
// Needs intel-graph.js and intel-graph-chooser.js; loaded with them by
// Elements/intel_graph_boot.ctp.

(function () {
    'use strict';

    var ATTRS = ['data-intel-graph-add', 'data-intel-graph-reveal', 'data-intel-graph-remove', 'data-intel-graph-other', 'data-intel-graph-new'];
    var CARRIERS = ATTRS.map(function (a) { return '[' + a + ']'; }).join(', ');
    var SPLIT = '[data-intel-graph-split]';
    // The record types the collection modal takes, and what it calls them.
    var MODAL_TYPES = { Event: 'Event', Attribute: 'Attribute', Object: 'Object', GalaxyCluster: 'GalaxyCluster', Value: 'AttributeValue' };
    var NOUNS = { Event: ['event', 'events'], Attribute: ['attribute', 'attributes'], Object: ['object', 'objects'],
                  GalaxyCluster: ['galaxy cluster', 'galaxy clusters'], Value: ['value', 'values'] };

    function IG() { return window.IntelGraph; }
    function lower(s) { return String(s || '').toLowerCase(); }
    function baseurl() { return (window.IntelGraphConfig && window.IntelGraphConfig.baseurl) || ''; }
    function toast(text, variant) {
        if (typeof window.showToast === 'function') window.showToast(text, variant || 'success');
    }
    function failure(err) { return (err && err.message) || 'error'; }
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

    function parse(raw) {
        try {
            var items = JSON.parse(raw);
            return Array.isArray(items) && items.length ? items : null;
        } catch (e) {
            return null;
        }
    }
    // The records an element acts on, from whichever attribute it carries.
    function itemsOf(control) {
        for (var i = 0; i < ATTRS.length; i++) {
            if (control.hasAttribute(ATTRS[i])) return parse(control.getAttribute(ATTRS[i]));
        }
        return null;
    }
    function workspaceName() {
        var a = IG() && IG().active();
        return a ? a.Collection.name : '';
    }

    // "the event Test event", "the value 8.8.8.8", "6 records: 4 attributes, 2 events".
    function describe(items) {
        if (items.length === 1) {
            var it = items[0], noun = (NOUNS[it.type] || ['record'])[0];
            var name = it.type === 'Value' ? it.value : it.label;
            return name ? 'the ' + noun + ' “' + name + '”' : 'this ' + noun;
        }
        var counts = {};
        items.forEach(function (it) { counts[it.type] = (counts[it.type] || 0) + 1; });
        return items.length + ' records: ' + Object.keys(counts).map(function (t) {
            var n = NOUNS[t] || ['record', 'records'];
            return counts[t] + ' ' + n[counts[t] === 1 ? 0 : 1];
        }).join(', ');
    }

    /* ── what the workspace holds ──────────────────────────── */
    // An element's record key, worked out once (a value's is a digest).
    var keyed = typeof WeakMap === 'function' ? new WeakMap() : null;
    function keyOfControl(control) {
        if (!keyed || !keyed.has(control)) return undefined;
        return keyed.get(control);
    }
    function state(items) {
        if (!items || items.length !== 1 || !IG() || !IG().active()) return null;
        var known = IG().holds(IG().keyNow(items[0]));
        return known === undefined ? null : (known ? 'in' : 'out');
    }
    function stateOf(control) {
        if (control.hasAttribute('data-intel-graph-stateless')) return 'out';
        var key = keyOfControl(control);
        if (!key || !IG() || !IG().active()) return 'out';
        return IG().holds(key) ? 'in' : 'out';
    }

    var LABELS = '.ig-add-lbl, .lb-lbl, .lb-tile-lbl';
    function markAdd(control) {
        var on = stateOf(control) === 'in';
        control.setAttribute('data-intel-graph-in', on ? 'true' : 'false');
        // A bulk bar's page writes its label
        var labels = control.hasAttribute('data-intel-graph-stateless') ? [] : control.querySelectorAll(LABELS);
        Array.prototype.forEach.call(labels, function (span) {
            if (!span.hasAttribute('data-ig-label-out')) span.setAttribute('data-ig-label-out', span.textContent);
            var labelIn = control.getAttribute('data-intel-graph-label-in') || 'In workspace ✓';
            // A tile has room for a word
            if (span.classList.contains('lb-tile-lbl')) labelIn = control.getAttribute('data-intel-graph-short-in') || 'Workspace ✓';
            span.textContent = on ? labelIn : span.getAttribute('data-ig-label-out');
            // The launch bar filters, and redraws, its entries by this
            if (span.classList.contains('lb-lbl') && control.hasAttribute('data-label')) control.setAttribute('data-label', span.textContent);
        });
        if (control.hasAttribute('data-intel-graph-icon-in')) {
            var glyph = control.querySelector('[data-intel-graph-icon]');
            if (glyph) {
                if (!glyph.hasAttribute('data-ig-icon-out')) glyph.setAttribute('data-ig-icon-out', glyph.className);
                glyph.className = on ? control.getAttribute('data-intel-graph-icon-in') : glyph.getAttribute('data-ig-icon-out');
            }
        }
        if (!control.hasAttribute('data-ig-title')) control.setAttribute('data-ig-title', control.getAttribute('title') || '');
        var base = control.getAttribute('data-ig-title');
        var a = IG() && IG().active();
        var c = a && a.Collection;
        var title;
        if (on) {
            title = 'In your workspace “' + c.name + '”' + (control.closest(SPLIT) ? ': show it in the dock or remove it' : ': show it in the dock');
        } else {
            var note = c && c.distribution ? '“' + c.name + '” is shared: partners receive what you add once it is published' : '';
            title = note ? (base ? base + ' — ' + note : note) : base;
        }
        if (title) control.setAttribute('title', title);
        else control.removeAttribute('title');
        // An icon alone says it in its label
        if (control.hasAttribute('data-ig-aria') || control.hasAttribute('aria-label')) {
            if (!control.hasAttribute('data-ig-aria')) control.setAttribute('data-ig-aria', control.getAttribute('aria-label'));
            control.setAttribute('aria-label', on ? 'In workspace “' + c.name + '”' : control.getAttribute('data-ig-aria'));
        }
    }
    function markWhen(control) {
        var want = control.getAttribute('data-intel-graph-when');
        var off = stateOf(control) !== want;
        control.hidden = off;
        // The launch bar's filter would show it again otherwise
        control.toggleAttribute('data-lb-off', off);
    }
    function markAll() {
        document.querySelectorAll('[data-intel-graph-add]').forEach(markAdd);
        document.querySelectorAll('[data-intel-graph-when]').forEach(markWhen);
    }

    // Keys for every control not keyed yet, then one question for what
    // nobody asked.
    var scanTimer = 0;
    function scanSoon() {
        clearTimeout(scanTimer);
        scanTimer = setTimeout(scan, 60);
    }
    function scan() {
        if (!IG() || !keyed) return;
        var controls = Array.prototype.slice.call(document.querySelectorAll('[data-intel-graph-add]:not([data-intel-graph-stateless]), [data-intel-graph-when]'));
        var fresh = controls.filter(function (c) { return !keyed.has(c); });
        Promise.all(fresh.map(function (control) {
            var items = itemsOf(control);
            keyed.set(control, null);
            if (!items || items.length !== 1) return null;
            return IG().keyOf(items[0]).then(function (key) { keyed.set(control, key); });
        })).then(function () {
            markAll();
            if (!IG().active()) return null;
            var items = [];
            controls.forEach(function (control) {
                var key = keyOfControl(control);
                if (key && IG().holds(key) === undefined) items.push(itemsOf(control)[0]);
            });
            return items.length ? IG().lookup(items) : null;
        }).then(markAll, markAll);
    }

    /* ── the split button's menu ───────────────────────────── */
    function menuItem(text, iconCls, attr, items, danger) {
        var li = el('li');
        var b = el('button', 'dropdown-item ig-add-item' + (danger ? ' ig-add-item-danger' : ''));
        b.type = 'button';
        b.appendChild(icon(iconCls));
        b.appendChild(el('span', null, text));
        b.setAttribute(attr, JSON.stringify(items));
        if (attr === 'data-intel-graph-add') b.setAttribute('data-intel-graph-stateless', '');
        li.appendChild(b);
        return li;
    }
    function menuHead(text) {
        var li = el('li');
        li.appendChild(el('h6', 'dropdown-header', text));
        return li;
    }
    function menuDivider() {
        var li = el('li');
        li.appendChild(el('hr', 'dropdown-divider'));
        return li;
    }
    function collectEntries(menu, items) {
        menu.appendChild(menuItem('Add to another collection…', 'fas fa-folder-plus', 'data-intel-graph-other', items));
        menu.appendChild(menuItem(items.length > 1 ? 'New collection with these…' : 'New collection with this…', 'fas fa-circle-plus', 'data-intel-graph-new', items));
    }
    // A main part may name what it carries (data-intel-graph-set) and offer
    // other sets of records (data-intel-graph-alt, [{label, items}]), each
    // with the same three entries under its name.
    function fillMenu(split) {
        var main = split.querySelector('[data-intel-graph-add]');
        var menu = split.querySelector('.dropdown-menu');
        var items = main && itemsOf(main);
        if (!menu || !items) return;
        menu.textContent = '';
        var alt = parse(main.getAttribute('data-intel-graph-alt') || 'null') || [];
        if (alt.length) {
            menu.appendChild(menuHead(main.getAttribute('data-intel-graph-set') || ''));
            collectEntries(menu, items);
            alt.forEach(function (set) {
                if (!set || !Array.isArray(set.items) || !set.items.length) return;
                menu.appendChild(menuDivider());
                menu.appendChild(menuHead(set.label || ''));
                menu.appendChild(menuItem('Add to the workspace', 'misp-icon misp-icon-analyst-graph misp-simple', 'data-intel-graph-add', set.items));
                collectEntries(menu, set.items);
            });
            return;
        }
        if (stateOf(main) === 'in') {
            var head = el('li');
            var h = el('h6', 'dropdown-header ig-add-head');
            h.appendChild(icon('fas fa-check'));
            h.appendChild(el('span', null, 'In your workspace “' + workspaceName() + '”'));
            head.appendChild(h);
            menu.appendChild(head);
            menu.appendChild(menuItem('Show in the dock', 'fas fa-location-crosshairs', 'data-intel-graph-reveal', items));
            menu.appendChild(menuItem('Remove from workspace', 'fas fa-folder-minus', 'data-intel-graph-remove', items, true));
            menu.appendChild(menuDivider());
        }
        collectEntries(menu, items);
    }
    function caretOf(split) {
        return split.querySelector('[data-bs-toggle="dropdown"]');
    }
    document.addEventListener('show.bs.dropdown', function (e) {
        var split = e.target.closest && e.target.closest(SPLIT);
        if (split) fillMenu(split);
    });
    function openMenu(split) {
        var caret = caretOf(split);
        if (!caret || !window.bootstrap || !window.bootstrap.Dropdown) return;
        // After this click: Bootstrap closes open menus on a click outside them.
        setTimeout(function () { window.bootstrap.Dropdown.getOrCreateInstance(caret).show(); }, 0);
    }

    /* ── the actions ───────────────────────────────────────── */
    function add(items, origin) {
        if (!IG() || !items || !items.length) return Promise.resolve(null);
        // A refusal lands in the dock's arrivals too.
        return IG().add(items, { origin: origin }).catch(function () { return null; });
    }

    function reveal(items) {
        if (IG()) IG().reveal(items);
    }

    function remove(items) {
        var name = workspaceName();
        return IG().remove(items).then(function (report) {
            var gone = (report.removed || []).length;
            toast(gone
                ? (items.length === 1 ? 'Removed ' + describe(items) : 'Removed ' + gone + ' records') + ' from your workspace “' + name + '”.'
                : 'Your workspace “' + name + '” did not hold it any more.', gone ? 'success' : 'info');
            return report;
        }, function (err) {
            toast('Not removed from “' + name + '”: ' + failure(err), 'danger');
        });
    }

    // Add to another collection…: one record in the collection modal, several
    // in the chooser.
    function other(items, origin) {
        if (items.length === 1 && MODAL_TYPES[items[0].type] && typeof window.openModal === 'function') {
            var item = items[0];
            var address = item.type === 'Value' ? IG().keyOf(item).then(function (k) { return k && k.slice('Value:'.length); }) : Promise.resolve(item.uuid);
            return address.then(function (a) {
                if (!a) return;
                window.openModal(baseurl() + '/collectionElements/addElementToCollection/' + MODAL_TYPES[item.type] + '/' + encodeURIComponent(a), 'xl');
            });
        }
        dialog('pick', items, origin);
        return Promise.resolve();
    }

    function newWith(items, origin) {
        dialog('new', items, origin);
    }

    // What an add to a collection that is not the workspace did.
    function sayAdded(report, name) {
        var added = (report.added || []).length, present = (report.present || []).length, refused = (report.refused || []).length;
        var parts = [];
        if (added) parts.push((added === 1 ? '1 record' : added + ' records') + ' added to “' + name + '”');
        if (present) parts.push((present === 1 ? '1 was' : present + ' were') + ' in it already');
        if (refused) parts.push(refused + ' not added' + (report.refused[0] && report.refused[0].error ? ' (' + report.refused[0].error + ')' : ''));
        toast((parts.join('; ') || 'Nothing added to “' + name + '”') + '.', refused && !added ? 'warning' : 'success');
    }

    /* ── the dialog ────────────────────────────────────────── */
    // mode 'pick': Add to another collection…, the list and New collection…
    // under it. mode 'new': New collection with this…, the form alone.
    function dialog(mode, items, origin) {
        var template = document.getElementById('ig-collect-dialog');
        if (!template || !window.bootstrap || !window.bootstrap.Modal || !window.IntelGraphChooser) return;
        var root = template.content.firstElementChild.cloneNode(true);
        document.body.appendChild(root);
        var title = root.querySelector('[data-ig-collect-title]');
        var sub = root.querySelector('.ig-collect-sub');
        var body = root.querySelector('[data-ig-collect-body]');
        var what = describe(items);
        var modal = window.bootstrap.Modal.getOrCreateInstance(root);
        root.addEventListener('hidden.bs.modal', function () {
            modal.dispose();
            root.remove();
        });
        function created(c, activate, name) {
            modal.hide();
            var report = c && c.report;
            var n = report ? (report.added || []).length + (report.present || []).length : 0;
            toast('“' + name + '” created with ' + (n === 1 ? '1 record' : n + ' records')
                + (activate ? '. It is your workspace.' : '.'));
            if (report && report.refused && report.refused.length) sayAdded({ refused: report.refused }, name);
        }
        var formOptions = {
            create: function (values, activate) {
                return IG().createCollection(values, { activate: activate, items: items, origin: origin });
            },
            done: created
        };
        if (mode === 'new') {
            title.textContent = 'New collection';
            sub.textContent = 'With ' + what + '.';
            var form = window.IntelGraphChooser.form(Object.assign({ label: 'Name', submit: 'Create' }, formOptions));
            body.appendChild(form);
            root.addEventListener('shown.bs.modal', function () { form.focusName(); });
        } else {
            title.textContent = 'Add to a collection';
            sub.textContent = what.charAt(0).toUpperCase() + what.slice(1) + '. Your workspace stays as it is.';
            window.IntelGraphChooser.fill(body, {
                scope: 'org',
                others: true,
                onPick: function (c) {
                    IG().add(items, { collection: c.uuid, origin: origin }).then(function (out) {
                        modal.hide();
                        sayAdded(out.report || {}, c.name);
                    }, function (err) {
                        toast('Not added to “' + c.name + '”: ' + failure(err), 'danger');
                    });
                },
                form: Object.assign({ label: 'Or a new collection', submit: 'Create' }, formOptions)
            });
            root.addEventListener('shown.bs.modal', function () {
                var first = body.querySelector('.ig-so-pick, input');
                if (first) first.focus();
            });
        }
        modal.show();
    }

    /* ── clicks ────────────────────────────────────────────── */
    // On the way down: a dropdown closes on this same click before it
    // bubbles here, and leaves the control no box to fly from.
    document.addEventListener('click', function (e) {
        var control = e.target.closest && e.target.closest(CARRIERS);
        if (!control) return;
        var items = itemsOf(control);
        e.preventDefault();
        if (!items) return;
        if (control.hasAttribute('data-intel-graph-add')) {
            if (stateOf(control) === 'in') {
                var split = control.closest(SPLIT);
                if (split) openMenu(split);
                else reveal(items);
                return;
            }
            add(items, control);
        } else if (control.hasAttribute('data-intel-graph-reveal')) {
            reveal(items);
        } else if (control.hasAttribute('data-intel-graph-remove')) {
            remove(items);
        } else if (control.hasAttribute('data-intel-graph-other')) {
            other(items, control);
        } else if (control.hasAttribute('data-intel-graph-new')) {
            newWith(items, control);
        }
    }, true);

    // The collection modal saved: a record added to the workspace through it
    // is in the workspace.
    document.addEventListener('misp:collection-element-added', function (e) {
        var d = e.detail || {};
        var a = IG() && IG().active();
        if (!a || d.collectionId == null || String(d.collectionId) !== String(a.Collection.id) || !d.uuid) return;
        IG().markHeld([(d.type === 'AttributeValue' ? 'Value' : d.type) + ':' + lower(d.uuid)], []);
        IG().refreshActive();
    });

    /* ── make it my workspace ──────────────────────────────── */
    function isWorkspace(uuid) {
        var a = IG() && IG().active();
        return !!a && lower(a.Collection.uuid) === lower(uuid);
    }

    // Its labels, the tile's and the menu's, say whether it is the workspace.
    function markWorkspaceControls() {
        document.querySelectorAll('[data-intel-graph-workspace]').forEach(function (control) {
            var on = isWorkspace(control.getAttribute('data-intel-graph-workspace'));
            if (!control.hasAttribute('data-ig-label')) control.setAttribute('data-ig-label', control.getAttribute('title') || 'Make it my workspace');
            var label = on ? 'Your workspace' : control.getAttribute('data-ig-label');
            control.setAttribute('aria-pressed', on ? 'true' : 'false');
            control.setAttribute('title', on ? 'Your workspace: “Add to workspace” feeds it' : label);
            control.setAttribute('aria-label', label);
            control.querySelectorAll('.lb-tile-lbl, .lb-lbl').forEach(function (span) {
                if (!span.hasAttribute('data-ig-label')) span.setAttribute('data-ig-label', span.textContent);
                // A tile has room for a word
                var current = span.classList.contains('lb-tile-lbl') ? 'Workspace ✓' : 'Your workspace';
                span.textContent = on ? current : span.getAttribute('data-ig-label');
            });
        });
    }

    document.addEventListener('click', function (e) {
        var control = e.target.closest && e.target.closest('[data-intel-graph-workspace]');
        if (!control) return;
        e.preventDefault();
        var uuid = control.getAttribute('data-intel-graph-workspace');
        if (!IG() || !uuid || isWorkspace(uuid)) return;
        IG().setActive(uuid).then(function (workspace) {
            toast('“' + workspace.Collection.name + '” is your workspace: “Add to workspace” feeds it.');
        }, function (err) {
            toast('Could not make it your workspace: ' + failure(err), 'danger');
        });
    });

    /* ── wiring ────────────────────────────────────────────── */
    function boot() {
        if (!IG()) return;
        IG().on('active', function () {
            markWorkspaceControls();
            markAll();
        });
        IG().on('count', markAll);
        IG().on('held', function (d) {
            if (d && d.keys === null) scanSoon();
            else markAll();
        });
        // Rows drawn after the page loaded: a tab, an ajax panel, a page of results.
        if (window.MutationObserver) {
            new MutationObserver(function (records) {
                for (var i = 0; i < records.length; i++) {
                    var nodes = records[i].addedNodes;
                    for (var j = 0; j < nodes.length; j++) {
                        var n = nodes[j];
                        if (n.nodeType === 1 && (n.matches(CARRIERS + ', [data-intel-graph-when]') || n.querySelector(CARRIERS + ', [data-intel-graph-when]'))) {
                            scanSoon();
                            return;
                        }
                    }
                }
            }).observe(document.body, { childList: true, subtree: true });
        }
        markWorkspaceControls();
        scan();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
    else boot();

    window.IntelGraphActions = {
        add: add,
        other: other,
        newWith: newWith,
        remove: remove,
        reveal: reveal,
        state: state,
        lookup: function (items) { return IG() ? IG().lookup(items).then(function () { markAll(); }) : Promise.resolve(); },
        describe: describe
    };
}());
