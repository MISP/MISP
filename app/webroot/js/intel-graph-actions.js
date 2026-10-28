// "Add to workspace". Every control on the page that carries
// data-intel-graph-add — a JSON list of items as IntelGraph.add() takes them,
// each with a label — sends them to the workspace's collection. With no
// workspace the dock asks which one, and makes it the workspace.
//
// What was added is said by the dock: its arrivals when it is open, the
// navbar slot's badge while it is closed.
//
// A control carrying data-intel-graph-workspace, a collection's uuid, makes
// that collection the workspace, and says so while it is.
//
//   IntelGraphActions.add(items, origin)   the same, from code (the explorer's
//                                          menus); origin as IntelGraph.add takes it
//
// Needs intel-graph.js; loaded with it by Elements/intel_graph_boot.ctp.

(function () {
    'use strict';

    function add(items, origin) {
        var IG = window.IntelGraph;
        if (!IG || !items || !items.length) return Promise.resolve(null);
        // A refusal lands in the dock's arrivals too.
        return IG.add(items, { origin: origin }).catch(function () { return null; });
    }

    document.addEventListener('click', function (e) {
        var control = e.target.closest && e.target.closest('[data-intel-graph-add]');
        if (!control) return;
        e.preventDefault();
        var items;
        try {
            items = JSON.parse(control.getAttribute('data-intel-graph-add'));
        } catch (err) {
            return;
        }
        if (!Array.isArray(items)) return;
        add(items, control);
    // On the way down: a dropdown closes on this same click before it
    // bubbles here, and leaves the control no box to fly from.
    }, true);

    function toast(text, variant) {
        if (typeof window.showToast === 'function') window.showToast(text, variant || 'success');
    }

    function isWorkspace(uuid) {
        var a = window.IntelGraph && window.IntelGraph.active();
        return !!a && String(a.Collection.uuid).toLowerCase() === String(uuid).toLowerCase();
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
        var IG = window.IntelGraph;
        var uuid = control.getAttribute('data-intel-graph-workspace');
        if (!IG || !uuid || isWorkspace(uuid)) return;
        IG.setActive(uuid).then(function (workspace) {
            toast('“' + workspace.Collection.name + '” is your workspace: “Add to workspace” feeds it.');
        }, function (err) {
            toast('Could not make it your workspace: ' + ((err && err.message) || 'error'), 'danger');
        });
    });

    document.addEventListener('intel-graph:active', markWorkspaceControls);
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', markWorkspaceControls);
    else markWorkspaceControls();

    window.IntelGraphActions = { add: add };
}());
