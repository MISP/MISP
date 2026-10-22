// "Add to graph" (PRD §8.3). Every control on the page that carries
// data-intel-graph-add — a JSON list of items as IntelGraph.add() takes them,
// each with a label — sends them to the active graph. With no active graph
// the dock asks which one, and makes it active.
//
// What was added is said by the dock: its arrivals when it is open, the
// navbar slot's badge while it is closed.
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

    window.IntelGraphActions = { add: add };
}());
