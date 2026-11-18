/*
 * Objects index: a table row, or a card, opens in place into the object's
 * attributes, fetched once from objects/indexCard/<id> (as a table for a row)
 * and kept for the next toggle. The event's Objects tab draws them with the page instead, so there
 * is nothing to fetch.
 *
 * Delegated on the document: the filter bar swaps the results block without a
 * page load, and this script runs before the table exists.
 *
 *   ObjectsIndex.setOpen(button, open)  open or close from code; every change
 *                                       fires a bubbling `oi:toggle` with
 *                                       { id, open } on the button
 *   ObjectsIndex.bindList(scope, key)   wire a list drawn as both a table and
 *                                       cards (see bindList)
 */
(function () {
    'use strict';

    if (window.ObjectsIndex) {
        return;
    }

    function loaderBox(url) {
        var box = document.createElement('div');
        box.className = 'oi-detail-box';
        box.dataset.url = url;
        box.innerHTML = '<div class="misp-loader misp-loader-sm" role="status"></div>';
        return box;
    }

    // The detail row under a table row, created on first open.
    function rowTarget(tr, url) {
        var next = tr.nextElementSibling;
        if (next && next.classList.contains('oi-detail')) {
            return { node: next, box: null };
        }
        var detail = document.createElement('tr');
        detail.className = 'oi-detail';
        var cell = document.createElement('td');
        cell.colSpan = tr.children.length;
        var box = loaderBox(url);
        cell.appendChild(box);
        detail.appendChild(cell);
        tr.insertAdjacentElement('afterend', detail);
        return { node: detail, box: box };
    }

    // The attribute slot at the bottom of a card, filled on first open.
    function tileTarget(tile, url) {
        var slot = tile.querySelector('.oi-tile-attrs');
        if (slot.firstElementChild) {
            return { node: slot, box: null };
        }
        var box = loaderBox(url);
        slot.appendChild(box);
        return { node: slot, box: box };
    }

    function setOpen(button, open) {
        var index = button.closest('.oi-index');
        var tr = button.closest('tr');
        var tile = tr ? null : button.closest('.oi-tile');
        if (!index || (!tr && !tile) || (button.getAttribute('aria-expanded') === 'true') === open) {
            return;
        }
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (tr) {
            tr.classList.toggle('oi-open', open);
        }
        var url = index.dataset.oiCardUrl + button.dataset.oiExpand + (tr ? '?view=table' : '');
        var target = tr ? rowTarget(tr, url) : tileTarget(tile, url);
        target.node.hidden = !open;
        if (target.box) {
            loadAjaxContainer(target.box);
        }
        button.dispatchEvent(new CustomEvent('oi:toggle', {
            bubbles: true,
            detail: { id: button.dataset.oiExpand, open: open }
        }));
    }

    /*
     * A list drawn whole as a table (#objTableView) and as cards (#objCardView)
     * inside `scope`, the event's Objects tab or a remote event preview's: an
     * object's two toggles move together, Expand all / Collapse all
     * (.obj-expand-all, .obj-collapse-all) reach every object, and the view
     * buttons switch the two. Those buttons (#viewList, #viewCard) repeat in
     * every tab's filter bar, so they are taken over within `scope` only.
     * `openKey` keeps the open objects in sessionStorage across page loads.
     */
    function bindList(scope, openKey) {
        function setObjectOpen(id, open) {
            scope.querySelectorAll('.oi-index [data-oi-expand="' + id + '"]').forEach(function (button) {
                setOpen(button, open);
            });
        }
        function readOpen() {
            if (!openKey) return [];
            try { return JSON.parse(sessionStorage.getItem(openKey) || '[]'); } catch (e) { return []; }
        }
        function writeOpen(ids) {
            if (!openKey) return;
            try { sessionStorage.setItem(openKey, JSON.stringify(ids)); } catch (e) {}
        }
        // On the list's own root, which an ajax reload replaces, so the
        // listener never stacks up.
        var root = scope.querySelector('#objectListContainer');
        if (root) {
            root.addEventListener('oi:toggle', function (e) {
                var id = e.detail.id;
                var ids = readOpen().filter(function (x) { return x !== id; });
                if (e.detail.open) ids.push(id);
                writeOpen(ids);
                setObjectOpen(id, e.detail.open);
            });
        }
        readOpen().forEach(function (id) { setObjectOpen(id, true); });

        [['.obj-expand-all', true], ['.obj-collapse-all', false]].forEach(function (pair) {
            var btn = scope.querySelector(pair[0]);
            if (!btn) return;
            btn.addEventListener('click', function () {
                scope.querySelectorAll('.oi-index [data-oi-expand]').forEach(function (button) {
                    setOpen(button, pair[1]);
                });
            });
        });

        function applyView(mode, animate) {
            var list = scope.querySelector('#objTableView');
            var cards = scope.querySelector('#objCardView');
            if (!list || !cards) return;
            var showCards = mode === 'card';
            list.classList.toggle('d-none', showCards);
            cards.classList.toggle('d-none', !showCards);
            var btnList = scope.querySelector('#viewList');
            var btnCard = scope.querySelector('#viewCard');
            if (btnList) btnList.classList.toggle('active', !showCards);
            if (btnCard) btnCard.classList.toggle('active', showCards);
            if (animate && typeof animateIndexView === 'function') {
                animateIndexView(showCards ? cards : list);
            }
        }
        // Own storage key: 'indexViewMode' drives the scaffold indexes, and an
        // object card is a different trade-off from an attribute card.
        [['#viewList', 'table'], ['#viewCard', 'card']].forEach(function (pair) {
            var btn = scope.querySelector(pair[0]);
            if (!btn) return;
            var fresh = btn.cloneNode(true);
            btn.parentNode.replaceChild(fresh, btn);
            fresh.addEventListener('click', function () {
                try { localStorage.setItem('objectsViewMode', pair[1]); } catch (e) {}
                applyView(pair[1], true);
            });
        });
        var saved = 'table';
        try { saved = localStorage.getItem('objectsViewMode') || 'table'; } catch (e) {}
        applyView(saved, false);
    }

    window.ObjectsIndex = { setOpen: setOpen, bindList: bindList };

    document.addEventListener('click', function (e) {
        var target = e.target;
        if (!target || !target.closest) {
            return;
        }
        var button = target.closest('.oi-index [data-oi-expand]');
        if (!button) {
            var cell = target.closest('.oi-index td.oi-col-object');
            if (!cell || target.closest('a, button, input, .dropdown')) {
                return;
            }
            button = cell.querySelector('[data-oi-expand]');
        }
        if (button) {
            e.preventDefault();
            setOpen(button, button.getAttribute('aria-expanded') !== 'true');
        }
    });
}());
