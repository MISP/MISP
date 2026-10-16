/*
 * Objects index: a table row, or a card, opens in place into the object's
 * attributes, fetched once from objects/indexCard/<id> and kept for the next
 * toggle.
 *
 * Delegated on the document: the filter bar swaps the results block without a
 * page load, and this script runs before the table exists.
 */
(function () {
    'use strict';

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

    function toggle(button) {
        var index = button.closest('.oi-index');
        var tr = button.closest('tr');
        var tile = tr ? null : button.closest('.oi-tile');
        if (!index || (!tr && !tile)) {
            return;
        }
        var open = button.getAttribute('aria-expanded') === 'true';
        button.setAttribute('aria-expanded', open ? 'false' : 'true');
        if (tr) {
            tr.classList.toggle('oi-open', !open);
        }
        var url = index.dataset.oiCardUrl + button.dataset.oiExpand;
        var target = tr ? rowTarget(tr, url) : tileTarget(tile, url);
        target.node.hidden = open;
        if (target.box) {
            loadAjaxContainer(target.box);
        }
    }

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
            toggle(button);
        }
    });
}());
