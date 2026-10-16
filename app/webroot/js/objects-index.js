/*
 * Objects index: a row opens in place into the object's attributes, fetched
 * once from objects/indexCard/<id> and kept for the next toggle.
 *
 * Delegated on the document: the filter bar swaps the results block without a
 * page load, and this script runs before the table exists.
 */
(function () {
    'use strict';

    function detailOf(tr) {
        var next = tr.nextElementSibling;
        return next && next.classList.contains('oi-detail') ? next : null;
    }

    function toggle(button) {
        var tr = button.closest('tr');
        var index = button.closest('.oi-index');
        if (!tr || !index) {
            return;
        }
        var open = button.getAttribute('aria-expanded') === 'true';
        var detail = detailOf(tr);
        button.setAttribute('aria-expanded', open ? 'false' : 'true');
        tr.classList.toggle('oi-open', !open);
        if (detail) {
            detail.hidden = open;
            return;
        }
        if (open) {
            return;
        }
        detail = document.createElement('tr');
        detail.className = 'oi-detail';
        var cell = document.createElement('td');
        cell.colSpan = tr.children.length;
        var box = document.createElement('div');
        box.className = 'oi-detail-box';
        box.dataset.url = index.dataset.oiCardUrl + button.dataset.oiExpand;
        box.innerHTML = '<div class="misp-loader misp-loader-sm" role="status"></div>';
        cell.appendChild(box);
        detail.appendChild(cell);
        tr.insertAdjacentElement('afterend', detail);
        loadAjaxContainer(box);
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
