/*
 * The counts an event preview index (Feeds and Servers preview_index.ctp)
 * leaves pending: `.te-index[data-counts-url]` names the endpoint, each
 * pending row its key (data-primary-id) and timestamp (data-ts). Four events
 * a request, three requests at a time; only the pending cells change.
 */
(function () {
    var cells = { attributes: '.te-c-attrs', objects: '.te-c-objs' };

    function run() {
        var index = document.querySelector('.te-index[data-counts-url]');
        if (!index) return;
        var url = index.getAttribute('data-counts-url');
        var failed = index.getAttribute('data-counts-failed') || '';
        var rows = Array.prototype.filter.call(index.querySelectorAll('tr[data-primary-id]'), function (tr) {
            return tr.querySelector('.te-pending');
        });
        var batches = [];
        for (var i = 0; i < rows.length; i += 4) {
            batches.push(rows.slice(i, i + 4));
        }

        function settle(tr, block) {
            Object.keys(cells).forEach(function (count) {
                var cell = tr.querySelector(cells[count]);
                if (!cell || !cell.querySelector('.te-pending')) return;
                var piece = block && block.querySelector('[data-count="' + count + '"]');
                if (piece) {
                    cell.innerHTML = piece.innerHTML;
                    return;
                }
                var none = document.createElement('span');
                none.className = 'te-zero';
                none.title = failed;
                none.textContent = '—';
                cell.replaceChildren(none);
            });
        }

        function fill(batch) {
            var tokens = batch.map(function (tr) { return tr.dataset.primaryId + ':' + (tr.dataset.ts || 0); });
            return fetch(url + '?events=' + encodeURIComponent(tokens.join(',')), { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (response) {
                    if (!response.ok) throw new Error(response.status);
                    return response.text();
                })
                .then(function (html) {
                    var box = document.createElement('div');
                    box.innerHTML = html;
                    batch.forEach(function (tr) {
                        settle(tr, box.querySelector('[data-key="' + CSS.escape(tr.dataset.primaryId) + '"]:not([data-failed])'));
                    });
                })
                .catch(function () {
                    batch.forEach(function (tr) { settle(tr, null); });
                });
        }

        var next = 0;
        function work() {
            if (next >= batches.length) return null;
            return fill(batches[next++]).then(work);
        }
        for (var w = 0; w < 3; w++) {
            work();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();
