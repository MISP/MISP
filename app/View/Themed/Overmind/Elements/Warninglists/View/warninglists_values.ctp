<?php
/*
 * The warninglist's values. A list can hold a million of them, so they are
 * never rendered with the page: warninglists/viewEntries serves them one
 * page at a time, filtered on the server.
 */
$warninglist = $data['Warninglist'] ?? [];
$count = (int)($entryCount ?? 0);
$entriesUrl = $baseurl . '/warninglists/viewEntries/' . (int)$warninglist['id'];
?>
<div class="card mb-3 shadow-sm" data-wl-values data-url="<?= h($entriesUrl) ?>">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:color-mix(in srgb, var(--warninglist) 14%, transparent);color:var(--warninglist);">
                    <i class="fas fa-list"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Values') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s value', '%s values', $count, number_format($count, 0, ',', ' '))) ?>
                    </div>
                </div>
            </div>
            <?php if ($count > 1): ?>
                <div class="input-group input-group-sm" style="max-width:260px;">
                    <span class="input-group-text border-end-0 bg-body">
                        <i class="fas fa-search text-muted small"></i>
                    </span>
                    <input type="search" class="form-control border-start-0 ps-0" maxlength="512"
                           data-wl-search autocomplete="off"
                           placeholder="<?= h(__('Filter values…')) ?>"
                           aria-label="<?= h(__('Filter values')) ?>">
                </div>
            <?php endif; ?>
        </div>
    </div>
    <div data-wl-body>
        <div class="text-center p-4"><div class="spinner-border spinner-border-sm text-body-secondary"></div></div>
    </div>
</div>

<script>
(function () {
    document.querySelectorAll('[data-wl-values]:not([data-wl-bound])').forEach(function (card) {
        card.setAttribute('data-wl-bound', '');
        var body = card.querySelector('[data-wl-body]');
        var search = card.querySelector('[data-wl-search]');
        var state = { q: '', page: 1 };
        var pending = null;

        function load() {
            if (pending) {
                pending.abort();
            }
            pending = new AbortController();
            var url = card.dataset.url + '?page=' + state.page + '&q=' + encodeURIComponent(state.q);
            body.style.opacity = '.5';
            fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' }, signal: pending.signal, credentials: 'same-origin' })
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error(response.status);
                    }
                    return response.text();
                })
                .then(function (html) {
                    body.innerHTML = html;
                    body.style.opacity = '';
                })
                .catch(function (error) {
                    if (error.name === 'AbortError') {
                        return;
                    }
                    body.style.opacity = '';
                    body.innerHTML = '<div class="text-center text-danger small py-4"><?= h(__('Could not load the values.')) ?></div>';
                });
        }

        body.addEventListener('click', function (event) {
            var button = event.target.closest('[data-wl-page]');
            if (!button || button.disabled) {
                return;
            }
            state.page = parseInt(button.dataset.wlPage, 10) || 1;
            load();
        });
        if (search) {
            var debounce;
            search.addEventListener('input', function () {
                clearTimeout(debounce);
                debounce = setTimeout(function () {
                    state.q = search.value.trim();
                    state.page = 1;
                    load();
                }, 250);
            });
        }
        load();
    });
})();
</script>
