<?php
$eventId  = h($data['Event']['id'] ?? '');
$uid      = 'evt-wl-' . $eventId;
$fetchUrl = h($baseurl . '/events/viewWarninglistHits/' . $eventId);
$indexUrl = h($baseurl . '/warninglists/index');
$attrsUrl = h($baseurl . '/events/viewAttributes/' . $eventId);
?>

<div class="card shadow-sm mb-3" id="warninglist-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:var(--warninglist-soft);">
                <i class="fas fa-exclamation-triangle"
                   style="color:var(--warninglist);font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Warning Lists') ?></div>
                <div class="small text-muted mt-1"
                     id="<?= $uid ?>-count">…</div>
            </div>
            <a href="<?= $indexUrl ?>"
               id="<?= $uid ?>-manage"
               class="btn btn-sm btn-outline-secondary d-flex
                      align-items-center gap-1"
               title="<?= __('Manage warning lists') ?>">
                <i class="fas fa-external-link-alt"></i>
            </a>
        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $uid ?>-body">
        <div class="text-center py-4 text-muted">
            <div class="spinner-border spinner-border-sm" role="status"></div>
        </div>
    </div>

</div>

<script>
(function () {
    var uid      = <?= json_encode($uid) ?>;
    var eventId  = <?= json_encode($eventId) ?>;
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var indexUrl = <?= json_encode($indexUrl) ?>;
    var attrsUrl = <?= json_encode($attrsUrl) ?>;
    var bodyEl   = document.getElementById(uid + '-body');
    var countEl  = document.getElementById(uid + '-count');
    var manageEl = document.getElementById(uid + '-manage');

    var L_NONE   = <?= json_encode(__('No hits')) ?>;
    var L_ONE    = <?= json_encode(__('list hit')) ?>;
    var L_MANY   = <?= json_encode(__('list hits')) ?>;
    var L_ALL    = <?= json_encode(__('Manage warning lists')) ?>;
    var L_HITS   = <?= json_encode(
        __('Manage the warning lists hit by this event')
    ) ?>;
    var L_FAIL   = <?= json_encode(__('Could not load warning list hits.')) ?>;

    if (!bodyEl) { return; }

    function setManageTarget(ids) {
        if (!manageEl) { return; }
        if (ids.length) {
            manageEl.setAttribute('href', indexUrl + '/id:' + ids.join('||'));
            manageEl.setAttribute('title', L_HITS);
        } else {
            manageEl.setAttribute('href', indexUrl);
            manageEl.setAttribute('title', L_ALL);
        }
    }

    function setCount(total) {
        if (!countEl) { return; }
        countEl.textContent = total === 0
            ? L_NONE
            : total + ' ' + (total === 1 ? L_ONE : L_MANY);
    }

    function showFlaggedAttributes(warninglistId) {
        var url  = attrsUrl + '/warninglist:'
            + encodeURIComponent(warninglistId);
        var link = document.querySelector(
            '.nav-link[href="#tab-attributes"]'
        );
        var pane = document.getElementById('tab-attributes');
        var cont = pane ? pane.querySelector(
            '.ajax-tab-content[data-url*="viewAttributes"]'
        ) : null;
        if (!link || !cont) { return; }

        if (cont.dataset.loaded && typeof reloadAjaxTabIndex === 'function') {
            reloadAjaxTabIndex(cont, url);
        } else {
            cont.dataset.url = url;
        }
        bootstrap.Tab.getOrCreateInstance(link).show();
    }

    function refresh() {
        return fetch(fetchUrl, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            cache: 'no-store'
        })
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                return r.text();
            })
            .then(function (html) {
                bodyEl.innerHTML = html;
                var root = bodyEl.querySelector('[data-wl-count]');
                if (!root) { return; }
                setCount(parseInt(root.getAttribute('data-wl-count'), 10) || 0);
                setManageTarget(
                    (root.getAttribute('data-wl-ids') || '')
                        .split(',')
                        .filter(Boolean)
                );
            })
            .catch(function () {
                bodyEl.innerHTML =
                    '<div class="text-center text-muted py-4 small">'
                    + '<i class="fas fa-exclamation-triangle me-2"></i>'
                    + L_FAIL
                    + '</div>';
                if (countEl) { countEl.textContent = ''; }
            });
    }

    // Delegated so it survives every refresh of the card body.
    bodyEl.addEventListener('click', function (e) {
        var row = e.target.closest('[data-wl-id]');
        if (!row || !bodyEl.contains(row)) { return; }
        e.preventDefault();
        showFlaggedAttributes(row.getAttribute('data-wl-id'));
    });

    // Hits are recomputed from the event's attributes on every call
    window.reloadWarninglistCard = refresh;
    document.addEventListener('misp:attributes-changed', refresh);

    // Restore the page as it was, without re-running anything 
    window.addEventListener('pageshow', function (e) {
        if (e.persisted) { refresh(); }
    });

    refresh();
}());
</script>
