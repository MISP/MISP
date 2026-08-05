<?php
$eventId      = h($data['Event']['id'] ?? '');
$uid          = 'evt-sightings-' . $eventId;
$fetchUrl     = h($baseurl . '/events/viewEventSightings/' . $eventId);
$mayModify    = $this->Acl->canModifyEvent($data);
?>

<div class="card shadow-sm mb-3" id="sightings-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#89009640;">
                <span class="misp-icon misp-icon-sighting misp-simple" style="color:#890096;font-size:1rem;"></span>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Sightings') ?></div>
                <div class="small text-muted mt-1"
                     id="<?= $uid ?>-count">…</div>
            </div>
            <a href=""
               class="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
               title="<?= __('Full sightings list') ?>">
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
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var countEl  = document.getElementById(uid + '-count');

    fetch(fetchUrl)
        .then(function (r) {
            if (!r.ok) { throw new Error(r.status); }
            return r.text();
        })
        .then(function (html) {
            document.getElementById(uid + '-body').innerHTML = html;
            var root = document.getElementById(uid + '-body')
                .querySelector('[data-sighting-total]');
            if (root && countEl) {
                var total = parseInt(
                    root.getAttribute('data-sighting-total'), 10
                );
                countEl.textContent = total === 0
                    ? <?= json_encode(__('No sightings')) ?>
                    : total + ' ' + <?= json_encode(__('sightings')) ?>;
            }
        })
        .catch(function () {
            document.getElementById(uid + '-body').innerHTML =
                '<div class="text-center text-muted py-4 small">'
                + '<i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(__('Could not load sightings.')) ?>
                + '</div>';
            if (countEl) { countEl.textContent = ''; }
        });
}());

/* Shared helper — only defined once even if card re-renders */
if (typeof sightingAdd === 'undefined') {
    window.sightingAdd = function (eventId, type, uid, url) {
        var token = document.querySelector(
            'meta[name="csrf-token"]'
        );
        var headers = { 'Content-Type': 'application/json' };
        if (token) {
            headers['X-CSRF-Token'] = token.content;
        }
        fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: headers,
            body: JSON.stringify({ type: type, id: eventId })
        })
        .then(function (r) { return r.json(); })
        .then(function (resp) {
            if (resp.saved) {
                /* Refresh the body */
                var fetchUrl = url.replace(
                    '/sightings/add/',
                    '/events/viewEventSightings/'
                );
                fetch(fetchUrl)
                    .then(function (r) { return r.text(); })
                    .then(function (html) {
                        var body = document.getElementById(
                            uid + '-body'
                        );
                        if (body) { body.innerHTML = html; }
                        var root = body
                            ? body.querySelector(
                                '[data-sighting-total]'
                            )
                            : null;
                        var countEl = document.getElementById(
                            uid + '-count'
                        );
                        if (root && countEl) {
                            var total = parseInt(
                                root.getAttribute(
                                    'data-sighting-total'
                                ), 10
                            );
                            countEl.textContent = total === 0
                                ? 'No sightings'
                                : total + ' sightings';
                        }
                    });
            }
        })
        .catch(function () {});
    };
}
</script>
