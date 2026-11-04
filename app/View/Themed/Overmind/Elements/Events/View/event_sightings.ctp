<?php
$eventId  = (int)($data['Event']['id'] ?? 0);
$uid      = 'evt-sightings-' . $eventId;
$fetchUrl = $baseurl . '/events/viewEventSightings/' . $eventId;
$advUrl   = $baseurl . '/sightings/advanced/' . $eventId . '/event';
?>

<div class="card shadow-sm mb-3" id="sightings-card">

    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#89009640;">
                <span class="misp-icon misp-icon-sighting misp-simple" style="color:#890096;font-size:1rem;"></span>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Sightings') ?></div>
                <div class="small text-muted mt-1" id="<?= $uid ?>-count">…</div>
            </div>
            <button type="button"
                    class="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
                    title="<?= __('Sighting details') ?>"
                    aria-label="<?= __('Sighting details') ?>"
                    onclick="openModal('<?= h($advUrl) ?>', 'xl')">
                <i class="fas fa-chart-area"></i>
            </button>
        </div>
    </div>

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
    var msgNone  = <?= json_encode(__('No sightings')) ?>;
    var msgSome  = <?= json_encode(__('%s sightings')) ?>;
    var msgFail  = <?= json_encode(__('Could not load sightings.')) ?>;

    function load() {
        var body    = document.getElementById(uid + '-body');
        var countEl = document.getElementById(uid + '-count');
        if (!body) return;
        fetch(fetchUrl, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status);
                return r.text();
            })
            .then(function (html) {
                body.innerHTML = html;
                var root = body.querySelector('[data-sighting-total]');
                if (root && countEl) {
                    var total = parseInt(root.getAttribute('data-sighting-total'), 10);
                    countEl.textContent = total === 0 ? msgNone : msgSome.replace('%s', total);
                }
            })
            .catch(function () {
                body.innerHTML = '<div class="text-center text-muted py-4 small">'
                    + '<i class="fas fa-exclamation-triangle me-2"></i>' + msgFail + '</div>';
                if (countEl) countEl.textContent = '';
            });
    }

    load();
    if (!window._sightingCardBound) {
        window._sightingCardBound = true;
        document.addEventListener('misp:sighting-change', function () {
            if (window._sightingCardLoad) window._sightingCardLoad();
        });
    }
    window._sightingCardLoad = load;
}());
</script>
