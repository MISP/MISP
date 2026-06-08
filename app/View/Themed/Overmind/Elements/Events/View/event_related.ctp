<?php
$eventId  = h($data['Event']['id'] ?? '');
$uid      = 'evt-related-' . $eventId;
$fetchUrl = h($baseurl . '/events/viewRelatedEvents/' . $eventId);
?>

<div class="card shadow-sm mb-3" id="related-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#fbffc8;">
                <i class="fas fa-link" style="color:#848b1b;font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Related Events') ?></div>
                <div class="small text-muted mt-1"
                     id="<?= $uid ?>-count">…</div>
            </div>
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
                .querySelector('[data-related-count]');
            if (root && countEl) {
                var total = parseInt(
                    root.getAttribute('data-related-count'), 10
                );
                countEl.textContent = total === 0
                    ? <?= json_encode(__('No correlations')) ?>
                    : total + ' ' + (
                        total === 1
                            ? <?= json_encode(__('related event')) ?>
                            : <?= json_encode(__('related events')) ?>
                    );
            }
        })
        .catch(function () {
            document.getElementById(uid + '-body').innerHTML =
                '<div class="text-center text-muted py-4 small">'
                + '<i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(__('Could not load related events.')) ?>
                + '</div>';
            if (countEl) { countEl.textContent = ''; }
        });
}());
</script>
