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
                 style="width:36px;height:36px;background:#E67F0D40;">
                <i class="fas fa-link" style="color:#E67F0D;font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Related Events') ?></div>
                <div class="small text-muted mt-1"
                     id="<?= $uid ?>-count">…</div>
            </div>
            <button type="button"
                    class="btn btn-sm btn-outline-secondary"
                    title="<?= h(__('View correlation graph')) ?>"
                    onclick="var t=document.querySelector('[href=\'#tab-correlation\']');if(t){bootstrap.Tab.getOrCreateInstance(t).show();}">
                <i class="fas fa-external-link-alt"></i>
            </button>
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

            var rows = document.getElementById(uid + '-body')
                .querySelectorAll('.related-event-row');
            var limit = 5;
            if (rows.length > limit) {
                for (var i = limit; i < rows.length; i++) {
                    rows[i].classList.add('d-none');
                }
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-sm btn-link w-100 text-muted py-2';
                btn.innerHTML = '<i class="fas fa-chevron-down me-1"></i>'
                    + <?= json_encode(__('Show all')) ?>
                    + ' (' + rows.length + ')';
                btn.addEventListener('click', function () {
                    for (var j = limit; j < rows.length; j++) {
                        rows[j].classList.remove('d-none');
                    }
                    btn.remove();

                    var btnLess = document.createElement('button');
                    btnLess.type = 'button';
                    btnLess.className = 'btn btn-sm btn-link w-100 text-muted py-2';
                    btnLess.innerHTML = '<i class="fas fa-chevron-up me-1"></i>'
                        + <?= json_encode(__('Show less')) ?>;
                    btnLess.addEventListener('click', function () {
                        for (var k = limit; k < rows.length; k++) {
                            rows[k].classList.add('d-none');
                        }
                        btnLess.remove();
                        document.getElementById(uid + '-body').appendChild(btn);
                    });
                    document.getElementById(uid + '-body').appendChild(btnLess);
                });
                document.getElementById(uid + '-body').appendChild(btn);
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
