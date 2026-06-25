<?php
$eventUuid = h($data['Event']['uuid'] ?? '');
$uid       = 'evt-collections-' . h($data['Event']['id'] ?? '');
$fetchUrl  = h($baseurl . '/collections/getCollectionsForElement/Event/' . $eventUuid . '.json');
$viewBase  = h($baseurl . '/collections/view/');
?>

<div class="card shadow-sm mb-3" id="collections-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#0d6efd40;">
                <i class="fas fa-folder-open" style="color:#0d6efd;font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Collections') ?></div>
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
    var viewBase = <?= json_encode($viewBase) ?>;
    var countEl  = document.getElementById(uid + '-count');
    var bodyEl   = document.getElementById(uid + '-body');

    fetch(fetchUrl, {
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
    })
        .then(function (r) {
            if (!r.ok) { throw new Error(r.status); }
            return r.json();
        })
        .then(function (collections) {
            if (!Array.isArray(collections)) { collections = []; }

            var total = collections.length;
            if (countEl) {
                countEl.textContent = total === 0
                    ? <?= json_encode(__('Not part of any collection')) ?>
                    : total + ' ' + (
                        total === 1
                            ? <?= json_encode(__('collection')) ?>
                            : <?= json_encode(__('collections')) ?>
                    );
            }

            if (total === 0) {
                bodyEl.innerHTML =
                    '<div class="text-center text-muted py-4 small">'
                    + '<i class="fas fa-folder me-2"></i>'
                    + <?= json_encode(__('This event is not part of any collection.')) ?>
                    + '</div>';
                return;
            }

            bodyEl.innerHTML = '';
            collections.forEach(function (collection) {
                var row = document.createElement('a');
                row.href = viewBase + encodeURIComponent(collection.id);
                row.className = 'd-flex align-items-center gap-2 px-3 py-2 '
                    + 'text-decoration-none text-body border-bottom collection-row';
                if (collection.description) {
                    row.title = String(collection.description);
                }

                var icon = document.createElement('i');
                icon.className = 'fas fa-folder text-primary flex-shrink-0';
                row.appendChild(icon);

                var name = document.createElement('span');
                name.className = 'text-truncate';
                name.textContent = collection.name
                    ? String(collection.name)
                    : <?= json_encode(__('Unnamed collection')) ?>;
                row.appendChild(name);

                var chevron = document.createElement('i');
                chevron.className = 'fas fa-chevron-right text-muted small ms-auto';
                row.appendChild(chevron);

                bodyEl.appendChild(row);
            });
        })
        .catch(function () {
            bodyEl.innerHTML =
                '<div class="text-center text-muted py-4 small">'
                + '<i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(__('Could not load collections.')) ?>
                + '</div>';
            if (countEl) { countEl.textContent = ''; }
        });
}());
</script>
