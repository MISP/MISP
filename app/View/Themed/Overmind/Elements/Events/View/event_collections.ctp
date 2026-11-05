<?php
$eventUuid = h($data['Event']['uuid'] ?? '');
$uid       = 'evt-collections-' . h($data['Event']['id'] ?? '');
$fetchUrl  = h($baseurl . '/collections/getCollectionsForElement/Event/' . $eventUuid . '.json');
$viewBase  = h($baseurl . '/collections/view/');
// The picker modal — an existing collection, or a new one carrying this event as its attach target.
$addUrl    = h($baseurl . '/collectionElements/addElementToCollection/Event/' . $eventUuid);
$mayAdd    = $this->Acl->canAccess('collectionElements', 'addElementToCollection');
?>

<div class="card shadow-sm mb-3<?= $mayAdd ? '' : ' d-none' ?>" id="collections-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom" id="<?= $uid ?>-head">
        <div class="d-flex align-items-center gap-2">
            <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;--tile:#1892B1;--tile-bg:#1892B140;">
                <i class="fas fa-folder-open" style="font-size:1rem;"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Collections') ?></div>
                <div class="small text-muted mt-1"
                     id="<?= $uid ?>-count">…</div>
            </div>

            <?php if ($mayAdd): ?>
            <button type="button"
                    class="btn btn-sm btn-outline-secondary flex-shrink-0"
                    data-tour="event-collections-add"
                    onclick="openModal('<?= $addUrl ?>', 'xl')"
                    title="<?= __('Add this event to a collection') ?>">
                <i class="fas fa-plus"></i>
            </button>
            <?php endif; ?>
        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $uid ?>-body">
        <div class="text-center py-4 text-muted">
            <div class="misp-loader misp-loader-sm" role="status"></div>
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
    var headEl   = document.getElementById(uid + '-head');
    var cardEl   = bodyEl.closest('.card');
    var mayAdd   = <?= json_encode($mayAdd) ?>;
    var eventUuid = <?= json_encode($data['Event']['uuid'] ?? '') ?>;

    // Empty, the card is its header and its +; without the + it has nothing to offer.
    function setEmpty(empty) {
        headEl.classList.toggle('border-bottom', !empty);
        bodyEl.classList.toggle('d-none', empty);
        cardEl.classList.toggle('d-none', empty && !mayAdd);
    }

    // The picker saves in place, so the card follows an add of this event.
    document.addEventListener('misp:collection-element-added', function (e) {
        var d = e.detail || {};
        if (d.type === 'Event' && String(d.uuid).toLowerCase() === eventUuid.toLowerCase()) { load(); }
    });
    load();

    function load() {
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

                bodyEl.innerHTML = '';
                setEmpty(total === 0);
                if (total === 0) { return; }

                collections.forEach(function (collection) {
                    var row = document.createElement('a');
                    row.href = viewBase + encodeURIComponent(collection.id);
                    row.className = 'd-flex align-items-center gap-2 px-3 py-2 '
                        + 'text-decoration-none text-body border-bottom collection-row';
                    if (collection.description) {
                        row.title = String(collection.description);
                    }

                    var icon = document.createElement('i');
                    icon.className = 'fas fa-folder text-accent flex-shrink-0';
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
                setEmpty(false);
                if (countEl) { countEl.textContent = ''; }
            });
    }
}());
</script>
