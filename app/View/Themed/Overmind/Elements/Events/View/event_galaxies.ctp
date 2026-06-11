<?php
$eventId  = h($data['Event']['id'] ?? '');
$uid      = 'evt-galaxies-' . $eventId;
$fetchUrl = h($baseurl . '/events/viewEventGalaxies/' . $eventId);
$mayModify = $this->Acl->canModifyEvent($data);
?>

<div class="card shadow-sm mb-3" id="galaxy-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">

            <!-- Icon + title + count -->
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:#e9d8fc;">
                    <span class="misp-icon misp-icon-galaxy misp-simple" style="color:#7C3AED;"></span>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Galaxy Clusters') ?></div>
                    <div class="small text-muted mt-1" id="<?= $uid ?>-count">…</div>
                </div>
            </div>

            <!-- Search -->
            <div class="input-group input-group-sm" style="max-width:260px;">
                <span class="input-group-text border-end-0 bg-white">
                    <i class="fas fa-search text-muted small"></i>
                </span>
                <input type="search"
                       id="<?= $uid ?>-search"
                       class="form-control border-start-0 ps-0"
                       placeholder="<?= __('Filter clusters…') ?>"
                       autocomplete="off"
                       aria-label="<?= __('Filter galaxy clusters') ?>">
            </div>

            <?php if ($mayModify || $isSiteAdmin): ?>
            <button type="button"
                    class="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
                    onclick="">
                <i class="fas fa-pen-to-square"></i>
                <?= __('Edit Galaxy Clusters') ?>
            </button>
            <?php endif; ?>

        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $uid ?>-body">
        <div class="text-center py-4 text-muted" id="<?= $uid ?>-spinner">
            <div class="spinner-border spinner-border-sm" role="status"></div>
        </div>
    </div>

</div>

<script>
(function () {
    var uid      = <?= json_encode($uid) ?>;
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var body     = document.getElementById(uid + '-body');
    var search   = document.getElementById(uid + '-search');
    var countEl  = document.getElementById(uid + '-count');

    loadGalaxies();

    function loadGalaxies() {
        fetch(fetchUrl)
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                return r.text();
            })
            .then(function (html) {
                body.innerHTML = html;
                var root   = body.querySelector('[data-galaxy-count]');
                var total  = root
                    ? parseInt(root.getAttribute('data-galaxy-count'), 10)
                    : 0;
                var label  = root
                    ? root.getAttribute('data-galaxy-count-label')
                    : <?= json_encode(__('clusters')) ?>;
                setCount(total, total, label);
                bindSearch(total, label);
            })
            .catch(function () {
                body.innerHTML =
                    '<div class="text-center text-muted py-4 small">'
                    + '<i class="fas fa-exclamation-triangle me-2"></i>'
                    + <?= json_encode(__('Could not load galaxy clusters.')) ?>
                    + '</div>';
                if (countEl) { countEl.textContent = ''; }
            });
    }

    /* ─── Count label ─── */
    function setCount(total, visible, label) {
        if (!countEl) { return; }
        label = label || <?= json_encode(__('clusters')) ?>;
        if (total === 0) {
            countEl.textContent = <?= json_encode(__('No clusters')) ?>;
        } else if (visible === total) {
            countEl.textContent = total + ' ' + label;
        } else {
            countEl.textContent =
                total + ' ' + label
                + ' · ' + visible + ' ' + <?= json_encode(__('visible')) ?>;
        }
    }

    /* ─── Client-side search ─── */
    function bindSearch(total, label) {
        if (!search) { return; }
        search.addEventListener('input', function () {
            applySearch(total, label);
        });
    }

    function applySearch(total, label) {
        var q        = search.value.toLowerCase().trim();
        var sections = body.querySelectorAll('[data-galaxy-section]');
        var noResult = body.querySelector('[data-galaxy-noresult]');
        var list     = body.querySelector('[data-galaxy-list]');
        var visible  = 0;

        sections.forEach(function (section) {
            var gName    = section.getAttribute('data-galaxy-name') || '';
            var cNames   = section.getAttribute('data-cluster-names') || '';
            var matches  = (q === '' || gName.includes(q) || cNames.includes(q));

            section.classList.toggle('d-none', !matches);

            if (matches) {
                /* When filtering, also hide individual clusters that don't match */
                var items = section.querySelectorAll('[data-cluster-item]');
                items.forEach(function (item) {
                    var cName = item.getAttribute('data-cluster-name') || '';
                    var show  = (q === '' || gName.includes(q) || cName.includes(q));
                    item.classList.toggle('d-none', !show);
                    if (show) { visible++; }
                });
                /* Re-show section if it contains at least one visible cluster */
                var anyVisible = section.querySelector('[data-cluster-item]:not(.d-none)');
                section.classList.toggle('d-none', !anyVisible);
            }
        });

        /* Total visible clusters when no filter */
        if (q === '') { visible = total; }

        var noMatch = total > 0 && visible === 0;
        if (list)     { list.classList.toggle('d-none', noMatch); }
        if (noResult) { noResult.classList.toggle('d-none', !noMatch); }

        setCount(total, visible, label);
    }

}());
</script>