<?php
$eventId   = h($data['Event']['id'] ?? '');
$uid       = 'evt-tags-' . $eventId;
$fetchUrl  = h($baseurl . '/events/viewEventTags/' . $eventId);
$editUrl   = h($baseurl . '/events/editEventTags/' . $eventId);

$mayModify = $this->Acl->canModifyTag($data);
?>

<div class="card shadow-sm mb-3" id="tags-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">

            <!-- Icon + title + count -->
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:#DB6A4718;">
                    <span class="misp-icon misp-icon-tag misp-simple" style="color:#DB6A47;font-size:1rem;"></span>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Tags') ?></div>
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
                       placeholder="<?= __('Filter tags…') ?>"
                       autocomplete="off"
                       aria-label="<?= __('Filter tags') ?>">
            </div>

            <?php if ($mayModify): ?>
            <!-- Edit button -->
            <button type="button"
                    class="btn btn-sm btn-outline-secondary flex-shrink-0"
                    onclick="openModal('<?= $editUrl ?>', 'xl')"
                    title="<?= __('Edit Tags') ?>">
                <i class="fas fa-pen-to-square me-1"></i>
                <?= __('Edit Tags') ?>
            </button>
            <?php endif; ?>

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
    var body     = document.getElementById(uid + '-body');
    var search   = document.getElementById(uid + '-search');
    var countEl  = document.getElementById(uid + '-count');
    var searchWired  = false;
    var currentTotal = 0;

    /* ─── Load ─── */
    function load() {
        return fetch(fetchUrl, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                return r.text();
            })
            .then(function (html) {
                body.innerHTML = html;
                var root = body.querySelector('[data-tag-count]');
                currentTotal = root ? parseInt(root.getAttribute('data-tag-count'), 10) : 0;
                setCount(currentTotal, currentTotal);
                if (search) {
                    if (search.value) { applySearch(); }
                    if (!searchWired) {
                        search.addEventListener('input', applySearch);
                        searchWired = true;
                    }
                }
            })
            .catch(function () {
                body.innerHTML =
                    '<div class="text-center text-muted py-4 small">'
                    + '<i class="fas fa-exclamation-triangle me-2"></i>'
                    + <?= json_encode(__('Could not load tags.')) ?>
                    + '</div>';
                if (countEl) { countEl.textContent = ''; }
            });
    }

    /* Expose a reload hook so the edit modal can refresh this card after save. */
    window['reloadTagsCard_' + uid] = load;

    load();

    /* ─── Count label ─── */
    function setCount(total, visible) {
        if (!countEl) { return; }
        if (total === 0) {
            countEl.textContent = <?= json_encode(__('No tags')) ?>;
        } else if (visible === total) {
            countEl.textContent = total + ' ' + <?= json_encode(__('tags')) ?>;
        } else {
            countEl.textContent =
                total + ' ' + <?= json_encode(__('tags')) ?>
                + ' · ' + visible + ' ' + <?= json_encode(__('visible')) ?>;
        }
    }

    /* ─── Search ─── */
    function applySearch() {
        var q        = search.value.toLowerCase().trim();
        var items    = body.querySelectorAll('[data-tag-item]');
        var tagList  = body.querySelector('[data-tag-list]');
        var noResult = body.querySelector('[data-tag-noresult]');
        var visible  = 0;

        items.forEach(function (item) {
            var name = item.getAttribute('data-tag-name') || '';
            var show = q === '' || name.includes(q);
            item.classList.toggle('d-none', !show);
            if (show) { visible++; }
        });

        var noMatch = items.length > 0 && visible === 0;
        if (tagList)  { tagList.classList.toggle('d-none', noMatch); }
        if (noResult) { noResult.classList.toggle('d-none', !noMatch); }
        setCount(currentTotal, visible);
    }

}());
</script>
