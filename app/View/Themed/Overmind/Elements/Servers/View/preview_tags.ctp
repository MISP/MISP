<?php
/**
 *
 * Read-only tags card for a remote event preview
 *
 */

if (!Configure::read('MISP.tagging')) {
    return;
}

$tags = array_values(array_filter(
    $data['Tag'] ?? [],
    function ($t) { return !empty($t['name']) && empty($t['is_galaxy']); }
));

$ctx = $previewContext ?? [];
$tagFilterUrl = $ctx['tagFilterUrl']
    ?? ($baseurl . '/servers/previewIndex/' . (int)($server['Server']['id'] ?? 0) . '/searchtag:%tag%');
$tagFilterKey = $ctx['tagFilterKey'] ?? 'id';

$uid = 'preview-tags-' . h($data['Event']['id'] ?? $data['Event']['uuid'] ?? '0');
?>

<div class="card shadow-sm mb-3 flex-grow-1" id="preview-tags-card">

    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;--tile:#DB6A47;--tile-bg:#DB6A4718;">
                    <span class="misp-icon misp-icon-tag misp-simple" style="font-size:1rem;"></span>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Tags') ?></div>
                    <div class="small text-muted mt-1" id="<?= $uid ?>-count">
                        <?= empty($tags) ? __('No tags') : count($tags) . ' ' . __('tags') ?>
                    </div>
                </div>
            </div>

            <?php if (!empty($tags)): ?>
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
            <?php endif; ?>
        </div>
    </div>

    <div class="p-3" id="<?= $uid ?>-body">
        <?php if (empty($tags)): ?>
            <div class="text-center text-muted py-3 small">
                <span class="misp-icon misp-icon-tag misp-simple opacity-50 me-1"></span>
                <?= __('This event has no tags') ?>
            </div>
        <?php else: ?>
            <div data-tag-list>
                <?= $this->TagChip->collection($tags, [
                    'searchUrl' => '',
                    // Without the key the remote index cannot be filtered on
                    // this tag, so the chip stays a plain label.
                    'href' => function ($row) use ($tagFilterKey, $tagFilterUrl) {
                        $filterKey = $row['Tag'][$tagFilterKey] ?? null;
                        if ($filterKey === null || $filterKey === '') {
                            return null;
                        }
                        return str_replace('%tag%', rawurlencode((string)$filterKey), $tagFilterUrl);
                    },
                ]) ?>
            </div>
            <div class="text-center text-muted py-3 small d-none" data-tag-noresult>
                <?= __('No tag matches your search') ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php if (!empty($tags)): ?>
<script>
(function () {
    var uid     = <?= json_encode($uid) ?>;
    var search  = document.getElementById(uid + '-search');
    var body    = document.getElementById(uid + '-body');
    var countEl = document.getElementById(uid + '-count');
    if (!search || !body) { return; }

    var items    = body.querySelectorAll('[data-tag-item]');
    var noResult = body.querySelector('[data-tag-noresult]');
    var total    = items.length;

    search.addEventListener('input', function () {
        var q = search.value.toLowerCase().trim();
        var visible = 0;
        items.forEach(function (item) {
            var name = item.getAttribute('data-tag-name') || '';
            var show = q === '' || name.indexOf(q) !== -1;
            item.classList.toggle('d-none', !show);
            if (show) { visible++; }
        });
        body.querySelectorAll('.hg-group').forEach(function (group) {
            group.classList.toggle('d-none', !group.querySelector('[data-tag-item]:not(.d-none)'));
        });
        if (noResult) { noResult.classList.toggle('d-none', visible !== 0); }
        if (countEl) {
            countEl.textContent = visible === total
                ? total + ' ' + <?= json_encode(__('tags')) ?>
                : total + ' ' + <?= json_encode(__('tags')) ?>
                    + ' · ' + visible + ' ' + <?= json_encode(__('visible')) ?>;
        }
    });
}());
</script>
<?php endif; ?>
