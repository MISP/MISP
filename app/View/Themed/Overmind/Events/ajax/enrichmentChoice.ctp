<?php

if (empty($type)) {
    $type = 'Enrichment';
}
$model = $model ?? 'Attribute';

usort($modules, function ($a, $b) {
    return strcmp(strtolower($a['name']), strtolower($b['name']));
});
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(72,67,92,.06);
            border-bottom:2px solid var(--enrichment);">
    <div>
        <div class="text-enrichment text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= h($type === 'Cortex' ? __('Cortex') : __('Enrichment')) ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-wand-magic-sparkles text-enrichment" style="font-size:1.2rem;"></i>
            <?= __('Choose a module') ?>
            <?php if (!empty($modules)): ?>
                <span class="badge rounded-pill text-bg-light border"><?= count($modules) ?></span>
            <?php endif; ?>
        </h4>
        <div class="text-muted small mt-1">
            <?= __('The selected module will be queried and its results shown for review before import.') ?>
        </div>
    </div>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4" style="background:var(--bs-tertiary-bg, #f8f9fa);">
    <?php if (empty($modules)): ?>
        <div class="alert alert-light border mb-0 d-flex align-items-center gap-2">
            <i class="fas fa-circle-info text-muted"></i>
            <?= __('No enabled module is compatible with this data.') ?>
        </div>
    <?php else: ?>
        <div class="d-flex flex-column gap-2">
            <?php foreach ($modules as $module): ?>
                <?php
                    $resultUrl = sprintf(
                        '%s/events/queryEnrichment/%s',
                        $baseurl,
                        implode('/', [h($id), h($module['name']), h($type), h($model)])
                    );
                ?>
                <button type="button"
                        class="btn btn-light border text-start d-flex align-items-start gap-3 p-3 enrichment-module-choice"
                        data-result-url="<?= $resultUrl ?>"
                        title="<?= h($module['description']) ?>">
                    <span class="d-inline-flex align-items-center justify-content-center rounded-circle flex-shrink-0"
                          style="width:2.2rem;height:2.2rem;background:rgba(72,67,92,.1);">
                        <i class="fas fa-puzzle-piece text-enrichment"></i>
                    </span>
                    <span class="flex-grow-1">
                        <span class="fw-bold d-block"><?= h($module['name']) ?></span>
                        <?php if (!empty($module['description'])): ?>
                            <span class="text-muted small"><?= h($module['description']) ?></span>
                        <?php endif; ?>
                    </span>
                    <i class="fas fa-chevron-right text-muted align-self-center"></i>
                </button>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<script>
(function () {
    var body = document.getElementById('mainModalBody');
    if (!body) { return; }
    var loadingMsg = <?= json_encode(__('Querying module, please wait…')) ?>;
    body.querySelectorAll('.enrichment-module-choice').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var url = btn.getAttribute('data-result-url');
            if (!url) { return; }
            // Swap the choice list for a spinner while the module is queried
            body.innerHTML =
                '<div class="d-flex flex-column align-items-center justify-content-center gap-3" style="min-height:220px;">'
              + '<div class="spinner-border text-enrichment" role="status" style="width:2.5rem;height:2.5rem;"></div>'
              + '<div class="text-muted">' + loadingMsg + '</div>'
              + '</div>';
            openModal(url);
        });
    });
})();
</script>
