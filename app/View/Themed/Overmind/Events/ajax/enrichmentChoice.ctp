<?php

if (empty($type)) {
    $type = 'Enrichment';
}
$model = $model ?? 'Attribute';

usort($modules, function ($a, $b) {
    return strcmp(strtolower($a['name']), strtolower($b['name']));
});
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'enrichment',
    'eyebrow' => $type === 'Cortex' ? __('Cortex') : __('Enrichment'),
    'title' => __('Choose a module'),
    'titleBadge' => empty($modules)
        ? ''
        : '<span class="badge rounded-pill text-bg-light border">' . count($modules) . '</span>',
    'titleIcon' => 'fas fa-wand-magic-sparkles',
    'description' => __('The selected module will be queried and its results shown for review before import.'),
    'close' => true,
]) ?>

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
