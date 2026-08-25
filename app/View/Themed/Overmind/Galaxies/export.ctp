<?php
/**
 * Export galaxy clusters modal. 
 * Posts (full page) to /galaxies/export/{id}; the response is a JSON body (raw) or a file download.
 *
 * Available vars: $galaxy, $distributionLevels (0-4, 4 = All sharing groups).
 */
$defaultDist = [1, 2, 3];

echo $this->Form->create('Galaxy', ['url' => $baseurl . '/galaxies/export/' . h($galaxy['Galaxy']['id'])]);
$this->Form->unlockField('Galaxy.distribution');
$this->Form->unlockField('Galaxy.format');
$this->Form->unlockField('Galaxy.download');
?>

<div id="galaxyExportModal">

    <!-- ── MODAL HEADER ─────────────────────────────────────────── -->
    <div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
         style="background:rgba(139,92,246,.06); border-bottom:2px solid var(--bs-galaxy);">
        <div>
            <div class="text-galaxy text-uppercase fw-semibold mb-1 export-section-label">
                <?= __('Galaxies') ?>
            </div>
            <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
                <i class="fas fa-download text-galaxy" style="font-size:1.25rem;"></i>
                <?= sprintf(__('Export: %s'), h($galaxy['Galaxy']['name'])) ?>
            </h4>
        </div>
        <span class="misp-icon misp-icon-galaxy misp-simple text-galaxy" style="font-size:2rem; opacity:.5;"></span>
    </div>

    <!-- ── BODY ─────────────────────────────────────────────────── -->
    <div class="p-4">

        <p class="text-muted small mb-4">
            <?= __('Choose which clusters to include and how you want to export them.') ?>
        </p>

        <!-- CLUSTERS' DISTRIBUTION -->
        <?php
        /*
         * Colours and icons come from the canonical table; only the wording is
         * local, because these cards sit two-per-row and need a short title
         * where the rest of the theme shows the full sentence.
         */
        $distTitles = [
            0 => __('Organisation'),
            1 => __('Community'),
            2 => __('Connected'),
            3 => __('All communities'),
            4 => __('Sharing groups'),
        ];
        $distMeta = [];
        foreach ($distTitles as $distLevel => $distTitle) {
            $distMeta[$distLevel] = ['title' => $distTitle]
                + $this->DistributionLevel->get($distLevel);
        }
        ?>
        <div class="mb-4">
            <div class="text-galaxy fw-bold text-uppercase mb-2 export-section-label">
                <i class="fas fa-share-nodes me-1"></i><?= __("Clusters' distribution") ?>
            </div>
            <div class="row g-2">
                <?php foreach ($distributionLevels as $level => $label):
                    $level = (int)$level;
                    $checked = in_array($level, $defaultDist, true);
                    $meta = $distMeta[$level] ?? ['title' => $label, 'icon' => 'fas fa-question', 'color' => '#6c757d'];
                ?>
                    <div class="col-md-6">
                        <label class="dist-export-card d-flex align-items-center gap-3 rounded-2 p-3 h-100 w-100 user-select-none mb-0"
                               data-active-color="<?= h($meta['color']) ?>"
                               style="cursor:pointer; border:1px solid <?= $checked ? $meta['color'] : '#dee2e6' ?>; transition:border-color .15s;">
                            <input type="checkbox"
                                   name="data[Galaxy][distribution][]"
                                   value="<?= h($level) ?>"
                                   class="form-check-input flex-shrink-0"
                                   style="margin-top:0;"
                                   <?= $checked ? 'checked' : '' ?>>
                            <div class="flex-fill">
                                <div class="fw-bold text-uppercase" style="font-size:.72rem; letter-spacing:.06em;">
                                    <?= h($meta['title']) ?>
                                </div>
                                <!--<div class="text-muted" style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                                    <= h($label) ?>
                                </div>-->
                            </div>
                            <i class="dist-export-icon <?= h($meta['icon']) ?>"
                               style="font-size:.95rem; color:<?= $checked ? $meta['color'] : '#adb5bd' ?>; transition:color .15s;"></i>
                        </label>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- CLUSTER TYPES -->
        <div class="mb-4">
            <div class="text-galaxy fw-bold text-uppercase mb-2 export-section-label">
                <i class="fas fa-layer-group me-1"></i><?= __('Cluster types') ?>
            </div>
            <div class="d-flex gap-4 flex-wrap">
                <div class="form-check form-switch form-switch-galaxy">
                    <?= $this->Form->checkbox('custom', ['class' => 'form-check-input', 'role' => 'switch', 'id' => 'exportCustom', 'checked' => true, 'hiddenField' => true]) ?>
                    <label class="form-check-label" for="exportCustom"><?= __('Custom clusters') ?></label>
                </div>
                <div class="form-check form-switch form-switch-galaxy">
                    <?= $this->Form->checkbox('default', ['class' => 'form-check-input', 'role' => 'switch', 'id' => 'exportDefault', 'checked' => true, 'hiddenField' => true]) ?>
                    <label class="form-check-label" for="exportDefault"><?= __('Default clusters') ?></label>
                </div>
            </div>
        </div>

        <!-- FORMAT -->
        <div class="mb-4">
            <div class="text-galaxy fw-bold text-uppercase mb-2 export-section-label">
                <i class="fas fa-file-code me-1"></i><?= __('Export format') ?>
            </div>
            <div class="d-flex gap-2 flex-wrap">
                <input type="radio" class="btn-check" name="data[Galaxy][format]" id="fmtMisp" value="misp" autocomplete="off" checked>
                <label class="btn btn-outline-galaxy text-start flex-fill py-2 px-3" for="fmtMisp">
                    <span class="d-block fw-semibold"><i class="fas fa-database me-1"></i> <?= __('MISP Format') ?></span>
                    <span class="d-block small opacity-75"><?= __('To re-import into another MISP') ?></span>
                </label>

                <input type="radio" class="btn-check" name="data[Galaxy][format]" id="fmtMispGalaxy" value="misp-galaxy" autocomplete="off">
                <label class="btn btn-outline-galaxy text-start flex-fill py-2 px-3" for="fmtMispGalaxy">
                    <span class="d-block fw-semibold"><i class="fab fa-github me-1"></i> <?= __('misp-galaxy format') ?></span>
                    <span class="d-block small opacity-75"><?= __('For the official repository') ?></span>
                </label>
            </div>
            <div id="mispGalaxyNotice" class="alert alert-warning mt-2 mb-0 py-2 small d-none">
                <strong><?= __('Warning!') ?></strong>
                <?= __('The exported JSON will not contain the `category` key. Keys such as `authors` and `version` may need to be adjusted manually.') ?>
            </div>
        </div>

        <!-- EXPORT TYPE -->
        <div class="mb-4">
            <div class="text-galaxy fw-bold text-uppercase mb-2 export-section-label">
                <i class="fas fa-arrow-down-wide-short me-1"></i><?= __('Export type') ?>
            </div>
            <div class="d-flex gap-2 flex-wrap">
                <input type="radio" class="btn-check" name="data[Galaxy][download]" id="typeRaw" value="raw" autocomplete="off" checked>
                <label class="btn btn-outline-galaxy text-start flex-fill py-2 px-3" for="typeRaw">
                    <span class="d-block fw-semibold"><i class="fas fa-eye me-1"></i> <?= __('Raw') ?></span>
                    <span class="d-block small opacity-75"><?= __('Display the JSON in the browser') ?></span>
                </label>

                <input type="radio" class="btn-check" name="data[Galaxy][download]" id="typeDownload" value="download" autocomplete="off">
                <label class="btn btn-outline-galaxy text-start flex-fill py-2 px-3" for="typeDownload">
                    <span class="d-block fw-semibold"><i class="fas fa-file-arrow-down me-1"></i> <?= __('Download') ?></span>
                    <span class="d-block small opacity-75"><?= __('Save the JSON as a file') ?></span>
                </label>
            </div>
        </div>

        <!-- ACTIONS -->
        <div class="d-flex justify-content-end gap-3">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                <?= __('Cancel') ?>
            </button>
            <button type="submit" class="btn btn-galaxy text-light">
                <i class="fas fa-download me-1"></i> <?= __('Export') ?>
            </button>
        </div>

    </div>

</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var notice = document.getElementById('mispGalaxyNotice');
    document.querySelectorAll('input[name="data[Galaxy][format]"]').forEach(function (r) {
        r.addEventListener('change', function () {
            notice.classList.toggle('d-none', this.value !== 'misp-galaxy');
        });
    });

    // Distribution cards: highlight border + icon in the level's colour when selected.
    document.querySelectorAll('.dist-export-card').forEach(function (card) {
        var cb = card.querySelector('input[type="checkbox"]');
        var icon = card.querySelector('.dist-export-icon');
        if (!cb) return;
        var activeColor = card.dataset.activeColor || 'var(--bs-galaxy)';
        cb.addEventListener('change', function () {
            card.style.borderColor = cb.checked ? activeColor : '#dee2e6';
            if (icon) icon.style.color = cb.checked ? activeColor : '#adb5bd';
        });
    });
})();
</script>
