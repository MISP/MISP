<?php
/*
 * BS5 popover-friendly confirm form for /event_templates/update (GET).
 * Rendered without a layout into #popover_form. Yes posts to the
 * same URL to execute the run; No closes via cancelPrompt().
 */
$present = isset($preview['present_in_library']) ? $preview['present_in_library'] : array();
$failed = isset($preview['failed']) ? $preview['failed'] : array();

$buckets = array('install' => array(), 'managed' => array(), 'forked' => array());
foreach ($present as $row) {
    if (empty($row['local'])) {
        $buckets['install'][] = $row;
    } elseif ((int)$row['local']['misp_default'] === 1) {
        $buckets['managed'][] = $row;
    } else {
        $buckets['forked'][] = $row;
    }
}
$renderBucket = function ($rows, $emptyText) {
    if (empty($rows)) {
        echo '<p class="text-muted fst-italic small mb-1">' . h($emptyText) . '</p>';
        return;
    }
    echo '<ul class="list-unstyled mb-1 ps-2 small">';
    foreach ($rows as $r) {
        echo '<li><code>' . h($r['slug'] ?? '') . '</code> — ' . h($r['name'] ?? '') . '</li>';
    }
    echo '</ul>';
};
?>
<div class="confirmation">
    <legend class="mb-2"><?= __('Update event templates from library') ?></legend>
    <div class="px-3 pb-3">
        <p class="small text-muted mb-2">
            <?= __('Reconcile the bundled <code>misp-event-templates</code> submodule with the local <code>event_templates</code> table.') ?>
        </p>

        <?php if (!empty($failed)): ?>
            <div class="alert alert-danger py-2 px-3 mb-2">
                <strong><?= __('%d on-disk template(s) could not be parsed:', count($failed)) ?></strong>
                <ul class="mb-0 mt-1 small">
                    <?php foreach ($failed as $f): ?>
                        <li><code><?= h($f['slug'] ?? '(no slug)') ?></code> — <?= h($f['error']) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <h6 class="fw-semibold mb-1 mt-2">
            <i class="fas fa-plus-circle text-success me-1"></i>
            <?= __('Will install') ?>
            <span class="badge bg-success-subtle text-success ms-1"><?= count($buckets['install']) ?></span>
        </h6>
        <?php $renderBucket($buckets['install'], __('Nothing to install — every library template already exists locally.')); ?>

        <h6 class="fw-semibold mb-1 mt-2">
            <i class="fas fa-sync text-primary me-1"></i>
            <?= __('May update') ?>
            <span class="badge bg-primary-subtle text-primary ms-1"><?= count($buckets['managed']) ?></span>
        </h6>
        <?php $renderBucket($buckets['managed'], __('No library-managed rows installed yet.')); ?>

        <h6 class="fw-semibold mb-1 mt-2">
            <i class="fas fa-code-fork text-warning me-1"></i>
            <?= __('Will skip (forked)') ?>
            <span class="badge bg-warning-subtle text-warning-emphasis ms-1"><?= count($buckets['forked']) ?></span>
        </h6>
        <?php $renderBucket($buckets['forked'], __('No forked rows.')); ?>

        <div class="d-flex justify-content-between mt-3">
            <button type="button" id="PromptYesButton"
                    class="btn btn-primary btn-sm"
                    onclick="submitEventTemplatesLibraryUpdate()"
                    aria-label="<?= __('Update') ?>"
                    title="<?= __('Update') ?>">
                <i class="fas fa-sync me-1"></i><?= __('Update') ?>
            </button>
            <span role="button" tabindex="0"
                  class="btn btn-outline-secondary btn-sm"
                  id="PromptNoButton"
                  onclick="cancelPrompt()"
                  aria-label="<?= __('Cancel') ?>"
                  title="<?= __('Cancel') ?>">
                <?= __('Cancel') ?>
            </span>
        </div>
    </div>
</div>
