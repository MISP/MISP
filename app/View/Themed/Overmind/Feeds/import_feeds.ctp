<?php
echo $this->Form->create('Feed', [
    'url' => $baseurl . '/feeds/importFeeds',
    'class' => 'feed-import-form',
]);
?>

<div class="card shadow-sm">
    <div class="card-body p-4">

        <h3 class="mb-3"><?= __('Import feeds from JSON') ?></h3>
        <p class="text-muted">
            <?= __('Paste a MISP feed metadata JSON below to add the feeds it describes. Feeds that already exist are skipped.') ?>
        </p>

        <div class="mb-3">
            <?= $this->Form->label('json', __('Feed metadata JSON'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->textarea('json', [
                'class' => 'form-control font-monospace',
                'rows' => 16,
                'spellcheck' => 'false',
                'required' => true,
                'placeholder' => '[{"Feed": {"name": "...", "provider": "...", "url": "..."}}]',
            ]) ?>
            <div class="form-text">
                <?= __('Accepts the output of a feed index export — a single feed object or a list of them.') ?>
            </div>
        </div>

        <!-- ACTIONS -->
        <div class="d-flex justify-content-end gap-3 mt-4">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
            <?= $this->Form->button(
                '<i class="fas fa-file-import me-1"></i> ' . __('Import'),
                ['class' => 'btn btn-primary', 'escapeTitle' => false, 'type' => 'submit']
            ) ?>
        </div>

    </div>
</div>

<?= $this->Form->end(); ?>
