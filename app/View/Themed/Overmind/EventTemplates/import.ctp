<?php
$modeOptions = [
    'fail' => __('fail — abort the import (default)'),
    'overwrite' => __('overwrite — replace in place, preserve original ownership'),
    'duplicate_as_new' => __('duplicate_as_new — assign a fresh UUID and save as new'),
];
?>
<?= $this->Form->create('EventTemplate', [
    'class' => 'needs-validation',
    'novalidate' => true,
    'enctype' => 'multipart/form-data',
    'url' => $baseurl . '/event_templates/import',
]) ?>

<div class="container mt-3">
    <div class="row justify-content-center">
        <div class="col-lg-8">

            <div class="card shadow-sm">
                <div class="card-body">

                    <h3 class="mb-2">
                        <?= __('Import event template') ?>
                    </h3>

                    <p class="text-muted mb-4">
                        <?= __(
                            'Paste a previously-exported event template JSON '
                            . 'below, or upload a .json file. Imported '
                            . 'templates become owned by your organisation '
                            . 'unless you use the overwrite mode.'
                        ) ?>
                    </p>

                    <div class="mb-3">
                        <?= $this->Form->label(
                            'json',
                            __('JSON'),
                            ['class' => 'form-label fw-semibold']
                        ) ?>
                        <?= $this->Form->textarea('json', [
                            'class' => 'form-control bg-light font-monospace',
                            'rows' => 16,
                            'placeholder' => __(
                                'Paste the event template export document here'
                            ),
                        ]) ?>
                    </div>

                    <div class="mb-3">
                        <?= $this->Form->label(
                            'submittedjson',
                            __('JSON file'),
                            ['class' => 'form-label fw-semibold']
                        ) ?>
                        <?= $this->Form->file('submittedjson', [
                            'class' => 'form-control bg-light',
                            'accept' => 'application/json,.json',
                        ]) ?>
                        <div class="form-text">
                            <?= __(
                                'Optional — if both JSON and a file are '
                                . 'provided, the file wins.'
                            ) ?>
                        </div>
                    </div>

                    <div class="mb-4">
                        <?= $this->Form->label(
                            'mode',
                            __('If a template with the same UUID already exists…'),
                            ['class' => 'form-label fw-semibold']
                        ) ?>
                        <?= $this->Form->select('mode', $modeOptions, [
                            'class' => 'form-select tom-select bg-light',
                            'default' => 'fail',
                            'empty' => false,
                        ]) ?>
                    </div>

                    <div class="d-flex justify-content-end gap-3">
                        <a class="btn btn-outline-secondary"
                           href="<?= $baseurl ?>/event_templates/index">
                            <?= __('Cancel') ?>
                        </a>
                        <?= $this->Form->button(
                            '<i class="fas fa-upload me-1"></i> '
                            . __('Import'),
                            [
                                'class' => 'btn btn-primary',
                                'escapeTitle' => false,
                            ]
                        ) ?>
                    </div>

                </div>
            </div>

        </div>
    </div>
</div>

<?= $this->Form->end() ?>
