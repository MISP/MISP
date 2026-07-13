<?php
$edit = $this->request->params['action'] === 'edit';
$entry = ($edit && !empty($blockEntry['OrgBlocklist'])) ? $blockEntry['OrgBlocklist'] : [];

echo $this->Form->create('OrgBlocklist', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit organisation blocklist entry') : __('Add organisation blocklist entries') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= __('Blocklisting an organisation prevents the creation and synchronisation of any of its events on this instance. It does not prevent a local user of the blocklisted organisation from logging in or viewing data. Paste a single UUID or a list (one per line).') ?>
                </div>

                <!-- UUIDS -->
                <div class="mb-3">
                    <?= $this->Form->label('uuids', __('Organisation UUIDs'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('uuids', [
                        'class' => 'form-control font-monospace',
                        'rows' => $edit ? 1 : 6,
                        'placeholder' => __('Enter a single or a list of UUIDs'),
                        'required' => !$edit,
                        'disabled' => $edit,
                        'value' => $edit ? ($entry['org_uuid'] ?? '') : ''
                    ]) ?>
                </div>

                <!-- ORG NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('org_name', __('Organisation name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('org_name', [
                        'class' => 'form-control',
                        'placeholder' => __('(Optional) The name that the organisation is associated with'),
                        'value' => $entry['org_name'] ?? ''
                    ]) ?>
                </div>

                <!-- COMMENT -->
                <div class="mb-4">
                    <?= $this->Form->label('comment', __('Comment'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('comment', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('(Optional) Any comments you would like to add regarding this (or these) entries.'),
                        'value' => $entry['comment'] ?? ''
                    ]) ?>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add to blocklist')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add to blocklist'),
                            'aria-label' => $edit ? __('Save changes') : __('Add to blocklist'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>
