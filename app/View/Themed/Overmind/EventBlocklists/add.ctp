<?php
$edit = $this->request->params['action'] === 'edit';
$entry = ($edit && !empty($blockEntry['EventBlocklist'])) ? $blockEntry['EventBlocklist'] : [];

echo $this->Form->create('EventBlocklist', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit event blocklist entry') : __('Add event blocklist entries') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= __('Events matching a blocklisted UUID are prevented from being created (also via synchronisation) on this instance. Paste a single UUID or a list (one per line).') ?>
                </div>

                <!-- UUIDS -->
                <div class="mb-3">
                    <?= $this->Form->label('uuids', __('Event UUIDs'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('uuids', [
                        'class' => 'form-control font-monospace',
                        'rows' => $edit ? 1 : 6,
                        'placeholder' => __('Enter a single or a list of UUIDs'),
                        'required' => !$edit,
                        'disabled' => $edit,
                        'value' => $edit ? ($entry['event_uuid'] ?? '') : ''
                    ]) ?>
                </div>

                <!-- CREATING ORG -->
                <div class="mb-3">
                    <?= $this->Form->label('event_orgc', __('Creating organisation'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('event_orgc', [
                        'class' => 'form-control',
                        'placeholder' => __('(Optional) The organisation that the event is associated with'),
                        'value' => $entry['event_orgc'] ?? ''
                    ]) ?>
                </div>

                <!-- EVENT INFO -->
                <div class="mb-3">
                    <?= $this->Form->label('event_info', __('Event info'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('event_info', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('(Optional) The event info of the event that you would like to block. Best left empty when adding a list of UUIDs.'),
                        'value' => $entry['event_info'] ?? ''
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
