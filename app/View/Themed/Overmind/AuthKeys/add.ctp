<?php
$edit = $this->request->params['action'] === 'edit';

if (empty($ajax)) {
    $this->set('headerTitle', $edit ? __('Edit auth key') : __('Add auth key'));
}

echo $this->Form->create('AuthKey', [
    'id' => 'AuthKeyForm',
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<div class="container">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body p-4">

                <h3 class="mb-2"><?= $edit ? __('Edit auth key') : __('Add auth key') ?></h3>
                <p class="text-muted small mb-4">
                    <?= __('Auth keys are used for API access. A user can have more than one authkey, so add a separate key per tool. Use the comment field to identify your keys.') ?>
                </p>

                <!-- USER -->
                <div class="mb-3">
                    <?= $this->Form->label('user_id', __('User'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('user_id', $dropdownData['user'] ?? [], [
                        'class' => 'form-select bg-light',
                        'empty' => false,
                        'disabled' => $edit, // owner is fixed on edit
                    ]) ?>
                    <?php if ($edit): ?>
                        <?= $this->Form->hidden('user_id') ?>
                    <?php endif; ?>
                </div>

                <!-- COMMENT -->
                <div class="mb-3">
                    <?= $this->Form->label('comment', __('Comment'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('comment', [
                        'class' => 'form-control bg-light',
                        'rows' => 3,
                        'placeholder' => __('A short description to identify this key'),
                    ]) ?>
                </div>

                <!-- ALLOWED IPS -->
                <div class="mb-3">
                    <?= $this->Form->label('allowed_ips', __('Allowed IPs'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('allowed_ips', [
                        'class' => 'form-control bg-light font-monospace',
                        'rows' => 3,
                        'placeholder' => __("One IP or CIDR per line\nLeave empty to allow any"),
                    ]) ?>
                </div>

                <!-- EXPIRATION -->
                <div class="mb-3">
                    <?= $this->Form->label('expiration', __('Expiration'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('expiration', [
                        'class' => 'form-control bg-light',
                        'placeholder' => 'YYYY-MM-DD',
                    ]) ?>
                    <div class="form-text">
                        <?= $validity
                            ? __('Keep empty for maximal validity of %s days', h($validity))
                            : __('Keep empty for indefinite validity') ?>
                    </div>
                </div>

                <!-- READ ONLY -->
                <div class="mb-4">
                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('read_only', [
                            'class' => 'form-check-input',
                            'id' => 'checkReadOnly',
                            'hiddenField' => true,
                        ]) ?>
                        <?= $this->Form->label('checkReadOnly', __('Read only (unsets all permissions — do not use for sync users)'), ['class' => 'form-check-label']) ?>
                    </div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i>' . ($edit ? __('Save changes') : __('Add auth key')),
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

<?= $this->Form->end() ?>

<?php if (!$edit): ?>
<script>
(function () {
    var form = document.getElementById('AuthKeyForm');
    if (!form) return;
    // Submit the "add" form over ajax: close this modal and show the generated
    // key in a chained modal (authkey_display)
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        openModalPostChained(form.getAttribute('action'), new FormData(form), 'lg');
    });
})();
</script>
<?php endif; ?>
