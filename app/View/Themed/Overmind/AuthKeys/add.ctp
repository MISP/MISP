<?php
$isEdit = $this->request->params['action'] === 'edit';
$authKey = $this->request->data['AuthKey'] ?? [];

if (empty($ajax)) {
    $this->set('headerTitle', $isEdit ? __('Edit auth key') : __('Add auth key'));
}

echo $this->Form->create('AuthKey', [
    'id' => 'AuthKeyForm',
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Auth Keys'),
    'title' => $isEdit ? __('Edit Auth Key') : __('Add Auth Key'),
    'description' => __('An auth key grants API access. A user may hold several — add one per tool, and name it in the comment.'),
    'icon' => 'fas fa-key',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── OWNER ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('User'),
                'required' => !$isEdit,
            ]) ?>
            <?= $this->Form->select('user_id', $dropdownData['user'] ?? [], [
                'id' => 'AuthKeyUserId',
                'class' => 'form-select tom-select',
                'empty' => false,
                /* The owner is fixed once the key exists; the hidden field below
                 * is what actually travels, since a disabled select is not
                 * posted. */
                'disabled' => $isEdit,
            ]) ?>
            <?php if ($isEdit): ?>
                <?= $this->Form->hidden('user_id') ?>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('The owner cannot be changed — delete this key and add one for the other user.'),
                    'icon' => 'fas fa-lock',
                ]) ?>
            <?php endif; ?>
        </div>

        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Comment'),
            ]) ?>
            <?= $this->Form->textarea('comment', [
                'id' => 'AuthKeyComment',
                'class' => 'form-control',
                'style' => 'border-color:#d8dde3;',
                'rows' => 3,
                'placeholder' => __('A short description to identify this key'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('The key itself is only ever shown once, so this is how you will recognise it later.'),
            ]) ?>
        </div>

        <!-- ── RESTRICTIONS ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Restrictions'),
            ]) ?>
            <div class="row g-3">
                <div class="col-md-7">
                    <label class="form-label text-muted mb-1" for="AuthKeyAllowedIps"
                           style="font-size:.75rem;">
                        <i class="fas fa-network-wired me-1" style="font-size:.7rem;"></i>
                        <?= __('Allowed IPs') ?>
                    </label>
                    <?= $this->Form->textarea('allowed_ips', [
                        'id' => 'AuthKeyAllowedIps',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3; resize:vertical;',
                        'rows' => 3,
                        'spellcheck' => 'false',
                        'placeholder' => "192.0.2.10\n198.51.100.0/24",
                    ]) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('One IP or CIDR per line. Left empty, the key works from anywhere.'),
                    ]) ?>
                </div>
                <div class="col-md-5">
                    <label class="form-label text-muted mb-1" for="AuthKeyExpiration"
                           style="font-size:.75rem;">
                        <i class="fas fa-hourglass-half me-1" style="font-size:.7rem;"></i>
                        <?= __('Expiration') ?>
                    </label>
                    <?= $this->Form->text('expiration', [
                        'id' => 'AuthKeyExpiration',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => 'YYYY-MM-DD',
                        'autocomplete' => 'off',
                    ]) ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => $validity
                            ? __('Left empty: the maximum of %s days applies.', h($validity))
                            : __('Left empty: the key never expires.'),
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── PERMISSIONS ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Permissions'),
            ]) ?>
            <div class="form-check form-switch">
                <?= $this->Form->checkbox('read_only', [
                    'class' => 'form-check-input',
                    'id' => 'AuthKeyReadOnly',
                    'hiddenField' => true,
                ]) ?>
                <?= $this->Form->label(
                    'AuthKeyReadOnly',
                    __('Read only'),
                    ['class' => 'form-check-label']
                ) ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Unsets every permission on the key — never use it for a sync user.'),
                'icon' => 'fas fa-triangle-exclamation',
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($authKey['id'])
            ? [['label' => __('Auth key'), 'id' => $authKey['id']]]
            : [],
        'hint' => __('The generated key is shown once, right after saving.'),
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Add Auth Key'),
            'icon' => 'fas fa-' . ($isEdit ? 'floppy-disk' : 'key'),
        ],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<?php if (!$isEdit): ?>
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
