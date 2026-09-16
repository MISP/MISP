<?php
if (empty($ajax)) {
    $this->set('headerTitle', __('Edit profile'));
}

echo $this->Form->create('User', [
    'id' => 'UserEditForm',
    'url' => '/users/edit',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Profile'),
    'title' => __('Edit profile'),
    'description' => __('Update your account details, notification preferences and cryptographic keys.'),
    'icon' => 'fas fa-user-pen',
    'isEdit' => true,
]) ?>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ACCOUNT -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Account'),
            ]) ?>
            <div class="row g-3">
                <div class="col-md-8">
                    <?= $this->Form->label('email', __('Email'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('email', [
                        'class' => 'form-control bg-light',
                        'disabled' => !$canChangeLogin,
                    ]) ?>
                </div>
                <div class="col-md-4">
                    <?= $this->Form->label('nids_sid', __('NIDS SID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('nids_sid', ['class' => 'form-control bg-light']) ?>
                </div>
            </div>
        </div>

        <?php if ($canChangePassword): ?>
            <!-- PASSWORD -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => __('Change password'),
                ]) ?>
                <div class="row g-3">
                    <div class="col-md-6">
                        <?= $this->Form->label('password', __('New password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('password', [
                            'class' => 'form-control bg-light',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                        <div class="form-text">
                            <?= __('Min length %s — complexity: %s', h($length), h($complexity)) ?>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <?= $this->Form->label('confirm_password', __('Confirm new password'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->password('confirm_password', [
                            'class' => 'form-control bg-light',
                            'autocomplete' => 'new-password',
                            'value' => '',
                        ]) ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- CRYPTO KEYS -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Cryptographic keys'),
            ]) ?>
            <?= $this->Form->label('gpgkey', __('PGP key'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->textarea('gpgkey', [
                'class' => 'form-control bg-light font-monospace',
                'rows' => 4,
                'placeholder' => __('Paste your PGP key here'),
            ]) ?>
            <?php if (Configure::read('SMIME.enabled')): ?>
                <div class="mt-3">
                    <?= $this->Form->label('certif_public', __('S/MIME public certificate (PEM)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('certif_public', [
                        'class' => 'form-control bg-light font-monospace',
                        'rows' => 4,
                    ]) ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- NOTIFICATIONS -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Notifications'),
            ]) ?>
            <?php
                $switches = [
                    'contactalert' => __('Receive "Contact reporter" request emails'),
                    'autoalert' => __('Event published notification'),
                    'notification_daily' => __('Daily notifications'),
                    'notification_weekly' => __('Weekly notifications'),
                    'notification_monthly' => __('Monthly notifications'),
                ];
            ?>
            <div class="row g-2">
                <?php foreach ($switches as $field => $label): ?>
                    <div class="col-md-6">
                        <div class="form-check form-switch">
                            <?= $this->Form->checkbox($field, [
                                'class' => 'form-check-input',
                                'id' => 'switch_' . $field,
                                'hiddenField' => true,
                            ]) ?>
                            <?= $this->Form->label('switch_' . $field, $label, ['class' => 'form-check-label']) ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if (Configure::read('Security.require_password_confirmation')): ?>
            <!-- CONFIRM WITH CURRENT PASSWORD -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => __('Confirm changes'),
                ]) ?>
                <?= $this->Form->label('current_password', __('Enter your current password to save'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->password('current_password', [
                    'class' => 'form-control bg-light',
                    'autocomplete' => 'current-password',
                    'value' => '',
                ]) ?>
            </div>
        <?php endif; ?>

    </div>
</div>

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'align' => 'end',
    'bleed' => true,
    'submit' => ['label' => __('Save changes'), 'icon' => 'fas fa-check'],
]) ?>

<?= $this->Form->end() ?>
