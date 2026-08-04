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

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Profile') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-pen-to-square text-primary" style="font-size:1.25rem;"></i>
            <?= __('Edit profile') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Update your account details, notification preferences and cryptographic keys.') ?>
        </p>
    </div>
    <i class="fas fa-user-pen text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ACCOUNT -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Account') ?>
            </div>
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
                <div class="text-primary fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Change password') ?>
                </div>
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
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Cryptographic keys') ?>
            </div>
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
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Notifications') ?>
            </div>
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
                <div class="text-primary fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Confirm changes') ?>
                </div>
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

<!-- ── FOOTER ───────────────────────────────────────────────── -->
<div class="px-4 py-3 d-flex align-items-center justify-content-end gap-2 border-top">
    <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
        <i class="fas fa-times me-1"></i><?= __('Discard') ?>
    </button>
    <?= $this->Form->button(
        '<i class="fas fa-check me-1"></i>' . __('Save changes'),
        [
            'class' => 'btn btn-primary btn-sm',
            'escapeTitle' => false,
        ]
    ) ?>
</div>

<?= $this->Form->end() ?>
