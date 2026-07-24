<?php

$uid = $user['User']['id'];

if (!empty($error)) {
    $encClass = 'alert-danger';
    $encIcon  = 'triangle-exclamation';
    $encMsg   = $error;
} elseif ($encryption) {
    $encClass = 'alert-success';
    $encIcon  = 'lock';
    $encMsg   = __('A %s key was found for this user — the credentials will be sent encrypted.', h($encryption));
} else {
    $encClass = 'alert-warning';
    $encIcon  = 'triangle-exclamation';
    $encMsg   = __('This user has no encryption key set. This instance allows clear-text e-mails, so the credentials will be sent unencrypted.');
}
?>

<?php echo $this->Form->create('User', [
    'url'   => $baseurl . '/users/initiatePasswordReset/' . h($uid),
    'class' => 'm-0',
]); ?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('User') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-key text-primary" style="font-size:1.25rem;"></i>
            <?= __('Create new credentials') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('for') ?> <?= h($user['User']['email']) ?>
        </p>
    </div>
    <i class="fas fa-user-shield text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ENCRYPTION STATUS -->
        <div class="alert <?= $encClass ?> d-flex align-items-center gap-2 mb-0">
            <i class="fas fa-<?= $encIcon ?>"></i>
            <span><?= $encMsg ?></span>
        </div>

        <p class="mb-0">
            <?= __('A new random password will be generated and e-mailed to the user. Their current password will stop working immediately.') ?>
        </p>

        <!-- FIRST TIME REGISTRATION -->
        <div class="form-check">
            <?= $this->Form->input('firstTime', [
                'type'    => 'checkbox',
                'div'     => false,
                'label'   => false,
                'class'   => 'form-check-input',
                'id'      => 'UserFirstTime',
                'checked' => !empty($firstTime),
            ]) ?>
            <label class="form-check-label" for="UserFirstTime">
                <?= __('First time registration (send a welcome message)') ?>
            </label>
        </div>

    </div>
</div>

<!-- ── FOOTER ───────────────────────────────────────────────── -->
<div class="px-4 py-3 d-flex justify-content-end gap-2 border-top">
    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
        <?= __('Cancel') ?>
    </button>
    <button type="submit" class="btn btn-primary"<?= !empty($error) ? ' disabled' : '' ?>>
        <i class="fas fa-key me-1"></i><?= __('Create & send credentials') ?>
    </button>
</div>

<?= $this->Form->end() ?>
