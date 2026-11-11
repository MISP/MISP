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

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('User'),
    'title' => __('Create new credentials'),
    'description' => __('for') . ' ' . $user['User']['email'],
    'titleIcon' => 'fas fa-key',
    'icon' => 'fas fa-user-shield',
]) ?>

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

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'align' => 'end',
    'bleed' => true,
    'cancel' => ['label' => __('Cancel')],
    'submit' => [
        'label' => __('Create & send credentials'),
        'icon' => 'fas fa-key',
        'disabled' => !empty($error),
    ],
]) ?>

<?= $this->Form->end() ?>
