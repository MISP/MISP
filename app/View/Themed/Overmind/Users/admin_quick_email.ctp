<?php
$uid = $user['User']['id'];

if ($encryption) {
    $encClass = 'alert-success';
    $encIcon  = 'lock';
    $encMsg   = __('A %s key was found for this user — the e-mail will be sent encrypted.', h($encryption));
} else {
    $encClass = 'alert-warning';
    $encIcon  = 'triangle-exclamation';
    $encMsg   = __('This user has no encryption key set. This instance allows clear-text e-mails, so the message will be sent unencrypted.');
}
?>


<?php
echo $this->Form->create('User', [
    'url'   => $baseurl . '/admin/users/quickEmail/' . h($uid),
    'class' => 'm-0',
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('User') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-envelope-open-text text-primary" style="font-size:1.25rem;"></i>
            <?= __('Send email') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('to') ?> <?= h($user['User']['email']) ?>
        </p>
    </div>
    <i class="fas fa-envelope text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>



<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ENCRYPTION STATUS -->
        <div class="alert <?= $encClass ?> d-flex align-items-center gap-2 mb-0">
            <i class="fas fa-<?= $encIcon ?>"></i>
            <span><?= $encMsg ?></span>
        </div>

        <!-- SUBJECT -->
        <div>
            <label for="UserSubject" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                <?= __('Subject') ?>
            </label>
            <?= $this->Form->input('subject', [
                'type'        => 'text',
                'div'         => false,
                'label'       => false,
                'class'       => 'form-control',
                'id'          => 'UserSubject',
                'placeholder' => __('Email subject'),
            ]) ?>
        </div>

        <!-- BODY -->
        <div>
            <label for="UserBody" class="text-primary fw-bold text-uppercase mb-1" style="font-size:.65rem;">
                <?= __('Message') ?>
            </label>
            <?= $this->Form->input('body', [
                'type'        => 'textarea',
                'div'         => false,
                'label'       => false,
                'class'       => 'form-control',
                'id'          => 'UserBody',
                'rows'        => 8,
                'placeholder' => __('Write your message…'),
            ]) ?>
        </div>

    </div>
</div>

<!-- FOOTER -->
<div class="px-4 py-3 d-flex justify-content-end gap-2 border-top">
    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
        <?= __('Discard') ?>
    </button>
    <button type="submit" class="btn btn-primary">
        <i class="fas fa-paper-plane me-1"></i><?= __('Send email') ?>
    </button>
</div>

<?= $this->Form->end() ?>
