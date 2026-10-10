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

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('User'),
    'title' => __('Send email'),
    'description' => __('to') . ' ' . $user['User']['email'],
    'titleIcon' => 'fas fa-envelope-open-text',
    'icon' => 'fas fa-envelope',
]) ?>



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

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'align' => 'end',
    'bleed' => true,
    'submit' => ['label' => __('Send email'), 'icon' => 'fas fa-paper-plane'],
]) ?>

<?= $this->Form->end() ?>
