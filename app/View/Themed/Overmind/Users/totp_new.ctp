<?php
if (empty($ajax)) {
    $this->set('headerTitle', __('Enable two-factor authentication'));
}

echo $this->Form->create('User', [
    'url' => '/users/totp_new',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Security'),
    'title' => __('Two-factor authentication'),
    'description' => __('Scan the QR code with your authenticator app, then enter the generated code to activate.'),
    'titleIcon' => 'fas fa-shield-halved',
    'icon' => empty($ajax) ? 'fas fa-qrcode' : '',
    'close' => !empty($ajax),
]) ?>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="mx-auto" style="max-width:460px;">

        <!-- QR CODE -->
        <div class="d-flex justify-content-center mb-4">
            <div class="p-3 bg-white border rounded" style="max-width:240px;">
                <?= $qrcode /* raw SVG from the controller */ ?>
            </div>
        </div>

        <!-- SECRET -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Or enter this secret manually') ?>
            </div>
            <div class="input-group">
                <input type="text" readonly class="form-control font-monospace"
                       id="totpSecret" value="<?= h($secret) ?>">
                <button class="btn btn-outline-secondary" type="button"
                        id="totpSecretCopy" title="<?= __('Copy secret') ?>">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
            <div class="form-text">
                <?= __('Once verified, you will also receive 50 single-use paper login tokens.') ?>
            </div>
        </div>

        <!-- OTP -->
        <div>
            <?= $this->Form->label('otp', __('One-time password'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->text('otp', [
                'id' => 'UserOtp',
                'class' => 'form-control',
                'placeholder' => __('Enter the 6-digit code'),
                'autocomplete' => 'one-time-code',
                'inputmode' => 'numeric',
            ]) ?>
        </div>

    </div>
</div>

<?= $this->element('genericElementsBS5/Forms/modal_footer', [
    'align' => 'end',
    'bleed' => true,
    /* Outside a modal there is nothing to dismiss — the page is the form. */
    'cancel' => empty($ajax) ? false : [],
    'submit' => ['label' => __('Validate'), 'icon' => 'fas fa-check'],
]) ?>

<?= $this->Form->end() ?>

<script>
(function () {
    var btn = document.getElementById('totpSecretCopy');
    if (btn) {
        btn.addEventListener('click', function () {
            copyValueToClipboard(
                document.getElementById('totpSecret').value,
                '<?= __('Secret copied to clipboard') ?>'
            );
        });
    }
})();
</script>
