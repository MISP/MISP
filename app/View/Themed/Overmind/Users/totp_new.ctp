<?php
if (empty($ajax)) {
    $this->set('headerTitle', __('Enable two-factor authentication'));
}

echo $this->Form->create('User', [
    'url' => '/users/totp_new',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Security') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-shield-halved text-primary" style="font-size:1.25rem;"></i>
            <?= __('Two-factor authentication') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Scan the QR code with your authenticator app, then enter the generated code to activate.') ?>
        </p>
    </div>
    <?php if (!empty($ajax)): ?>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
    <?php else: ?>
        <i class="fas fa-qrcode text-primary" style="font-size:2rem; opacity:.5;"></i>
    <?php endif; ?>
</div>

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

<!-- ── FOOTER ───────────────────────────────────────────────── -->
<div class="px-4 py-3 d-flex align-items-center justify-content-end gap-2 border-top">
    <?php if (!empty($ajax)): ?>
        <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
            <i class="fas fa-times me-1"></i><?= __('Discard') ?>
        </button>
    <?php endif; ?>
    <?= $this->Form->button(
        '<i class="fas fa-check me-1"></i>' . __('Validate'),
        ['class' => 'btn btn-primary btn-sm', 'escapeTitle' => false]
    ) ?>
</div>

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
