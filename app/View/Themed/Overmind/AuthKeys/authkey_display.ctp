<?php
$rawKey = $entity['AuthKey']['authkey_raw'] ?? '';
?>

<div class="container py-2">
    <div class="d-flex align-items-center justify-content-between mb-3">
        <h4 class="mb-0">
            <i class="fas fa-circle-check text-success me-2"></i><?= __('Auth key created') ?>
        </h4>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
    </div>

    <div class="alert alert-success mb-3">
        <?= __('Your authentication key was created successfully.') ?>
    </div>

    <p class="text-muted small mb-2">
        <?= __('Note down the key below — this is the only time it is shown in plain text. If you lose it, delete the entry and generate a new one. MISP identifies the key by its first and last 4 characters.') ?>
    </p>

    <div class="input-group mb-4">
        <input type="text" readonly class="form-control font-monospace"
               id="authkeyRawValue" value="<?= h($rawKey) ?>">
        <button class="btn btn-outline-secondary" type="button"
                id="authkeyCopyBtn" title="<?= __('Copy to clipboard') ?>">
            <i class="fas fa-copy"></i>
        </button>
    </div>

    <div class="d-flex justify-content-end">
        <button type="button" class="btn btn-primary" id="authkeyDoneBtn">
            <i class="fas fa-check me-1"></i><?= __('I have noted it down') ?>
        </button>
    </div>
</div>

<script>
(function () {
    var copyBtn = document.getElementById('authkeyCopyBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', function () {
            copyValueToClipboard(
                document.getElementById('authkeyRawValue').value,
                '<?= __('Auth key copied to clipboard') ?>'
            );
        });
    }
    var doneBtn = document.getElementById('authkeyDoneBtn');
    if (doneBtn) {
        doneBtn.addEventListener('click', function () {
            // Close the modal, then refresh so the new key appears in the list.
            var el = document.getElementById('mainModal');
            var inst = el ? bootstrap.Modal.getInstance(el) : null;
            if (inst && el.classList.contains('show')) {
                el.addEventListener('hidden.bs.modal', function () { location.reload(); }, { once: true });
                inst.hide();
            } else {
                location.reload();
            }
        });
    }
})();
</script>
