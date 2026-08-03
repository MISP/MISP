<?php
/**
 * POST /servers/update answers with the raw git output as text/plain rather
 * than redirecting, so the form is submitted over fetch and the output is
 * shown in place instead of navigating away from the page.
 */
$formId = 'misp-update-form';
?>

<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto" style="max-width: 34rem;">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2"><?= __('Update MISP') ?></h4>
        </div>
        <div class="card-body">
            <?php if (!$isUpdatePossible): ?>
                <div class="alert alert-warning d-flex gap-2" role="alert">
                    <i class="fas fa-triangle-exclamation mt-1"></i>
                    <div><?= __('Update is not possible: this instance is not on a branch, or the MISP folder is not writeable by the web user.') ?></div>
                </div>
                <div class="d-flex justify-content-end">
                    <button type="button" class="btn btn-outline-secondary"
                            onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                        <?= __('Close') ?>
                    </button>
                </div>
            <?php else: ?>
                <?= $this->Form->create('Server', array(
                    'id' => $formId,
                    'url' => $baseurl . '/servers/update',
                    'class' => 'm-0',
                )) ?>
                    <p class="mb-3">
                        <?= __('Pull the latest commit from the "%s" branch? If MISP has local changes the merge will fail.', h($branch)) ?>
                    </p>
                    <div class="d-flex justify-content-between align-items-center">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-download me-1"></i><?= __('Update MISP') ?>
                        </button>
                        <button type="button" class="btn btn-outline-secondary"
                                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                            <?= __('Cancel') ?>
                        </button>
                    </div>
                <?= $this->Form->end() ?>
                <pre class="dg-sql mt-3 d-none" id="<?= h($formId) ?>-output"></pre>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
(function () {
    var form = document.getElementById('<?= h($formId) ?>');
    if (!form) return;
    var output = document.getElementById('<?= h($formId) ?>-output');
    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var submit = form.querySelector('[type="submit"]');
        submit.disabled = true;
        output.classList.remove('d-none');
        output.textContent = <?= json_encode(__('Updating…')) ?>;
        fetch(form.getAttribute('action'), {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            body: new URLSearchParams(new FormData(form))
        })
            .then(function (r) { return r.text(); })
            .then(function (text) { output.textContent = text; })
            .catch(function () { output.textContent = <?= json_encode(__('The update request failed.')) ?>; })
            .finally(function () { submit.disabled = false; });
    });
})();
</script>
