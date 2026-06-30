<?php
/**
 * Overmind discard-proposal confirmation modalW
 */
$discardUrl = h($baseurl . '/shadow_attributes/discard/' . (int)$id);
?>

<div class="p-4">

    <h6 class="fw-semibold mb-3 d-flex align-items-center gap-2">
        <i class="fas fa-comment-slash text-danger"></i>
        <?= __('Discard proposal') ?>
    </h6>

    <p class="text-muted small mb-3">
        <?= __('This proposal will be discarded and cannot be recovered.') ?>
    </p>

    <div class="d-flex justify-content-end gap-2 mt-3">
        <button type="button"
                class="btn btn-outline-secondary btn-sm"
                onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide()">
            <?= __('Cancel') ?>
        </button>
        <button type="button"
                id="proposal-discard-confirm-btn"
                class="btn btn-danger btn-sm"
                data-url="<?= $discardUrl ?>">
            <i class="fas fa-times me-1"></i>
            <?= __('Discard') ?>
        </button>
    </div>

</div>

<script>
(function () {
    var btn = document.getElementById('proposal-discard-confirm-btn');
    if (!btn) { return; }
    var url     = btn.dataset.url;
    var msgOk   = <?= json_encode(__('Proposal discarded.')) ?>;
    var msgFail = <?= json_encode(__('Could not discard proposal.')) ?>;

    btn.addEventListener('click', async function () {
        btn.disabled = true;
        try {
            var r = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     (typeof getCsrfToken === 'function' ? getCsrfToken() : '')
                }
            });
            var data = await r.json();
            if (data && data.saved) {
                var modalEl = document.getElementById('mainModal');
                var inst = modalEl ? bootstrap.Modal.getInstance(modalEl) : null;
                if (inst) { inst.hide(); }
                if (typeof showToast === 'function') { showToast(data.success || msgOk, 'success'); }
                if (typeof reloadProposalTabs === 'function') {
                    reloadProposalTabs();
                }
            } else {
                if (typeof showToast === 'function') { showToast((data && data.errors) ? data.errors : msgFail, 'danger'); }
                btn.disabled = false;
            }
        } catch (e) {
            if (typeof showToast === 'function') { showToast(msgFail, 'danger'); }
            btn.disabled = false;
        }
    });
}());
</script>
