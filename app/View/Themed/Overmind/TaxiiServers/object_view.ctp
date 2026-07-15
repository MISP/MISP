<?php
// Layout-less modal fragment injected into #mainModalBody by openModal().
// The controller sets $title (already h()-escaped object id) and $json
// (a JSON_PRETTY_PRINT string of the remote STIX object).
$preId = 'taxii-object-' . dechex(mt_rand());
?>
<div class="card shadow-sm">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h4 class="card-title mb-0">
            <i class="fas fa-cube me-2"></i><?= $title ?>
        </h4>
        <button
            type="button"
            class="btn btn-outline-secondary btn-sm"
            onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
            <i class="fas fa-xmark me-1"></i><?= __('Close') ?>
        </button>
    </div>
    <div class="card-body">
        <pre id="<?= $preId ?>"
             class="bg-body-tertiary border p-3 rounded small mb-0"
             style="max-height: 60vh; overflow: auto;"><?= h($json) ?></pre>
    </div>
</div>
