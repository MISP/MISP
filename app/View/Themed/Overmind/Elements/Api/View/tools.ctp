<?php
$curlCode = $curl ?? '';
$pymispCode = $python ?? '';
?>

<div class="api-call-container">
    <div class="border rounded-3 overflow-hidden mb-3">
        <div class="bg-light border-bottom d-flex justify-content-between align-items-center py-2 px-3">
            <span class="fw-semibold small">cURL</span>
            <button
                class="text-muted border-0 bg-white"
                onclick="copyToClipboard(this, document.getElementById('curl-code').innerText)"
                data-bs-toggle="tooltip"
                title="<?= __('Copy cURL Command') ?>"
                aria-label="<?= __('Copy cURL Command') ?>">
                <i class="fas fa-copy"></i>
            </button>
        </div>
        <pre id="curl-code" class="p-3 m-0 font-monospace overflow-auto custom-code-text"><?= h($curlCode) ?></pre>
    </div>

    <div class="border rounded-3 overflow-hidden">
        <div class="bg-light border-bottom d-flex justify-content-between align-items-center py-2 px-3">
            <span class="fw-semibold small">PyMISP</span>
            <button
                class="text-muted border-0 bg-white"
                onclick="copyToClipboard(this, document.getElementById('pymisp-code').innerText)"
                data-bs-toggle="tooltip"
                title="<?= __('Copy PyMISP Command') ?>"
                aria-label="<?= __('Copy PyMISP Command') ?>">
                <i class="fas fa-copy"></i>
            </button>
        </div>
        <pre id="pymisp-code" class="p-3 m-0 font-monospace overflow-auto custom-code-text"><?= h($pymispCode) ?></pre>
    </div>
</div>