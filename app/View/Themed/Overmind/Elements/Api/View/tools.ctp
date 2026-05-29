<?php
$curlCode = $curl ?? '';
$pymispCode = $python ?? '';
?>

<div class="api-call-container">
    <div class="border rounded-3 overflow-hidden mb-3">
        <div class="bg-light border-bottom d-flex justify-content-between align-items-center py-2 px-3">
            <span class="fw-semibold small">cURL</span>
            <button class="btn btn-sm text-secondary p-0 border-0 shadow-none hover-dark" onclick="copyCode('curl-code')" title="Copier">
                <i class="fas fa-copy"></i>
            </button>
        </div>
        <pre id="curl-code" class="bg-dark p-3 m-0 font-monospace overflow-auto custom-code-text"><?= h($curlCode) ?></pre>
    </div>

    <div class="border rounded-3 overflow-hidden">
        <div class="bg-light border-bottom d-flex justify-content-between align-items-center py-2 px-3">
            <span class="fw-semibold small">PyMISP</span>
            <button class="btn btn-sm text-secondary p-0 border-0 shadow-none hover-dark" onclick="copyCode('pymisp-code')" title="Copier">
                <i class="fas fa-copy"></i>
            </button>
        </div>
        <pre id="pymisp-code" class="bg-dark p-3 m-0 font-monospace overflow-auto custom-code-text"><?= h($pymispCode) ?></pre>
    </div>
</div>