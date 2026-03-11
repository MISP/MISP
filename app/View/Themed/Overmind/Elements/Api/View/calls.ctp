<!-- =======================================================
Still in work 
======================================================= -->

<?php

$curlCode = $curl ?? '';
$pymispCode = $python ?? '';

?>

<div class="api-call-container">
    <!-- cURL -->
    <div class="api-call-block mb-3">
        <div class="api-call-header">
            <span>cURL</span>
            <button class="copy-btn" onclick="copyCode('curl-code')">
                <i class="fas fa-copy"></i>
            </button>
        </div>
    <pre id="curl-code" class="api-call-code"><?= h($curlCode) ?></pre>

    </div>

    <!-- PyMISP -->
    <div class="api-call-block">
        <div class="api-call-header">
            <span>PyMISP</span>
            <button class="copy-btn" onclick="copyCode('pymisp-code')">
                <i class="fas fa-copy"></i>
            </button>
        </div>
    <pre id="pymisp-code" class="api-call-code"><?= h($pymispCode) ?></pre>
    </div>
</div>