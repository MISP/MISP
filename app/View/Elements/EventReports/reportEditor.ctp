<script>
    'use strict';
    var proxyMISPElements = <?= json_encode(is_array($proxyMISPElements) ? $proxyMISPElements : array($proxyMISPElements), JSON_HEX_TAG); ?>;
    var eventid = '<?= !isset($eventid) ? '' : h($eventid) ?>'
    var reportid = '<?= h($reportid) ?>'
    var invalidMessage = '<?= __('invalid scope or id') ?>'
</script>

<?php
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'markdownEditor/event-report',
        ],
        'css' => [
            'markdownEditor/event-report',
            ]
    ]);
    
?>