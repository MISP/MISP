<script>
    'use strict';
    var proxyMISPElements = null
    var eventid = '<?= !isset($eventid) ? '' : h($eventid) ?>'
    var reportid = '<?= h($reportid) ?>'
    var invalidMessage = '<?= __('invalid scope or id') ?>'
    // Confirmation URL of the AI report summary, null while the action is
    // not available to the user (the view decides).
    var aiSummarizeReportUrl = <?= json_encode(empty($aiSummarizeReportUrl) ? null : $aiSummarizeReportUrl) ?>
</script>

<?php
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'markdownEditor/event-report',
            'font-awesome-helper',
        ],
        'css' => [
            'markdownEditor/event-report',
            ]
    ]);
    
?>