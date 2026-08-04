<?php
/**
 * Renders the event report as read-only rendered markdown.
 * Designed to be embedded in an iframe for previewing reports.
 * Includes MISP-specific element rendering (attributes, tags, galaxies, etc.)
 * but no editor toolbar or editing capabilities.
 */
    echo $this->element('genericElements/assetLoader', [
        'css' => ['markdownEditor/markdownEditor', 'markdownEditor/event-report', 'highlight.min'],
    ]);
?>

<style>
    /* Remove default page margins/padding for clean iframe embedding */
    html {
        margin: 0;
        padding: 0;
        height: 100%;
        overflow-x: hidden;
        overflow-y: auto;
    }
    body {
        margin: 0;
        padding: 10px;
        min-height: 100%;
        background: #fff;
        overflow-x: hidden;
        overflow-y: auto;
    }
    /* Hide elements not needed in rendered view */
    #markdown-viewer-toolbar,
    .raw-container,
    #editor-container,
    #resizable-handle,
    #loadingBackdrop,
    .markdownEditor-full-container > .split-container > #editor-container {
        display: none !important;
    }
    /* Make viewer take full width */
    .split-container {
        display: block !important;
    }
    #viewer-container {
        display: block !important;
        width: 100% !important;
        max-width: 100% !important;
    }
    #viewer {
        padding: 0;
    }
</style>

<div class="markdownEditor-full-container">
    <div id="markdown-viewer-toolbar" class="btn-toolbar" style="display: none;"></div>
    <div class="raw-container" style="display: none;">
        <pre id="raw"><?php echo h($report['EventReport']['content']); ?></pre>
    </div>
    <div class="split-container">
        <div id="editor-container" style="display: none;">
            <div id="editor-subcontainer">
                <textarea id="editor"></textarea>
            </div>
        </div>
        <div id="viewer-container">
            <div id="viewer"></div>
        </div>
    </div>
</div>

<script>
    'use strict';
    var md, cm;
    var saveConfirmMessage = '';
    var saveSuccessMessage = '';
    var saveFailedMessage = '';
    var imgPictureFailedMessage = '';
    var savePDFConfirmMessage = '';
    var confirmationMessageUnsavedChanges = '';
    var changeDetectedMessage = '';
    var canEdit = false;
    var isSiteAdmin = <?= $isSiteAdmin ? 'true' : 'false' ?>;
    var originalRaw = <?= json_encode(is_array($report['EventReport']['content']) ? $report['EventReport']['content'] : array($report['EventReport']['content']), JSON_HEX_TAG); ?>[0];
    var lastModified = '<?= h($report['EventReport']['timestamp']) ?>' + '000';
    var templateVariables = <?= json_encode($templateVariables, JSON_HEX_TAG); ?>;
    var templateVariablesProxy = {};
    templateVariables.forEach(function(entry) {
        templateVariablesProxy[entry.name] = entry.value;
    });
    var markdownOverrideEnabledParsingRules = [<?= Configure::read('MISP.enableEventReportImageParsingRule') === true ? '"image"' : '' ?>];
    var autoRenderMarkdown = true;
</script>

<?php
    echo $this->element('genericElements/assetLoader', [
        'js' => [
            'jquery-ui.min',
            'doT',
            'markdown-it',
            'mermaid',
            'highlight.min',
            'FileSaver',
        ],
    ]);
    echo $this->element('genericElements/assetLoader', [
        'js' => ['markdownEditor/markdownEditor'],
    ]);
    // Load the MISP element rendering (event-report.js + variables)
    echo $this->element('EventReports/reportEditor', [
        'reportid' => $report['EventReport']['id'],
        'eventid' => $report['EventReport']['event_id'],
    ]);
?>

<script>
    // After the markdown editor initializes in viewer mode, notify parent for iframe resize
    $(document).ready(function() {
        function notifyParentOfResize() {
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({
                    type: 'reportPreviewResize',
                    height: Math.max(
                        document.body.scrollHeight,
                        document.body.offsetHeight,
                        document.documentElement.scrollHeight,
                        document.documentElement.offsetHeight
                    )
                }, '*');
            }
        }

        function scheduleResizeNotifications() {
            [0, 150, 400, 900].forEach(function(delay) {
                setTimeout(notifyParentOfResize, delay);
            });
        }

        // Small delay to ensure rendering is complete
        setTimeout(scheduleResizeNotifications, 500);

        // Also notify after MISP elements are loaded (they load asynchronously)
        var resizeObserver = new MutationObserver(function() {
            scheduleResizeNotifications();
        });
        resizeObserver.observe(document.getElementById('viewer'), {
            childList: true,
            subtree: true,
            attributes: true
        });

        window.addEventListener('load', scheduleResizeNotifications);
    });
</script>
