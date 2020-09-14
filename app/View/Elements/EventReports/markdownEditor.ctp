<?php
    $insideModal = isset($insideModal) ? $insideModal : false;
    if ($canEdit && isset($helpModal)) {
        echo $this->element($helpModal);
    }
?>

<div id="mardown-viewer-toolbar" class="btn-toolbar">
    <div class="btn-group">
        <?php if ($canEdit && !$insideModal): ?>
            <button type="button" class="btn" data-togglemode="editor" onclick="setMode('editor')">
                <i class="<?= $this->FontAwesome->getClass('edit') ?> fa-edit"></i>
                <?= __('Edit') ?>
            </button>
            <button type="button" class="btn" data-togglemode="splitscreen" onclick="setMode('splitscreen')">
                <i class="<?= $this->FontAwesome->getClass('columns') ?> fa-columns"></i>
                <?= __('Split Screen') ?>
            </button>
        <?php endif; ?>
        <button type="button" class="btn btn-inverse" data-togglemode="viewer" onclick="setMode('viewer')">
            <i class="<?= $this->FontAwesome->getClass('markdown') ?> fa-markdown"></i>
            <?= __('Markdown') ?>
        </button>
        <button type="button" class="btn" data-togglemode="raw" onclick="setMode('raw')">
            <i class="<?= $this->FontAwesome->getClass('code') ?> fa-code"></i>
            <?= __('Raw') ?>
        </button>
    </div>
    <div class="btn-group">
        <?php if ($canEdit && !$insideModal): ?>
            <button id="saveMarkdownButton" type="button" class="btn btn-primary" onclick="saveMarkdown()">
                <i class="<?= $this->FontAwesome->getClass('save') ?>"></i>
                <?= __('Save') ?>
            </button>
        <?php endif; ?>
        <?php if (!$insideModal): ?>
            <button id="saveMarkdownButton" type="button" class="btn btn-primary" onclick="downloadMarkdown('pdf')">
                <i class="<?= $this->FontAwesome->getClass('file-pdf') ?>" onclick=""></i>
                <?= __('Download') ?>
            </button>
            <button class="btn btn-primary dropdown-toggle" data-toggle="dropdown">
                <span class="caret"></span>
            </button>
            <ul class="dropdown-menu">
                <li class="dropdown-submenu">
                    <a tabindex="-1" href="#">
                        <span class="icon"><i class="<?= $this->FontAwesome->getClass('download') ?> fa-download"></i></span>
                        <?= __('Downloads') ?>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a tabindex="-1" href="#" onclick="downloadMarkdown('pdf')">
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('file-pdf') ?> fa-file-pdf"></i></span>
                            <?= __('Download PDF (via print)') ?>
                        </a></li>
                        <li><a tabindex="-1" href="#" onclick="downloadMarkdown('text')">
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('markdown') ?> fa-markdown"></i></span>
                            <?= __('Download Markdown') ?>
                        </a></li>
                        <li><a tabindex="-1" href="#" title="<?= __('Replace custom syntax by a valid one') ?>" onclick="downloadMarkdown('text-gfm')">
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('markdown') ?> fa-markdown"></i></span>
                            <?= __('Download GFM simplified format') ?>
                        </a></li>
                    </ul>
                </li>
            </ul>
        <?php elseif($canEdit): ?>
            <a id="saveMarkdownButton" type="button" class="btn btn-primary" href="<?= $baseurl . '/eventReports/view/' . $reportid ?>" target="_blank">
                <i class="<?= $this->FontAwesome->getClass('edit') ?>"></i>
                <?= __('Edit report') ?>
            </a>
        <?php endif; ?>
    </div>
    <?php if ($canEdit && !$insideModal): ?>
        <button type="button" class="btn btn-primary" onclick="showHelp()">
            <i class="<?= $this->FontAwesome->getClass('question-circle') ?> fa-question-circle"></i>
            <?= __('Help') ?>
        </button>
    <?php endif; ?>
</div>

<div class="raw-container">
    <pre id="raw"><?php echo h($markdown) ?></pre>
</div>
<div class="split-container">
    <div id="editor-container">
        <div id="editor-subcontainer">
            <div id="top-bar" class="editor-action-bar">
                <span class="<?= $this->FontAwesome->getClass('bold') ?> useCursorPointer icon" onclick="replacementAction('bold')"></span>
                <span class="<?= $this->FontAwesome->getClass('italic') ?> useCursorPointer icon" onclick="replacementAction('italic')"></span>
                <span class="<?= $this->FontAwesome->getClass('heading') ?> useCursorPointer icon" onclick="replacementAction('heading')"></span>
                <span class="<?= $this->FontAwesome->getClass('strikethrough') ?> useCursorPointer icon" onclick="replacementAction('strikethrough')"></span>
                <i class="top-bar-separator"></i>
                <span class="<?= $this->FontAwesome->getClass('list-ul') ?> useCursorPointer icon" onclick="replacementAction('list-ul')"></span>
                <span class="<?= $this->FontAwesome->getClass('list-ol') ?> useCursorPointer icon" onclick="replacementAction('list-ol')"></span>
                <i class="top-bar-separator"></i>
                <span class="<?= $this->FontAwesome->getClass('quote-left') ?> useCursorPointer icon" onclick="replacementAction('quote')"></span>
                <span class="<?= $this->FontAwesome->getClass('code') ?> useCursorPointer icon" onclick="replacementAction('code')"></span>
                <span class="<?= $this->FontAwesome->getClass('table') ?> useCursorPointer icon" onclick="replacementAction('table')"></span>
            </div>
            <textarea id="editor"></textarea>
            <div id="bottom-bar" class="editor-action-bar">
                <span id="lastModifiedField" title="<?= __('Last updated') ?>">
                </span>
                <span>
                    <span title="<?= __('Toggle autocompletion while typing'); ?>">
                        <input type="checkbox" id="autocompletionCB" style="margin: 0 2px 0 0" checked="checked"></input>
                        <span class="<?= $this->FontAwesome->getClass('magic') ?> useCursorPointer icon" onclick="$autocompletionCB[0].checked = !$autocompletionCB[0].checked"></span>
                    </span>
                </span>
                <span>
                    <span title="<?= __('Synchronize the scrolling'); ?>">
                        <input type="checkbox" id="syncScrollCB" style="margin: 0 2px 0 0" checked="checked"></input>
                        <span class="<?= $this->FontAwesome->getClass('link') ?> useCursorPointer icon" onclick="$syncScrollCB[0].checked = !$syncScrollCB[0].checked"></span>
                    </span>
                </span>
                <span>
                    <span title="<?= __('Automatically render markdown when typing'); ?>">
                        <input type="checkbox" id="autoRenderMarkdownCB" style="margin: 0 2px 0 0" checked="checked"></input>
                        <span class="<?= $this->FontAwesome->getClass('markdown') ?> useCursorPointer icon" onclick="$autoRenderMarkdownCB[0].checked = !$autoRenderMarkdownCB[0].checked"></span>
                    </span>
                </span>
            </div>
        </div>
        <div id="resizable-handle" class="ui-resizable-handle ui-resizable-e"></div>
    </div>
    <div id="viewer-container">
        <div id="viewer"></div>
    </div>
</div>

<?php
    echo $this->element('genericElements/assetLoader', array(
        'js' => array(
            'doT',
            'markdown-it',
            'highlight.min',
            'FileSaver',
            'markdownEditor/markdownEditor'
        ),
        'css' => array(
            'highlight.min',
            'markdownEditor/markdownEditor'
        )
    ));
    if ($canEdit) {
        echo $this->element('genericElements/assetLoader', array(
            'js' => array(
                'moment-with-locales',
                'codemirror/codemirror',
                'codemirror/modes/markdown',
                'codemirror/addons/simplescrollbars',
                'codemirror/addons/show-hint',
            ),
            'css' => array(
                'codemirror',
                'codemirror/simplescrollbars',
                'codemirror/show-hint',
            )
        ));
    }
    if (!empty($webDependencies)) {
        echo $this->element('genericElements/assetLoader', $webDependencies);
    }

    // - Add last modified timestamp & time since last edit
?>
<script>
    'use strict';
    var md, cm;
    var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
    var proxyMISPElements = <?= json_encode(is_array($proxyMISPElements) ? $proxyMISPElements : array($proxyMISPElements), JSON_HEX_TAG); ?>;
    var eventid = '<?= !isset($eventid) ? '' : h($eventid) ?>'
    var reportid = '<?= h($reportid) ?>'
    var lastModified = '<?= h($lastModified) ?>' + '000'
    var canEdit = <?= $canEdit ? 'true' : 'false' ?>;
    var invalidMessage = '<?= __('invalid scope or id') ?>'
    var saveConfirmMessage = '<?= __('You are about to save the document. Do you wish to proceed?') ?>'
    var saveSuccessMessage = '<?= 'Markdown saved' ?>'
    var saveFailedMessage = '<?= 'Could not save markdown. Reason' ?>'
    var savePDFConfirmMessage = '<?= __('In order to save the PDF, you have to set the print destination to `Save as PDF`.') ?>'
    var confirmationMessageUnsavedChanges = '<?= __('You are about to leave the page with unsaved changes. Do you want to proceed?') ?>'
</script>
