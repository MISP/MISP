<?php
/**
 * additionalMarkdownElements: List of custom elements linked to the markdown view to be injected
 *    [
 *         'path' => 'The path of the element',
 *         'variables' => 'List of variables to be passed on the element'
 *    ]
 * additionalMarkdownHelpModalElements: List of custom elements linked to the help modal to be injected
 *    [
 *         'path' => 'The path of the element',
 *         'tab_name' => 'The name of the navigation tab'
 *    ]
 */
    $insideModal = isset($insideModal) ? $insideModal : false;
    if ($canEdit) {
        if (!empty($additionalMarkdownHelpModalElements)) {
            foreach ($additionalMarkdownHelpModalElements as $i => $additionalHelpModal) {
                $additionalMarkdownHelpModalElements[$i]['tab_content'] = $this->element($additionalHelpModal['path']);
            }
        }
        echo $this->element('markdownEditor/markdownEditorHelpModal', ['additionalMarkdownHelpModalElements' => $additionalMarkdownHelpModalElements]);
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
            <button class="btn btn-primary dropdown-toggle" data-toggle="dropdown">
                <?= __('Menu') ?>
                <span class="caret"></span>
            </button>
            <ul id="markdownDropdownGeneralMenu" class="dropdown-menu">
                <li class="dropdown-submenu">
                    <a tabindex="-1" href="#">
                        <span class="icon"><i class="<?= $this->FontAwesome->getClass('download') ?>"></i></span>
                        <?= __('Download') ?>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a tabindex="-1" href="#" onclick="downloadMarkdown('pdf')">
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('file-pdf') ?>"></i></span>
                            <?= __('Download PDF (via print)') ?>
                        </a></li>
                        <li><a tabindex="-1" href="#" onclick="downloadMarkdown('text')">
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('markdown') ?>"></i></span>
                            <?= __('Download Markdown') ?>
                        </a></li>
                        <li><a tabindex="-1" href="#" title="<?= __('Replace custom syntax by a valid one') ?>" onclick="downloadMarkdown('text-gfm')">
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('markdown') ?>"></i></span>
                            <?= __('Download GFM simplified format') ?>
                        </a></li>
                    </ul>
                </li>
                <li class="dropdown-submenu">
                    <a tabindex="-1" href="#">
                        <span class="icon"><i class="<?= $this->FontAwesome->getClass('markdown') ?>"></i></span>
                        <?= __('Markdown parsing rules') ?>
                    </a>
                    <ul id="markdown-dropdown-rules-menu" class="dropdown-menu">
                        <li><a tabindex="-1" href="#" style="min-width: 200px;" onclick="markdownItToggleRule('image', arguments[0]); return false;" >
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('image') ?>"></i></span>
                            <span class="ruleText"><?= __('Image parsing') ?></span>
                            <span id="markdownparsing-image-parsing-enabled" class="bold green hidden" style="float: right;"><?= __('enabled') ?></span>
                            <span id="markdownparsing-image-parsing-disabled" class="bold red" style="float: right;"><?= __('disabled') ?></span>
                        </a></li>
                        <li><a tabindex="-1" href="#" style="min-width: 200px;" onclick="markdownItToggleRule('link', arguments[0]); return false;" >
                            <span class="icon"><i class="<?= $this->FontAwesome->getClass('link') ?>"></i></span>
                            <span class="ruleText"><?= __('Link parsing') ?></span>
                            <span id="markdownparsing-link-parsing-enabled" class="bold green hidden" style="float: right;"><?= __('enabled') ?></span>
                            <span id="markdownparsing-link-parsing-disabled" class="bold red" style="float: right;"><?= __('disabled') ?></span>
                        </a></li>
                    </ul>
                </li>
            </ul>
        <?php elseif($canEdit && !empty($editRedirect)): ?>
            <a type="button" class="btn btn-primary" href="<?= h($editRedirect) ?>#splitscreen" target="_blank">
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
                <span class="<?= $this->FontAwesome->getClass('bold') ?> useCursorPointer icon" onclick="replacementAction('bold')" title="<?= __('Bold') ?>"></span>
                <span class="<?= $this->FontAwesome->getClass('italic') ?> useCursorPointer icon" onclick="replacementAction('italic')" title="<?= __('Italic') ?>"></span>
                <span class="<?= $this->FontAwesome->getClass('heading') ?> useCursorPointer icon" onclick="replacementAction('heading')" title="<?= __('Heading') ?>"></span>
                <span class="<?= $this->FontAwesome->getClass('strikethrough') ?> useCursorPointer icon" onclick="replacementAction('strikethrough')" title="<?= __('Strikethrough') ?>"></span>
                <i class="top-bar-separator"></i>
                <span class="<?= $this->FontAwesome->getClass('list-ul') ?> useCursorPointer icon" onclick="replacementAction('list-ul')" title="<?= __('Unordered list') ?>"></span>
                <span class="<?= $this->FontAwesome->getClass('list-ol') ?> useCursorPointer icon" onclick="replacementAction('list-ol')" title="<?= __('Ordered list') ?>"></span>
                <i class="top-bar-separator"></i>
                <span class="<?= $this->FontAwesome->getClass('quote-left') ?> useCursorPointer icon" onclick="replacementAction('quote')" title="<?= __('Quote') ?>"></span>
                <span class="<?= $this->FontAwesome->getClass('code') ?> useCursorPointer icon" onclick="replacementAction('code')" title="<?= __('Code') ?>"></span>
                <span class="<?= $this->FontAwesome->getClass('table') ?> useCursorPointer icon" onclick="replacementAction('table')" title="<?= __('Table') ?>"></span>
                <span style="position: absolute;right: 10px;">
                    <button id="cancelMarkdownButton" type="button" class="btn btn-mini" onclick="cancelEdit()">
                        <?= __('Cancel') ?>
                    </button>
                </span>
            </div>
            <textarea id="editor"></textarea>
            <div id="bottom-bar" class="editor-action-bar">
                <span id="lastModifiedField" title="<?= __('Last updated') ?>" class="label"></span>
                <span>
                    <span title="<?= __('Toggle autocompletion while typing'); ?>">
                        <input type="checkbox" id="autocompletionCB" style="margin: 0 2px 0 0" checked="checked"></input>
                        <span class="<?= $this->FontAwesome->getClass('magic') ?> useCursorPointer icon" onclick="$autocompletionCB[0].checked = !$autocompletionCB[0].checked"></span>
                    </span>
                </span>
                <span>
                    <span title="<?= __('Synchronize scrolling'); ?>">
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
                <span style="margin-left: auto">
                    <span title="<?= __('Toggle fullscreen mode'); ?>">
                        <span id="toggleFullScreenMode" class="<?= $this->FontAwesome->getClass('expand-arrows-alt') ?> useCursorPointer icon" onclick="toggleFullscreenMode()"></span>
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
<div id="loadingBackdrop" class="modal-backdrop" style="display: none"></div>

<script>
    'use strict';
    var md, cm;
    var saveConfirmMessage = '<?= __('You are about to save the document. Do you wish to proceed?') ?>'
    var saveSuccessMessage = '<?= 'Markdown saved' ?>'
    var saveFailedMessage = '<?= 'Could not save markdown. Reason' ?>'
    var savePDFConfirmMessage = '<?= __('In order to save the PDF, you have to set the print destination to `Save as PDF`.') ?>'
    var confirmationMessageUnsavedChanges = '<?= __('You are about to leave the page with unsaved changes. Do you want to proceed?') ?>'
    var changeDetectedMessage = '<?= __('Unsaved changes') ?>'
    var canEdit = <?= $canEdit ? 'true' : 'false' ?>;
    var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
    var lastModified = '<?= h($lastModified) ?>' + '000'
</script>

<?php
    echo $this->element('genericElements/assetLoader', array(
        'js' => array(
            'doT',
            'markdown-it',
            'highlight.min',
            'FileSaver',
        ),
        'css' => array(
            'highlight.min',
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
    echo $this->element('genericElements/assetLoader', array(
        'js' => array('markdownEditor/markdownEditor'),
        'css' => array('markdownEditor/markdownEditor')
    ));
    if (!empty($additionalMarkdownElements)) {
        echo $this->element($additionalMarkdownElements['path'], $additionalMarkdownElements['variables']);
    }
?>
