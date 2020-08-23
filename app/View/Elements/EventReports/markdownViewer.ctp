<?php echo $this->element('EventReports/markdownViewerHelpModal') ?>

<div id="mardown-viewer-toolbar" class="btn-toolbar">
    <div class="btn-group">
        <button type="button" class="btn" data-togglemode="editor" onclick="setMode('editor')">
            <i class="<?= $this->FontAwesome->getClass('edit') ?> fa-edit"></i>
            <?= __('Edit') ?>
        </button>
        <button type="button" class="btn" data-togglemode="splitscreen" onclick="setMode('splitscreen')">
            <i class="<?= $this->FontAwesome->getClass('columns') ?> fa-columns"></i>
            <?= __('Split Screen') ?>
        </button>
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
        <button id="saveMarkdownButton" type="button" class="btn btn-primary" onclick="saveMarkdown()">
            <i class="<?= $this->FontAwesome->getClass('save') ?> fa-save"></i>
            <?= __('Save') ?>
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
    </div>
    <button type="button" class="btn btn-primary" onclick="showHelp()">
        <i class="<?= $this->FontAwesome->getClass('question-circle') ?> fa-question-circle"></i>
        <?= __('Help') ?>
    </button>
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
                <i class="top-bar-separator"></i>
                <span class="<?= $this->FontAwesome->getClass('cube') ?> useCursorPointer icon" onclick="replacementAction('attribute')"></span>
                <span class="<?= $this->FontAwesome->getClass('cubes') ?> useCursorPointer icon" onclick="replacementAction('object')"></span>
            </div>
            <textarea id="editor"></textarea>
            <div id="bottom-bar" class="editor-action-bar">
                <span id="lastModifiedField">
                    <?= isset($lastModified) ? h($lastModified) : '' ?>
                </span>
                <span>
                    <span title="<?= __('Toggle autocompletion while typing'); ?>">
                        <input type="checkbox" id="autocompletionCB" style="margin: 0 2px 0 0" checked="checked"></input>
                        <span class="<?= $this->FontAwesome->getClass('magic') ?> useCursorPointer icon" onclick="$autocompletionCB[0].checked = !$autocompletionCB[0].checked"></span>
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
            'codemirror/codemirror',
            'codemirror/modes/markdown',
            'codemirror/addons/simplescrollbars',
            'codemirror/addons/show-hint',
        ),
        'css' => array(
            'highlight.min',
            'codemirror',
            'codemirror/simplescrollbars',
            'codemirror/show-hint',
        )
    ));

    // - Add last modified timestamp & time since last edit
    // - Add Picker for elements [correlation/eventGraph picture/tags/galaxyMatrix]
    // - Add support of picture (attachment) in the markdown
?>
<script>
    'use strict';
    var md, cm;
    var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
    var proxyMISPElements = <?= json_encode(is_array($proxyMISPElements) ? $proxyMISPElements : array($proxyMISPElements), JSON_HEX_TAG); ?>;
    var MISPElementValues = [], MISPElementTypes = [], MISPElementIDs = []
    var modelName = '<?= h($modelName) ?>';
    var mardownModelFieldName = '<?= h($mardownModelFieldName) ?>';
    var debounceDelay = 50;
    var renderTimer, scrollTimer;
    var scrollMap;
    var $splitContainer, $editorContainer, $rawContainer, $viewerContainer, $resizableHandle, $autocompletionCB
    var $editor, $viewer, $raw
    var $saveMarkdownButton, $mardownViewerToolbar
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';
    var dotTemplateAttribute = doT.template("<span class=\"misp-element-wrapper attribute useCursorPointer\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\">{{=it.type}}<span class=\"blue\"> {{=it.value}}</span></span></span>");
    var dotTemplateAttributePicture = doT.template("<div class=\"misp-picture-wrapper attributePicture useCursorPointer\"><img data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\" href=\"#\" src=\"{{=it.src}}\" alt=\"{{=it.alt}}\" title=\"\"/></div>");
    var dotTemplateObject = doT.template("<span class=\"misp-element-wrapper object useCursorPointer\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\">{{=it.type}}<span class=\"\"> {{=it.value}}</span></span></span>");
    var dotTemplateInvalid = doT.template("<span class=\"misp-element-wrapper invalid\"><span class=\"bold red\">{{=it.scope}}<span class=\"blue\"> ({{=it.id}})</span></span></span>");

    var contentChanged = false
    var defaultMode = 'viewer'
    var currentMode
    var splitEdit = true
    var noEditorScroll = false // Necessary as onscroll cannot be unbound from CM
    $(document).ready(function() {
        $splitContainer = $('.split-container')
        $editorContainer = $('#editor-container')
        $viewerContainer = $('#viewer-container')
        $rawContainer = $('div.raw-container')
        $resizableHandle = $('#resizable-handle')
        $editor = $('#editor')
        $viewer = $('#viewer')
        $raw = $('#raw')
        $mardownViewerToolbar = $('#mardown-viewer-toolbar')
        $saveMarkdownButton = $('#saveMarkdownButton')
        $autocompletionCB = $('#autocompletionCB')

        initMarkdownIt()
        initCodeMirror()
        setMode(defaultMode)
        setEditorData(originalRaw);

        $editorContainer.resizable({
            handles: {
                e: $resizableHandle
            },
            grid: 50,
            minWidth: 300,
            maxWidth: window.innerWidth -220 - 300,
            stop: function() {
                cm.refresh()
                scrollMap = null;
            },
            helper: 'ui-resizable-helper'
        })
        renderMarkdown()

        $editorContainer.on('touchstart mouseover', function () {
            noEditorScroll = false
            $viewerContainer.off('scroll');
            cm.on('scroll', function(event) {
                if (!noEditorScroll) {
                    doScroll(syncResultScroll)
                }
            });
        });

        $viewerContainer.on('touchstart mouseover', function () {
            noEditorScroll = true
            $viewerContainer.on('scroll', function() {
                doScroll(syncSrcScroll)
            });
        });

        buildMISPElementHints()
    })

    function initMarkdownIt() {
        var mdOptions = {
            highlight: function (str, lang) {
                if (lang && hljs.getLanguage(lang)) {
                    try {
                        return hljs.highlight(lang, str, true).value;
                    } catch (__) {}
                }
                return ''; // use external default escaping
            }
        }
        md = window.markdownit('default', mdOptions);
        md.disable([ 'link', 'image' ])
        md.renderer.rules.table_open = function () {
            return '<table class="table table-striped">\n';
        };
        md.renderer.rules.paragraph_open = injectLineNumbers;
        md.renderer.rules.heading_open = injectLineNumbers;
        md.renderer.rules.MISPElement = MISPElementRenderer;
        md.renderer.rules.MISPPictureElement = MISPPictureElementRenderer;
        md.inline.ruler.push('MISP_element_rule', MISPElementRule);
    }

    function initCodeMirror() {
        var cmOptions = {
            mode: 'markdown',
            theme:'default',
            lineNumbers: true,
            indentUnit: 4,
            showCursorWhenSelecting: true,
            lineWrapping: true,
            scrollbarStyle: 'overlay',
            extraKeys: {
                "Esc": function(cm) {
                    console.log('<esc>')
                },
                "Ctrl-Space": "autocomplete",
                "Ctrl-B": function() { replacementAction('bold') },
                "Ctrl-I": function() { replacementAction('italic') },
                "Ctrl-H": function() { replacementAction('heading') },
                "Ctrl-M": function() { replacementAction('element') },
            },
            hintOptions: {
                hint: hintMISPElements,
                completeSingle: false
            },
        }
        cm = CodeMirror.fromTextArea($editor[0], cmOptions);
        cm.on('changes', function() {
            doRender();
        })
        cm.on("keyup", function (cm, event) {
            if (!cm.state.completionActive && /*Enables keyboard navigation in autocomplete list*/
                event.keyCode != 13 &&        /*Enter - do not open autocomplete list just after item has been selected in it*/ 
                $autocompletionCB.prop('checked')) {
                cm.showHint()
            }
        });
    }

    function hintMISPElements(cm, options) {
        var authorizedMISPElements = ['attribute', 'object']
        var reMISPElement = RegExp('@\\[(?<scope>' + authorizedMISPElements.join('|') + ')\\]\\((?<elementid>[^\\)]+)\\)');
        var reExtendedWord = /\S/
        var scope, elementID, element
        var cursor = cm.getCursor()
        var line = cm.getLine(cursor.line)
        var start = cursor.ch
        var end = cursor.ch
        while (start && reExtendedWord.test(line.charAt(start - 1))) --start
        while (end < line.length && reExtendedWord.test(line.charAt(end))) ++end
        var word = line.slice(start, end).toLowerCase()
        
        var res = reMISPElement.exec(word)
        if (res !== null) {
            scope = res.groups.scope
            elementID = res.groups.elementid
            element = proxyMISPElements[scope][elementID]
            var hintList = []
            if (element !== undefined) {
                hintList.push(
                    {
                        text: '@[' + scope + '](' + element.id + ')',
                        render: function(elem, self, data) {
                            var hintElement = renderHintElement(scope, element)
                            $(elem).append(hintElement)
                        },
                        className: 'hint-container',
                    }
                )
            } else { // search in hint arrays
                var maxHints = 10
                var MISPElementToCheck = [MISPElementValues, MISPElementTypes, MISPElementIDs]
                MISPElementToCheck.forEach(function(MISPElement) {
                    MISPElement.forEach(function(hint) {
                        if (hintList.length >= maxHints) {
                            return false
                        }
                        if (hint[0].startsWith(elementID)) {
                            element = proxyMISPElements[scope][hint[1]]
                            if (element !== undefined) { // Correct scope
                                hintList.push({
                                    text: '@[' + scope + '](' + element.id + ')',
                                    element: element,
                                    render: function(elem, self, data) {
                                        var hintElement = renderHintElement(scope, data.element)
                                        $(elem).append(hintElement)
                                    },
                                    className: 'hint-container',
                                })
                            }
                        }
                    })
                })
            }
            return {
                list: hintList,
                from: CodeMirror.Pos(cursor.line, start),
                to: CodeMirror.Pos(cursor.line, end)
            }
        }
        return null
    }

    function renderHintElement(scope, element) {
        var $node;
        if (scope == 'attribute') {
            $node = $('<span/>').addClass('hint-attribute')
            $node.append($('<i/>').addClass('').text('[' + element.id + '] '))
                .append($('<span/>').addClass('bold').text(element.type + ' '))
                .append($('<span/>').addClass('bold blue').text(element.value + ' '))
        } else if (scope == 'object') {
            $node = $('<span/>').addClass('hint-object')
            $node.append($('<i/>').addClass('').text('[' + element.id + '] '))
                .append($('<span/>').addClass('bold').text(element.name + ' '))
                .append($('<span/>').addClass('bold blue').text(element.Attribute.length))
        } else {
            $node = $('<span>No match</span>') // should not happen
        }
        return $node
    }

    function MISPElementRule(state, startLine, endLine, silent) {
        var pos, start, labelStart, labelEnd, res, elementID, code, content, token, tokens, attrs, scope
        var oldPos = state.pos,
            max = state.posMax
        
        if (state.src.charCodeAt(state.pos) !== 0x40/* @ */) { return false; }
        if (state.src.charCodeAt(state.pos + 1) === 0x21/* ! */) {
            if (state.src.charCodeAt(state.pos + 2) !== 0x5B/* [ */) { return false;}
        } else {
            if (state.src.charCodeAt(state.pos + 1) !== 0x5B/* [ */) { return false; }
        }

        var isPicture = state.src.charCodeAt(state.pos + 1) === 0x21/* ! */

        if (isPicture) {
            labelStart = state.pos + 3;
            labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 2, false);
        } else {
            labelStart = state.pos + 2;
            labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 1, false);
        }

        // parser failed to find ']', so it's not a valid link
        if (labelEnd < 0) { return false; }
        scope = state.src.slice(labelStart, labelEnd)

        pos = labelEnd + 1;
        if (pos < max && state.src.charCodeAt(pos) === 0x28/* ( */) {
            start = pos;
            res = state.md.helpers.parseLinkDestination(state.src, pos, state.posMax);
            if (res.ok) {
                elementID = res.str.substring(1, res.str.length-1);
                pos = res.pos-1;
            }
        }

        if (pos >= max || state.src.charCodeAt(pos) !== 0x29/* ) */) {
            state.pos = oldPos;
            return false;
        }
        pos++;

        if (!/^\d+$/.test(elementID)) {
            return false;
        }

        // We found the end of the link, and know for a fact it's a valid link;
        // so all that's left to do is to call tokenizer.
        content = {
            scope: scope,
            elementID: elementID,
        }

        if (isPicture) {
            token      = state.push('MISPPictureElement', 'div', 0);
        } else {
            token      = state.push('MISPElement', 'div', 0);
        }
        token.children = tokens;
        token.content  = content;

        state.pos = pos;
        state.posMax = max;
        return true;
    }

    function MISPElementRenderer(tokens, idx, options, env, slf) {
        var allowedScope = ['attribute', 'object']
        var token = tokens[idx];
        var scope = token.content.scope
        var elementID = token.content.elementID
        if (allowedScope.indexOf(scope) == -1) {
            return renderInvalidMISPElement(scope, elementID);
        }
        return renderMISPElement(scope, elementID)
    }

    function MISPPictureElementRenderer(tokens, idx, options, env, slf) {
        var allowedScope = ['attribute']
        var token = tokens[idx];
        var scope = token.content.scope
        var elementID = token.content.elementID
        if (allowedScope.indexOf(scope) == -1) {
            return renderInvalidMISPElement(scope, elementID);
        }
        return renderMISPPictureElement(scope, elementID)
    }

    function renderMISPElement(scope, elementID) {
        var templateVariables
        if (scope == 'attribute') {
            var attribute = proxyMISPElements[scope][elementID]
            if (attribute !== undefined) {
                templateVariables = sanitizeObject({
                    scope: 'attribute',
                    elementid: elementID,
                    type: attribute.type,
                    value: attribute.value
                })
                return dotTemplateAttribute(templateVariables);
            }
        } else if (scope == 'object') {
            var mispObject = proxyMISPElements[scope][elementID]
            if (mispObject !== undefined) {
                templateVariables = sanitizeObject({
                    scope: 'object',
                    elementid: elementID,
                    type: mispObject.name,
                    value: mispObject.Attribute.length
                })
                return dotTemplateObject(templateVariables);
            }
        }
        return renderInvalidMISPElement(scope, elementID)
    }

    function renderMISPPictureElement(scope, elementID) {
        var attribute = proxyMISPElements[scope][elementID]
        if (attribute !== undefined) {
            var templateVariables = sanitizeObject({
                scope: 'attribute',
                elementid: elementID,
                type: attribute.type,
                value: attribute.value,
                alt: scope + ' ' + elementID,
                src: '<?= $baseurl ?>/attributes/viewPicture/1235',
                title: attribute.type + ' ' + attribute.value,
            })
            return dotTemplateAttributePicture(templateVariables);
        }
        return renderInvalidMISPElement(scope, elementID)
    }

    function renderInvalidMISPElement(scope, elementID) {
        var templateVariables = sanitizeObject({
            scope: '<?= __('invalid scope or id') ?>',
            id: elementID
        })
        return dotTemplateInvalid(templateVariables);
    }

    function sanitizeObject(obj) {
        var newObj = {}
        for (var key of Object.keys(obj)) {
            var newVal = $('</p>').text(obj[key]).html()
            newObj[key] = newVal
        }
        return newObj
    }

    function hideAll() {
        $rawContainer.hide()
        $editorContainer.hide()
        $viewerContainer.hide()
        $resizableHandle.hide()
    }

    function setMode(mode) {
        currentMode = mode
        $mardownViewerToolbar.find('button').removeClass('btn-inverse')
        $mardownViewerToolbar.find('button[data-togglemode="' + mode + '"]').addClass('btn-inverse')
        hideAll()
        $editorContainer.css('width', '');
        if (mode == 'raw') {
            $rawContainer.show()
        }
        if (mode == 'splitscreen') {
            $resizableHandle.show()
            $splitContainer.addClass('split-actif')
        } else {
            $resizableHandle.hide()
            $splitContainer.removeClass('split-actif')
        }
        if (mode == 'viewer' || mode == 'splitscreen') {
            $viewerContainer.show()
        }
        if (mode == 'editor' || mode == 'splitscreen') {
            $editorContainer.show({
                duration: 0,
                complete: function() {
                    cm.refresh()
                    // Make sure to build the scrollmap after the rendering
                    setTimeout(function() {
                        scrollMap = buildScrollMap() 
                    }, 500);
                }
            })
        }
    }

    function getEditorData() {
        return cm.getValue()
    }

    function setEditorData(data) {
        cm.setValue(data)
    }

    function saveMarkdown() {
        if (!confirm('<?= __('You are about to save the document. Do you wish to proceed?') ?>')) {
            return
        }
        var url = "<?= $baseurl ?>/eventReports/edit/<?= h($id) ?>"
        fetchFormDataAjax(url, function(formHTML) {
            $('body').append($('<div id="temp" style="display: none"/>').html(formHTML))
            var $tmpForm = $('#temp form')
            var formUrl = $tmpForm.attr('action')
            $tmpForm.find('[name="data[' + modelName + '][' + mardownModelFieldName + ']"]').val(getEditorData())
            
            $.ajax({
                data: $tmpForm.serialize(),
                beforeSend: function() {
                    $saveMarkdownButton
                        .prop('disabled', true)
                        .append(loadingSpanAnimation);
                    $editor.prop('disabled', true);
                },
                success:function(data, textStatus) {
                    showMessage('success', '<?= 'Markdown saved' ?>');
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    showMessage('fail', '<?= 'Could not save markdown. Reason' ?>' + ": " + errorThrown);
                },
                complete:function() {
                    $('#temp').remove();
                    $saveMarkdownButton
                        .prop('disabled', false)
                        .find('#loadingSpan').remove();
                    $editor.prop('disabled', false);
                },
                type:"post",
                url: formUrl
            })
        })
    }

    function downloadMarkdown(type) {
        var content, fileType, baseName, extension
        if (type == 'pdf') {
            if (currentMode != 'viewer' && currentMode != 'splitscreen') {
                setMode('viewer')
                setTimeout(function (){ // let the parser render the document
                    if (confirm('<?= __('In order to save the PDF, you have to set the print destination to `Save as PDF`.') ?>')) {
                        window.print()
                    }
                }, 300);
            } else {
                if (confirm('<?= __('In order to save the PDF, you have to set the print destination to `Save as PDF`.') ?>')) {
                    window.print()
                }
            }
            return
        } else if (type == 'text') {
            content = getEditorData()
            baseName = 'event-report-' + (new Date()).getTime()
            extension = 'md'
            fileType = 'text/markdown'
        } else if (type == 'text-gfm') {
            content = replaceMISPElementByTheirValue(getEditorData())
            baseName = 'event-report-' + (new Date()).getTime()
            extension = 'md'
            fileType = 'text/markdown'
        }
        var filename = baseName + '.' + extension
        var blob = new Blob([content], {
            type: fileType
        })
        saveAs(blob, filename)
    }

    function showHelp() {
        $('#genericModal.markdown-modal-helper').modal();
    }

    function replaceMISPElementByTheirValue(raw) {
        var match, replacement, element
        var final = ''
        var authorizedMISPElements = ['attribute', 'object']
        var reMISPElement = RegExp('@\\[(?<scope>' + authorizedMISPElements.join('|') + ')\\]\\((?<elementid>[\\d]+)\\)', 'g');
        var offset = 0
        while ((match = reMISPElement.exec(raw)) !== null) {
            element = proxyMISPElements[match.groups.scope][match.groups.elementid]
            if (element !== undefined) {
                replacement = match.groups.scope + '-' + element.uuid
            } else {
                replacement = match.groups.scope + '-' + match.groups.elementid
            }
            final += raw.substring(offset, match.index) + replacement
            offset = reMISPElement.lastIndex
        }
        final += raw.substring(offset)
        return final
    }

    function renderMarkdown() {
        var toRender = getEditorData();
        var result = md.render(toRender);
        scrollMap = null;
        $viewer.html(result);
        registerListener()
    }

    function doRender() {
        clearTimeout(renderTimer);
        renderTimer = setTimeout(renderMarkdown, debounceDelay);
    }

    function registerListener() {
        $('.misp-element-wrapper').filter('.attribute').popover({
            trigger: 'click',
            title: getTitleFromMISPElementDOM,
            html: true,
            content: getContentFromMISPElementDOM
        })
        $('.misp-picture-wrapper > img').popover({
            trigger: 'click',
            title: getTitleFromMISPElementDOM,
            html: true,
            content: getContentFromMISPElementDOM,
            placement: 'top'
        })
        $('.misp-element-wrapper').filter('.object').popover({
            trigger: 'click',
            title: getTitleFromMISPElementDOM,
            html: true,
            content: getContentFromMISPElementDOM
        })
    }

    function getElementFromDom(node) {
        var scope = $(node).data('scope')
        var elementID = $(node).data('elementid')
        if (scope !== undefined && elementID !== undefined) {
            return {
                element: proxyMISPElements[scope][elementID],
                scope: scope,
                elementID: elementID
            }
        }
        return false
    }

    function getTitleFromMISPElementDOM() {
        var data = getElementFromDom(this)
        var title = '<?= __('invalid scope or id') ?>'
        var dismissButton = ''
        if (data !== false) {
            dismissButton = '<button type="button" class="close" style="margin-left: 5px;" data-scope="' + data.scope + '" data-elementid="' + data.elementID + '" onclick="closeThePopover(this)">×</button>';
            title = data.scope.charAt(0).toUpperCase() + data.scope.slice(1) + ' ' + data.elementID
        }
        return title + dismissButton
    }

    function closeThePopover(closeButton) {
        var scope = $(closeButton).data('scope')
        var elementID = $(closeButton).data('elementid')
        var $MISPElement = $('[data-scope="' + scope + '"][data-elementid="' + elementID + '"]')
        $MISPElement.popover('hide');
    }

    function constructAttributeRow(attribute)
    {
        var attributeFieldsToRender = ['id', 'category', 'type', 'value', 'comment']
        var $tr = $('<tr/>')
        attributeFieldsToRender.forEach(function(field) {
            $tr.append($('<td/>').text(attribute[field]))
        })
        var $tags = $('<div/>')
        if (attribute.AttributeTag !== undefined) {
            attribute.AttributeTag.forEach(function(attributeTag) {
                var tag = attributeTag.Tag
                var $tag = $('<div/>').append(
                    $('<span/>')
                        .addClass('tagComplete nowrap')
                        .css({'background-color': tag.colour, 'color': getTextColour(tag.colour), 'box-shadow': '1px 1px 3px #888888c4'})
                        .text(tag.name)
                )
                $tags.append($tag)
            })
        }
        $tr.append($('<td/>').append($tags))
        var $galaxies = $('<div/>')
        if (attribute.Galaxy !== undefined) {
            attribute.Galaxy.forEach(function(galaxy) {
                var $galaxy = $('<div/>').append(
                    $('<span/>')
                        .addClass('tagComplete nowrap')
                        .css({'background-color': '#0088cc', 'color': getTextColour('#0088cc'), 'box-shadow': '1px 1px 3px #888888c4'})
                        .text(galaxy.name + ' :: ' + galaxy.GalaxyCluster[0].value)
                )
                $galaxies.append($galaxy)
            })
        }
        $tr.append($('<td/>').append($galaxies))
        return $tr
    }

    function constructAttributeHeader(attribute, showAll) {
        showAll = showAll !== undefined ? showAll : false
        var attributeFieldsToRender = ['id', 'category', 'type', 'value', 'comment']
        var $tr = $('<tr/>')
        attributeFieldsToRender.forEach(function(field) {
            $tr.append($('<th/>').text(field))
        })
        if (showAll || (attribute.AttributeTag !== undefined && attribute.AttributeTag.length > 0)) {
            $tr.append($('<th/>').text('tags'))
        }
        if (showAll || (attribute.Galaxy !== undefined && attribute.Galaxy.length > 0)) {
            $tr.append($('<th/>').text('galaxies'))
        }
        var $thead = $('<thead/>').append($tr)
        return $thead
    }

    function constructObject(object) {
        var objectFieldsToRender = ['id', 'name', 'description', 'distribution']
        var $object = $('<div/>').addClass('similarObjectPanel')
                        .css({border: '1px solid #3465a4', 'border-radius': '5px'})
        var $top = $('<div/>').addClass('blueElement')
            .css({padding: '4px 5px'})
        objectFieldsToRender.forEach(function(field) {
            $top.append($('<div/>').append(
                $('<span/>').addClass('bold').text(field + ': '),
                $('<span/>').text(object[field])
            ))
        })
        
        var $attributeTable = $('<table/>').addClass('table table-striped table-condensed')
            .css({'margin-bottom': '3px'})
        var $thead = constructAttributeHeader({}, true)
        var $tbody = $('<tbody/>')
        object.Attribute.forEach(function(attribute) {
            $tbody.append(constructAttributeRow(attribute))
        })
        $attributeTable.append($thead, $tbody)
        $object.append($top, $attributeTable)
        return $('<div/>').append($object)
    }

    function getContentFromMISPElementDOM() {
        var data = getElementFromDom(this)
        
        if (data !== false) {
            if (data.scope == 'attribute') {
                var $thead = constructAttributeHeader(data.element)
                var $row = constructAttributeRow(data.element)
                var $attribute = $('<div/>').append(
                    $('<table/>')
                        .addClass('table table-condensed')
                        .append($thead)
                        .append($('<tbody/>').append($row))
                )
                return $attribute.html()
            } else if (data.scope == 'object') {
                var $object = constructObject(data.element)
                return $object.html()
            }
        }
        return '<?= __('invalid scope or id') ?>'
    }

    function replacementAction(action) {
        var start = cm.getCursor('start')
        var end = cm.getCursor('end')
        var content = cm.getRange(start, end)
        var replacement = content
        var setCursorTo = false

        switch (action) {
            case 'bold':
                replacement = '**' + content + '**'
                break;
            case 'italic':
                replacement = '*' + content + '*'
                break;
            case 'heading':
                start.ch = 0
                replacement = cm.getRange({line: start.line, ch: 0}, {line: start.line, ch: 1}) == '#' ? '#' : '# '
                end = null
                break;
            case 'strikethrough':
                replacement = '~~' + content + '~~'
                break;
            case 'list-ul':
                start.ch = 0
                var currentFirstChar = cm.getRange({line: start.line, ch: 0}, {line: start.line, ch: 2})
                if (currentFirstChar == '* ') {
                    replacement = ''
                    end.ch = 2
                } else {
                    replacement = '* '
                    end = null
                }
                break;
            case 'list-ol':
                start.ch = 0
                var currentFirstChar = cm.getRange({line: start.line, ch: 0}, {line: start.line, ch: 3})
                if (currentFirstChar == '1. ') {
                    replacement = ''
                    end.ch = 3
                } else {
                    replacement = '1. '
                    end = null
                }
                break;
            case 'quote':
                start.ch = 0
                var currentFirstChar = cm.getRange({line: start.line, ch: 0}, {line: start.line, ch: 2})
                if (currentFirstChar == '> ') {
                    replacement = ''
                    end.ch = 2
                } else {
                    replacement = '> '
                    end = null
                }
                break;
            case 'code':
                cm.replaceRange('\n```', {line: start.line - 1})
                cm.replaceRange('\n```', {line: end.line + 1})
                cm.setCursor(start.line + 1)
                cm.focus()
                return;
            case 'table':
                var tableTemplate = '| Column 1 | Column 2 | Column 3 |\n| -------- | -------- | -------- |\n| Text     | Text     | Text     |\n'
                var lineContent = cm.getLine(start.line)
                if (lineContent != '') {
                    tableTemplate = '\n' + tableTemplate
                }
                cm.replaceRange(tableTemplate, {line: start.line + 1})
                var startSelection = start.line + 1
                if (lineContent != '') {
                    startSelection++
                }
                cm.setSelection({line: startSelection, ch: 2}, {line: startSelection, ch: 10})
                cm.focus()
                return;
            case 'element':
                replacement = '@[MISPElement]()'
                end = null
                cm.replaceRange(replacement, start)
                cm.setSelection({line: start.line, ch: start.ch + 2}, {line: start.line, ch: start.ch + 2 + 11})
                cm.focus()
                return;
            case 'attribute':
                replacement = '@[attribute]()'
                end = null
                setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
                break;
            case 'object':
                replacement = '@[object]()'
                end = null
                setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
                break;
            default:
                break;
        }
        cm.replaceRange(replacement, start, end)
        if (setCursorTo !== false) {
            cm.setCursor(setCursorTo.line, setCursorTo.ch)
        }
        cm.focus()
    }

    function buildMISPElementHints() {
        Object.keys(proxyMISPElements['attribute']).forEach(function(k) {
            var attribute = proxyMISPElements['attribute'][k]
            MISPElementValues.push([attribute.value, k])
            MISPElementTypes.push([attribute.type, k])
            MISPElementIDs.push([attribute.id, k])
            MISPElementIDs.push([attribute.uuid, k])
        })
        Object.keys(proxyMISPElements['object']).forEach(function(k) {
            var object = proxyMISPElements['object'][k]
            MISPElementTypes.push([object.name, k])
            MISPElementIDs.push([object.id, k])
            MISPElementIDs.push([object.uuid, k])
        })
    }


// Inject line numbers for sync scroll. Notes:
//
// - We track only headings and paragraphs on first level. That's enough.
// - Footnotes content causes jumps. Level limit filter it automatically.
function injectLineNumbers(tokens, idx, options, env, slf) {
    var line;
    if (tokens[idx].map && tokens[idx].level === 0) {
        line = tokens[idx].map[0];
        tokens[idx].attrJoin('class', 'line');
        tokens[idx].attrSet('data-line', String(line+1));
    }
    return slf.renderToken(tokens, idx, options, env, slf);
}


// Build offsets for each line (lines can be wrapped)
// That's a bit dirty to process each line everytime, but ok for demo.
// Optimizations are required only for big texts.
// Copyright: https://github.com/markdown-it/markdown-it/blob/master/support/demo_template/index.js
function buildScrollMap() {
    var i, offset, nonEmptyList, pos, a, b, lineHeightMap, linesCount,
    acc, sourceLikeDiv, textarea = $(cm.getWrapperElement()),
    _scrollMap;
    
    sourceLikeDiv = $('<div />').css({
        position: 'absolute',
        visibility: 'hidden',
        height: 'auto',
        width: textarea[0].clientWidth,
        'font-size': textarea.css('font-size'),
        'font-family': textarea.css('font-family'),
        'line-height': textarea.css('line-height'),
        'white-space': textarea.css('white-space')
    }).appendTo('body');
    
    offset = $viewerContainer.scrollTop() - $viewerContainer.offset().top;
    if ($(cm.getWrapperElement()).closest('.modal').length > 0) { // inside a modal
        offset -= 20
    }
    _scrollMap = [];
    nonEmptyList = [];
    lineHeightMap = [];
    
    acc = 0;
    cm.eachLine(function(line) {
        var h, lh;
        lineHeightMap.push(acc)
        if (line.text.length === 0) {
            acc++
            return
        }
        sourceLikeDiv.text(line.text);
        h = parseFloat(sourceLikeDiv.css('height'));
        lh = parseFloat(sourceLikeDiv.css('line-height'));
        acc += Math.round(h / lh);
    })
    sourceLikeDiv.remove();
    lineHeightMap.push(acc);
    linesCount = acc;
    
    for (i = 0; i < linesCount; i++) { _scrollMap.push(-1); }
    
    nonEmptyList.push(0);
    _scrollMap[0] = 0;
    
    $viewerContainer.find('.line').each(function (n, el) {
        var $el = $(el), t = $el.data('line');
        if (t === '') { return; }
        t = lineHeightMap[t];
        if (t !== 0) { nonEmptyList.push(t); }
        _scrollMap[t] = Math.round($el.offset().top + offset);
    });

    nonEmptyList.push(linesCount);
    _scrollMap[linesCount] = $viewerContainer[0].scrollHeight;
    
    pos = 0;
    for (i = 1; i < linesCount; i++) {
        if (_scrollMap[i] !== -1) {
            pos++;
            continue;
        }
        
        a = nonEmptyList[pos];
        b = nonEmptyList[pos + 1];
        _scrollMap[i] = Math.round((_scrollMap[b] * (i - a) + _scrollMap[a] * (b - i)) / (b - a));
    }
    
    return _scrollMap;
}

function doScroll(fun) {
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(fun, debounceDelay);
}

// Synchronize scroll position from source to result
var syncResultScroll = function () {
    var lineNo = Math.ceil(cm.getScrollInfo().top/cm.defaultTextHeight());
    if (!scrollMap) { scrollMap = buildScrollMap(); }
    var posTo = scrollMap[lineNo];
    $viewerContainer.stop(true).animate({
        scrollTop: posTo
    }, 100, 'linear');
}

// Synchronize scroll position from result to source
var syncSrcScroll = function () {
    var resultHtml = $viewerContainer,
    scrollTop  = resultHtml.scrollTop(),
    lines,
    i,
    line;
    
    if (!scrollMap) { scrollMap = buildScrollMap(); }
    
    lines = Object.keys(scrollMap);
    
    if (lines.length < 1) {
        return;
    }
    
    line = lines[0];
    
    for (i = 1; i < lines.length; i++) {
        if (scrollMap[lines[i]] < scrollTop) {
            line = lines[i];
            continue;
        }
        break;
    }
    cm.scrollTo(0, line*cm.defaultTextHeight())
}


</script>

<style> 
@media print {
    body * {
        visibility: hidden;
    }
    #viewer, #viewer * {
        visibility: visible;
    }
    #viewer {
        position: absolute;
        left: 0;
        top: 0;
    }
}

.split-container {
    overflow: hidden;
    min-height: 500px;
}

.modal-body-xl .split-container {
    max-height: calc(70vh - 50px)
}

.split-container > div {
}

.split-container.split-actif > #editor-container, .split-container.split-actif > #viewer-container {
    max-height: calc(100vh - 120px)
}

.modal-body-xl .split-container.split-actif > #editor-container,
.modal-body-xl .split-container.split-actif > #viewer-container {
}


#viewer-container {
    margin: 0 0;
    justify-content: center;
    padding: 7px;
    overflow-y: auto;
    padding: 0 15px;
    box-shadow: inset 0px 2px 6px #eee;
}

#editor-container {
    border: 1px solid #ccc;
    width: 50%;
    min-width: 300px;
    position: relative;
    float: left;
}

.split-container:not(.split-actif) #editor-container {
    float: unset;
    width: unset;
}

#editor {
    min-height: 500px;
    width: 100%;
    border-radius: 0;
    resize: vertical;
}

#viewer {
    width: 100%;
    max-width: 1200px;
    margin: auto;
}

#editor-container > div:not(.ui-resizable-handle) {
    width: 100%;
}

.split-container .ui-resizable-handle {
    box-shadow: 4px 0 6px #eee;
    width: 7px;
    position: absolute;
    right: -7px;
    z-index: 1;
    cursor: col-resize;
}

.ui-resizable-helper {
    border-right: 2px dotted #ccc;
    cursor: col-resize;
    z-index: 1060 !important;
}

#editor-subcontainer {
    display: flex;
    flex-direction: column;
}

#editor-subcontainer > div:not(#bottom-bar) {
    flex-grow: 1;
}

#bottom-bar {
    height: 1.5em;
}
#top-bar {
    height: 34px;
}
.editor-action-bar {
    display: flex;
    align-items: center;
    background-color: #3c3c3c;
    color: white;
    padding: 0 20px;
}
#top-bar .icon {
    padding: 2px 2px;
    border-radius: 2px;
    vertical-align: middle;
    font-size: 16px;
    margin: 0px 5px
}
#top-bar .icon:hover {
    background-color: #f3f3f3;
    color: black;
}
.top-bar-separator {
    display: inline-block;
    margin: auto 8px;
    width: 1px;
    height: 15px;
    background-color: #d0d0d0;
}

.dropdown-menu li .icon {
    width: 20px;
    display: inline-block;
}

.cm-s-default {
    width: 100%;
    height: calc(100vh - 120px - 1.5em - 34px)
}

.modal-body-xl .split-container .cm-s-default{
    max-height: calc(70vh - 55px)
}

.modal-body-xl #viewer {
    max-height: calc(70vh - 75px)
}

.popover {
    max-width: 66%;
}

.cm-s-default .CodeMirror-gutter-wrapper {
    z-index: 1;
}
.cm-s-default .CodeMirror-gutters {
    z-index: 0;
}

.link-not-active {
  pointer-events: none;
  cursor: default;
  text-decoration: none;
  color: black;
}

.misp-element-wrapper {
    padding: 2px 3px;
    margin: 3px 3px;
    border: 1px solid #ddd;
    background-color: #f5f5f5;
    border-radius: 3px;
    line-height: 24px;
}

.misp-element-wrapper.object {
    border: 0;
    background-color: #3465a4 !important;
    color: #ffffff;
}

.attributePicture > img {
    display: block;
    margin: 0 auto;
}

.CodeMirror-hint-active .blue {
    color: white !important;
}
</style>