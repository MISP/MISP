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
        <button id="saveMarkdownButton" type="button" class="btn btn-success" onclick="saveMarkdown()">
            <i class="<?= $this->FontAwesome->getClass('save') ?> fa-save"></i>
            <?= __('Save') ?>
        </button>
    </div>
</div>

<div class="raw-container">
    <pre id="raw"><?php echo h($markdown) ?></pre>
</div>
<div class="split-container">
    <div id="editor-container">
        <div id="editor-subcontainer">
            <textarea id="editor"></textarea>
            <div id="bottom-bar">
                <span id="lastModifiedField">
                    <?= isset($lastModified) ? h($lastModified) : '' ?>
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
            'markdown-it',
            'highlight.min',
            'codemirror/codemirror',
            'codemirror/modes/markdown',
            'codemirror/addons/simplescrollbars',
        ),
        'css' => array(
            'highlight.min',
            'codemirror',
            'codemirror/simplescrollbars',
        )
    ));
?>
<script>
    'use strict';
    var md, cm;
    var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
    var modelName = '<?= h($modelName) ?>';
    var mardownModelFieldName = '<?= h($mardownModelFieldName) ?>';
    var debounceDelay = 50;
    var renderTimer, scrollTimer;
    var scrollMap;
    var $splitContainer, $editorContainer, $rawContainer, $viewerContainer, $resizableHandle
    var $editor, $viewer, $raw
    var $saveMarkdownButton, $mardownViewerToolbar
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';

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
                }
            }
        }
        cm = CodeMirror.fromTextArea($editor[0], cmOptions);
        cm.on('changes', function() {
            doRender();
        })
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

    function renderMarkdown() {
        var toRender = getEditorData();
        var result = md.render(toRender);
        scrollMap = null;
        $viewer.html(result);
    }

    function doRender() {
        clearTimeout(renderTimer);
        renderTimer = setTimeout(renderMarkdown, debounceDelay);
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
        tokens[idx].attrSet('data-line', String(line));
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

    // SCROLL SYNC NOT WORKING IN MODAL
    
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
.split-container {
    overflow: hidden;
    min-height: 700px;
}

.modal-body-xl .split-container {
    max-height: calc(70vh - 50px)
}

.split-container > div {
}

.split-container.split-actif > #editor-container, .split-container.split-actif > #viewer-container {
    max-height: calc(100vh - 120px)
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
    border-right: 2px dotted #CCC;
}

#editor-subcontainer {
    display: flex;
    flex-direction: column;
}

#editor-subcontainer > div:not(#bottom-bar) {
    flex-grow: 1;
}

#bottom-bar {
    display: none;
    height: 2em;
    width: 100%
}

.cm-s-default {
    width: 100%;
    height: calc(100vh - 120px)
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
</style>