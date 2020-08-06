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
    var renderDelay = 50;
    var renderTimer;
    var $splitContainer, $editorContainer, $rawContainer, $viewerContainer, $resizableHandle
    var $editor, $viewer, $raw
    var $saveMarkdownButton, $mardownViewerToolbar
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';

    var contentChanged = false
    var defaultMode = 'viewer'
    var currentMode
    var splitEdit = true
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
            minWidth: 300,
            stop: function() {
                cm.refresh()
            }
        })
        renderMarkdown()
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
            if (mode != 'splitscreen') {
                $editorContainer.css('width', '100%');
            }
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
        $viewer.html(result);
    }

    function doRender() {
        clearTimeout(renderTimer);
        renderTimer = setTimeout(function() {
            renderMarkdown();
        }, renderDelay);
    }


</script>

<style> 
.split-container {
    display: flex;
    overflow: hidden;
    min-height: 700px;
}

.modal-body-xl .split-container {
    max-height: calc(70vh - 50px)
}

.split-container > div {
}

.split-container > #editor-container, .split-container > #viewer-container {
    max-height: 890px;
}


#viewer-container {
    margin-left: 10px;
    display: flex;
    justify-content: center;
    min-width: 600px;
    padding: 7px;
    overflow-y: auto;
    flex-grow: 1;
    border-left: 1px solid #00000010;
}

#editor-container {
    border: 1px solid #ccc;
    /* max-height: 890px; */
    width: 50%;
    min-width: 300px;
    position: relative;
    display: flex;
}


#editor {
    flex-grow: 1;
    min-height: 500px;
    width: 100%;
    border-radius: 0;
    resize: vertical;
}

#viewer {
    width: 100%;
    max-width: 1200px;
}

#editor-container > div:not(.ui-resizable-handle) {
    width: 100%;
}

.split-container .ui-resizable-handle {
    box-shadow: 4px 0 6px #eee;
    width: 7px;
    border-left: 1px solid #e0e0e0e0;
    position: absolute;
    right: -7px;
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
}
.link-not-active {
  pointer-events: none;
  cursor: default;
  text-decoration: none;
  color: black;
}
</style>