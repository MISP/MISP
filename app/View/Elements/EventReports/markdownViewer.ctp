<div style="margin-bottom: 10px;">
    <button id="cancelEditButton" type="button" class="btn btn-inverse" onclick="toggleEditor()">
        <i class="<?= $this->FontAwesome->getClass('times') ?> fa-times"></i>
        <?= __('Cancel Edit') ?>
    </button>
    <button id="toggleEditButton" type="button" class="btn btn-inverse" onclick="toggleEditor()">
        <i class="<?= $this->FontAwesome->getClass('edit') ?> fa-edit"></i>
        <?= __('Edit') ?>
    </button>
    <button id="saveMarkdownButton" type="button" class="btn btn-primary" onclick="saveMarkdown()" disabled>
        <i class="<?= $this->FontAwesome->getClass('edit') ?> fa-edit"></i>
        <?= __('Save') ?>
    </button>
</div>
<!-- <div id="raw">
    <pre><?php echo h($markdown) ?></pre>
</div> -->
<div class="editorMode-container">
    <a id="linkSplitEdit" class="useCursorPointer bold link-not-active">
        <i class="<?= $this->FontAwesome->getClass('columns') ?> fa-columns"></i>
        <?= __('Toggle Split Edit') ?>
    </a>
    <a id="linkMonoEdit" class="useCursorPointer">
        <i class="<?= $this->FontAwesome->getClass('window-maximize') ?> fa-window-maximize"></i>
        <?= __('Toggle Split Edit') ?>
    </a>
</div>
<div class="split-container">
    <div id="editor-container" style="display: flex;">
        <textarea id="editor"></textarea>
    </div>
    <div id="viewer-container">
        <div id="lastModifiedField">
            <?= isset($lastModified) ? h($lastModified) : '' ?>
        </div>
        <div id="viewer"></div>
    </div>
</div>

<?php
    echo $this->element('genericElements/assetLoader', array(
        'js' => array('markdown-it', 'highlight.min', 'codemirror/codemirror', 'codemirror/modes/markdown'),
        'css' => array('highlight.min', 'codemirror')
    ));
?>
<script>
    'use strict';
    var md, cm;
    var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
    var modelName = '<?= h($modelName) ?>';
    var mardownModelFieldName = '<?= h($mardownModelFieldName) ?>';
    var renderTimer;
    var renderDelay = 50;
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';
    var $editorContainer, $editor, $viewer, $viewerContainer, $saveMarkdownButton, $linkSplitEdit, $linkMonoEdit, $cancelEditButton, $toggleEditButton
    var editTurnedOn = false
    var splitEdit = true
    $(document).ready(function() {
        $editorContainer = $('#editor-container')
        $editor = $('#editor')
        $viewer = $('#viewer')
        $viewerContainer = $('#viewer-container')
        $saveMarkdownButton = $('#saveMarkdownButton')
        $cancelEditButton = $('#cancelEditButton')
        $toggleEditButton = $('#toggleEditButton')
        $linkSplitEdit = $('#linkSplitEdit')
        $linkMonoEdit = $('#linkMonoEdit')

        // $editorContainer.hide();
        $saveMarkdownButton.hide();
        $linkSplitEdit.hide();
        $linkMonoEdit.hide();
        $cancelEditButton.hide();
        setEditorData(originalRaw);
        initMarkdownIt()

        $linkSplitEdit.add($linkMonoEdit).click(function() {
            toggleSplitEdit()
        })
        $editor.on('input', function() {
            doRender();
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

        var cmOptions = {
            mode: 'markdown',
            theme: "default",
            lineNumbers: true,
            indentUnit: 4,
            showCursorWhenSelecting: true,
        }
        cm = CodeMirror.fromTextArea($editor[0], cmOptions);
    }
    
    function toggleEditor() {
        $editorContainer.toggle()
        $saveMarkdownButton.toggle()
        $linkSplitEdit.toggle()
        $linkMonoEdit.toggle()
        $cancelEditButton.toggle()
        $toggleEditButton.toggle()
        editTurnedOn = !editTurnedOn
        setEditorData(originalRaw)
        renderMarkdown()
    }

    function toggleSplitEdit() {
        splitEdit = !splitEdit
        $linkSplitEdit.toggleClass('link-not-active')
        $linkMonoEdit.toggleClass('link-not-active')
        if (splitEdit) {
            $viewerContainer.show()
        } else {
            $viewerContainer.hide()
        }
    }

    function getEditorData() {
        return $editor.val()
    }

    function setEditorData(data) {
        $editor.val(data)
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
            $saveMarkdownButton.prop('disabled', false);
            renderMarkdown();
        }, renderDelay);
    }


</script>

<style> 
.split-container {
    display: flex;
    justify-content: center;
}

.split-container > div {
    flex-grow: 1;
    margin-left: 10px;
    min-width: 50%;
}

.editorMode-container {
    margin-left: 10px;
}

.editorMode-container > a {
    margin: 2px 5px;
}

#editor {
    min-height: 500px;
    width: 100%;
    border-radius: 0;
    resize: vertical;
}

.cm-s-default {
    width: 100%;
}

#viewer-container {
    max-width: 1200px;
    padding: 7px;
    box-shadow: 3px 3px 3px 0px rgba(0,0,0,0.75);
    border: 1px solid;
}

.link-not-active {
  pointer-events: none;
  cursor: default;
  text-decoration: none;
  color: black;
}
</style>