<div style="margin-bottom: 10px;">
    <!-- <button type="button" class="btn btn-primary" onclick="renderMarkdown()">
        <i class="<?= $this->FontAwesome->getClass('markdown') ?> fa-markdown"></i>
        <?= __('Render Markdown') ?>
    </button> -->
    <button type="button" class="btn btn-inverse" onclick="toggleEditor()">
        <i class="<?= $this->FontAwesome->getClass('edit') ?> fa-edit"></i>
        <?= __('Edit') ?>
    </button>
    <button id="saveMarkdownButton" type="button" class="btn btn-primary" onclick="saveMarkdown()" disabled>
        <i class="<?= $this->FontAwesome->getClass('edit') ?> fa-edit"></i>
        <?= __('Save') ?>
    </button>
    <!-- <button type="button" class="btn btn-primary">
        <i class="<?= $this->FontAwesome->getClass('columns') ?> fa-columns"></i>
        <?= __('Split Edit') ?>
    </button> -->
</div>
<!-- <div id="raw">
    <pre><?php echo h($markdown) ?></pre>
</div> -->
<div class="viewer-container">
    <div id="editor-container" style="display: flex;">
        <textarea id="editor"></textarea>
    </div>
    <div id="viewer">
    </div>
</div>

<?php
    echo $this->element('genericElements/assetLoader', array(
        'js' => array('markdown-it')
    ));
?>
<script>
    var md;
    var originalRaw = <?= json_encode(is_array($markdown) ? $markdown : array($markdown), JSON_HEX_TAG); ?>[0];
    var modelName = '<?= h($modelName) ?>';
    var mardownModelFieldName = '<?= h($mardownModelFieldName) ?>';
    var renderTimer;
    var renderDelay = 50;
    var loadingSpanAnimation = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';
    $(document).ready(function() {
        $('#editor-container').hide();
        md = window.markdownit();
        setEditorData(originalRaw);
        $('#editor').on('input', function() {
            doRender();
        })
        renderMarkdown()
    })
    
    function toggleEditor() {
        $('#editor-container').show();
    }

    function getEditorData() {
        return $('#editor').val()
    }

    function setEditorData(data) {
        $('#editor').val(data)
    }

    function saveMarkdown() {
        var url = "<?= $baseurl ?>/eventReports/edit/<?= h($id) ?>"
        fetchFormDataAjax(url, function(formHTML) {
            $('body').append($('<div id="temp" style="display: none"/>').html(formHTML))
            var $tmpForm = $('#temp form')
            $tmpForm.find('[name="data[' + modelName + '][' + mardownModelFieldName + ']"]').val(getEditorData())
            
            $.ajax({
                data: $('#GalaxyAttachMultipleClustersForm').serialize(),
                beforeSend: function() {
                    $('#saveMarkdownButton')
                        .prop('disabled', 'disabled')
                        .append(loadingSpanAnimation);
                },
                success:function(data, textStatus) {
                    showMessage('success', '<?= 'Markdown saved' ?>');
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    showMessage('fail', '<?= 'Could not save markdown. Reason' ?>' + ": " + errorThrown);
                },
                complete:function() {
                    $('#temp').remove();
                    $('#saveMarkdownButton')
                        .prop('disabled', '')
                        .find('#loadingSpan').remove();
                },
                type:"post",
                url: url
            })
        })
    }

    function renderMarkdown() {
        var toRender = getEditorData();
        var result = md.render(toRender);
        $('#viewer').html(result);
    }

    function doRender() {
        clearTimeout(renderTimer);
        renderTimer = setTimeout(function() {
            $('#saveMarkdownButton').prop('disabled', '');
            renderMarkdown();
        }, renderDelay);
    }


</script>

<style> 
.viewer-container {
    display: flex;
}

.viewer-container > div {
    flex-grow: 1;
    margin-left: 10px;
}

#editor {
    width: 100%;
    border-radius: 0;
}
</style>