<?php

$params['type'] = 'textarea';
echo $this->Form->input($fieldData['field'], $params);

echo $this->element('genericElements/assetLoader', array(
    'js' => array(
        'codemirror/codemirror',
        'codemirror/modes/markdown',
    ),
    'css' => array(
        'codemirror',
    )
));

?>

<script>
    var cm;
    function setupCodeMirror() {
        var cmOptions = {
            mode: "text/markdown",
            theme:'default',
            gutters: ["CodeMirror-lint-markers"],
            lineNumbers: true,
            indentUnit: 4,
            showCursorWhenSelecting: true,
            lineWrapping: true,
            autoCloseBrackets: true,
            extraKeys: {
                "Esc": function(cm) {
                },
            },
        }
        cm = CodeMirror.fromTextArea(document.getElementById('EventReportTemplateVariableValue'), cmOptions);
    }

    $(document).ready(function() {
        setupCodeMirror()
        $('#EventReportTemplateVariableValue').change(function() {
            console.log($(this).val())
        })
    })
</script>

<style>
.CodeMirror-wrap {
    border: 1px solid #cccccc;
    min-width: 800px;
    height: 800px;
    margin-bottom: 10px;
    resize: auto;
}
.cm-trailingspace {
    background-image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAQAAAACCAYAAAB/qH1jAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH3QUXCToH00Y1UgAAACFJREFUCNdjPMDBUc/AwNDAAAFMTAwMDA0OP34wQgX/AQBYgwYEx4f9lQAAAABJRU5ErkJggg==);
    background-position: bottom left;
    background-repeat: repeat-x;
}
.CodeMirror-gutters {
    z-index: 2;
}
</style>