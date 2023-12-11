<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Create report from event', h($event_id)),
            'description' => __('Generate a report based on filtering criterias.'),
            'model' => 'EventReport',
            'fields' => array(
                array(
                    'type' => 'textarea',
                    'field' => 'filters',
                    'class' => 'input span6',
                    'div' => 'text',
                    'label' =>  __('REST search filters'),
                    'title' => __('Provide the filtering criterias for attributes to be taken into account in the report')
                ),
                array(
                    'type' => 'checkbox',
                    'field' => 'include_event_metadata',
                ),
                array(
                    'type' => 'checkbox',
                    'field' => 'include_correlations',
                ),
                array(
                    'type' => 'checkbox',
                    'field' => 'include_attack_matrix',
                ),
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => 'submitReportFromEvent()'
            )
        )
    ));

    echo $this->element('genericElements/assetLoader', array(
        'js' => array(
            'codemirror/codemirror',
            'codemirror/modes/javascript',
            'codemirror/addons/closebrackets',
            'codemirror/addons/lint',
            'codemirror/addons/jsonlint',
            'codemirror/addons/json-lint',
        ),
        'css' => array(
            'codemirror',
            'codemirror/show-hint',
            'codemirror/lint',
        )
    ));
?>

<script>
var cm
function setupCodemirror() {
    var cmOptions = {
        mode: "application/json",
        theme:'default',
        gutters: ["CodeMirror-lint-markers"],
        lint: true,
        lineNumbers: true,
        indentUnit: 4,
        showCursorWhenSelecting: true,
        lineWrapping: true,
        autoCloseBrackets: true,
    }
    var defaultEditorContent = {
        value: '',
        type: '',
        category: '',
        tags: '',
    }
    cm = CodeMirror.fromTextArea(document.getElementById('EventReportFilters'), cmOptions);
    cm.setValue(JSON.stringify(defaultEditorContent, null, 4))
}
setTimeout(setupCodemirror, 350);

function submitReportFromEvent() {
    cm.save()
    submitPopoverForm('<?= h($event_id) ?>', 'addEventReport', 0, 1)
}
</script>

<style>
.CodeMirror-wrap {
    border: 1px solid #cccccc;
    width: 500px;
    height: 150px;
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