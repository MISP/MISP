<?php
    $modelForForm = 'Event';
    $action = $this->request->params['action'];
    echo $this->element('genericElements/Form/genericForm', [
        'form' => $this->Form,
        'data' => [
            'title' => __('Populate Event'),
            'model' => $modelForForm,
            'fields' => [
                [
                    'field' => 'json',
                    'class' => 'input-big-chungus',
                    'type' => 'textarea'
                ],
            ],
            'submit' => [
                'action' => $action
            ]
        ]
    ]);
    echo $this->element('/genericElements/SideMenu/side_menu', [
        'menuList' => 'event',
        'menuItem' => 'populate',
        'event' => $event,
    ]);
    echo $this->element('genericElements/assetLoader', array(
        'js' => array(
            'codemirror/codemirror',
            'codemirror/modes/javascript',
            'codemirror/addons/show-hint',
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
<script type="text/javascript">
    $(function() {
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
            extraKeys: {
                "Esc": function(cm) {
                },
            },
        }
        cm = CodeMirror.fromTextArea(document.getElementById('EventJson'), cmOptions);
    });
</script>

<style>
.CodeMirror-wrap {
    border: 1px solid #cccccc;
    width: 700px;
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
