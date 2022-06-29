<?php
$modelForForm = 'SharingGroupBlueprints';
$edit = $this->request->params['action'] === 'edit' ? true : false;
$fields = [
    [
        'field' => 'name',
        'class' => 'span6'
    ],
    [
        'field' => 'rules',
        'type' => 'textarea'
    ]
];
$description = sprintf(
    '%s<br />%s<br /><br />%s<br />%s',
    __('Create a sharing group blueprint, which can be used to generate a sharing rule based on the nested rules described.'),
    __('Simply create a JSON dictionary using a combination of filters and boolean operators.'),
    '<span class="bold">Filters</span>: org_id, org_type, org_uuid, org_name, org_sector, org_nationality, sharing_group_id, , sharing_group_uuid',
    '<span class="bold">Boolean operators</span>: OR, AND, NOT'
);
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'description' => $description,
        'model' => 'SharingGroupBlueprint',
        'title' => $edit ? __('Edit SharingGroupBlueprint') : __('Add SharingGroupBlueprint'),
        'fields' => $fields,
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);

if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}

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
    var cm;
    setupCodeMirror()

    function setupCodeMirror() {
        var cmOptions = {
            mode: "application/json",
            theme:'default',
            gutters: ["CodeMirror-lint-markers"],
            lint: true,
            lineNumbers: true,
            indentUnit: 4,
            showCursorWhenSelecting: true,
            lineWrapping: true,
            autoCloseBrackets: true
        }
        cm = CodeMirror.fromTextArea(document.getElementById('SharingGroupBlueprintRules'), cmOptions);
        cm.on("keyup", function(cm, event) {
            $('#urlParams').val(cm.getValue())
        });
    }
</script>

<style>
    div .CodeMirror {
        width: 500px;
        border: 1px solid #ddd;
    }
</style>
