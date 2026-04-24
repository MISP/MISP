<?php
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'formOptions' => [
        'enctype' => 'multipart/form-data',
    ],
    'data' => [
        'model' => 'EventTemplate',
        'title' => __('Import event template'),
        'description' => __(
            'Paste a previously-exported event template JSON below, '
            . 'or upload a .json file. Imported templates become owned '
            . 'by your organisation unless you use the overwrite mode.'
        ),
        'fields' => [
            [
                'field' => 'json',
                'type' => 'text',
                'class' => 'input span8',
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Paste the event template export document here'),
                'rows' => 16,
            ],
            [
                'field' => 'submittedjson',
                'label' => __('JSON file'),
                'type' => 'file',
            ],
            [
                'field' => 'mode',
                'label' => __('If a template with the same UUID already exists…'),
                'type' => 'dropdown',
                'default' => 'fail',
                'options' => [
                    'fail' => __('fail — abort the import (default)'),
                    'overwrite' => __('overwrite — replace in place, preserve original ownership'),
                    'duplicate_as_new' => __('duplicate_as_new — assign a fresh UUID and save as new'),
                ],
            ],
        ],
    ],
]);
echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'eventTemplates',
    'menuItem' => 'import',
]);
