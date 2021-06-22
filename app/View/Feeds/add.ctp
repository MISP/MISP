<?php
$modelForForm = 'Feeds';
$edit = $this->request->params['action'] === 'edit' ? true : false;
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => isset($edit) ? __('Edit MISP feed') : __('Add MISP feed'),
        'description' => __('Add a new MISP feed source.'),
        'model' => 'Feed',
        'fields' => [
            [
                'field' => 'enabled',
                'label' => __('Enabled'),
                'type' => 'checkbox'
            ],
            [
                'field' => 'caching_enabled',
                'label' => __('Caching enabled'),
                'type' => 'checkbox'
            ],
            [
                'field' => 'lookup_visible',
                'label' => __('Lookup visible'),
                'type' => 'checkbox'
            ],
            [
                'field' => 'name',
                'label' => __('Name'),
                'placeholder' => 'Feed name',
                'required' => 1
            ],
            [
                'field' => 'provider',
                'label' => __('Provider'),
                'placeholder' => 'Name of the content provider',
                'required' => 1
            ],
            [
                'field' => 'input_source',
                'label' => __('Input Source'),
                'options' => $dropdownData['inputSources'],
                'type' => 'dropdown'
            ],
            [
                'field' => 'url',
                'label' => __('URL'),
                'placeholder' => 'URL of the feed',
                'required' => 1
            ],
            [
                'field' => 'source_format',
                'label' => __('Source Format'),
                'options' => $dropdownData['feedTypes'],
                'type' => 'dropdown'
            ],
            [
                'field' => 'headers',
                'label' => __('Any headers to be passed with requests (for example: Authorization)'),
                'class' => 'span6',
                'placeholder' => 'Line break separated list of headers in the "headername: value" format',
                'rows' => 4,
            ],
            [
                'field' => 'distribution',
                'label' => __('Distribution'),
                'options' => $dropdownData['distributionLevels'],
                'selected' => isset($entity['Feed']['distribution']) ? $entity['Feed']['distribution'] : 3,
                'type' => 'dropdown'
            ],
            [
                'field' => 'tag_id',
                'label' => __('Default Tag'),
                'options' => $dropdownData['tags'],
                'selected' => isset($entity['Feed']['tag_id']) ? $entity['Feed']['tag_id'] : '0',
                'type' => 'dropdown',
                'searchable' => 1
            ],
            [
                'field' => 'rules',
                'label' => __('Filter rules'),
                'type' => 'pullRules',
                'tags' => $dropdownData['tags'],
                'orgs' => $dropdownData['orgs'],
                'pull_rules' => $entity['Feed']['rules']
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
?>

<?php
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
