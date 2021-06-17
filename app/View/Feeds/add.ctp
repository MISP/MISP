<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => isset($edit) ? __('Edit MISP feed') : __('Add MISP feed'),
        'description' => __('Add a new MISP feed source.'),
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
                'selected' => isset($feed['Feed']['distribution']) ? $feed['Feed']['distribution'] : 3,
                'type' => 'dropdown'
            ],
            [
                'field' => 'tag_id',
                'label' => __('Default Tag'),
                'options' => $dropdownData['tags'],
                'selected' => isset($feed['Feed']['tag_id']) ? $feed['Feed']['tag_id'] : 0,
                'type' => 'dropdown',
                'searchable' => 1
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
