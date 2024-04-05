<?php
echo $this->element(
    '/genericElements/SideMenu/side_menu',
    ['menuList' => 'admin', 'menuItem' => 'sightingBlocklistsAdd']
);

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => __('Add Sighting Blocklist Entries'),
        'description' => __('Blocklisting an organisation prevents the creation of any sighting by that organisation on this instance as well as syncing of that organisation\'s sightings to this instance. It does not prevent a local user of the blocklisted organisation from logging in and editing or viewing data. <br/>Paste a list of all the organisation UUIDs that you want to add to the blocklist below (one per line).'),
        'fields' => [
            [
                'field' => 'uuids',
                'label' => __('UUIDs'),
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'type' => 'textarea',
                'placeholder' => __('Enter a single or a list of UUIDs'),
            ],
            [
                'field' => 'org_name',
                'label' => __('Organisation name'),
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) The organisation name that the organisation is associated with')
            ],
            [
                'field' => 'comment',
                'label' => __('Comment'),
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) Any comments you would like to add regarding this (or these) entries.')
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
