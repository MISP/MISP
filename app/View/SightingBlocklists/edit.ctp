<?php
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'sightingBlocklistsAdd'));

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => __('Edit Sighting Blocklist Entries'),
        'description' => __('Blocklisting an organisation prevents the creation of any sighting by that organisation on this instance as well as syncing of that organisation\'s sightings to this instance. It does not prevent a local user of the blocklisted organisation from logging in and editing or viewing data. <br/>Paste a list of all the organisation UUIDs that you want to add to the blocklist below (one per line).'),
        'fields' => [
            [
                'field' => 'org_uuid',
                'label' => __('UUIDs'),
                'default' => $blockEntry['SightingBlocklist']['org_uuid'],
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'type' => 'textarea',
                'disabled' => true,
                'placeholder' => __('Enter a single or a list of UUIDs')
            ],
            [
                'field' => 'org_name',
                'label' => __('Organisation name'),
                'default' => $blockEntry['SightingBlocklist']['org_name'],
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) The organisation name that the organisation is associated with')
            ],
            [
                'field' => 'comment',
                'label' => __('Comment'),
                'default' => $blockEntry['SightingBlocklist']['comment'],
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
