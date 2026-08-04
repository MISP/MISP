<?php
if ($isSiteAdmin) {
    echo $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'admin', 'menuItem' => 'eventBlocklistsAdd']);
} else {
    echo $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'event-collection', 'menuItem' => 'eventBlocklistsAdd']);
}

echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => __('Add Event Blocklist Entries'),
        'description' => __('Simply paste a list of all the event UUIDs that you wish to block from being entered.'),
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
                'field' => 'event_orgc',
                'label' => __('Creating organisation'),
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) The organisation that the event is associated with')
            ],
            [
                'field' => 'event_info',
                'label' => __('Event info'),
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) the event info of the event that you would like to block. It\'s best to leave this empty if you are adding a list of UUIDs.')
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
