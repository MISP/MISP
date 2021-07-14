<?php
$modelForForm = 'Organisation';
echo $this->element('genericElements/Form/genericForm', [
    'form' => $this->Form,
    'formOptions' => [
        'enctype' => 'multipart/form-data',
    ],
    'data' => [
        'model' => $modelForForm,
        'title' => __('%s Organisation', Inflector::Humanize($action)),
        'fields' => [
            sprintf('<h4>%s</h4>', __('Mandatory Fields')),
            [
                'default' => true,
                'type' => 'checkbox',
                'field' => 'local',
                'label' => __('Local organisation'),
                'description' => __('If the organisation should have access to this instance, make sure that the Local organisation setting is checked. If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting.')
            ],
            [
                'field' => 'name',
                'label' => __('Organisation Identifier'),
                'placeholder' => __('Brief organisation identifier'),
                'class' => 'input-xxlarge',
            ],
            [
                'field' => 'uuid',
                'label' => __('UUID'),
                'placeholder' => __('Paste UUID or click generate'),
                'stayInLine' => true,
                'class' => 'input-xxlarge'
            ],
            sprintf('<span class="btn btn-inverse" role="button" tabindex="0" aria-label="%s" title="%s" style="margin-top:25px;margin-left: -132px;border-top-left-radius: 0;border-bottom-left-radius: 0;" onClick="generateOrgUUID();">%s</span>', __('Generate UUID'), __('Generate a new UUID for the organisation'), __('Generate UUID')),
            sprintf('<h4>%s</h4>', __('Optional Fields')),
            [
                'field' => 'description',
                'type' => 'textarea',
                'label' => __('A brief description of the organisation'),
                'placeholder' => __('A description of the organisation that is purely informational.'),
                'class' => 'input-xxlarge',
            ],
            [
                'field' => 'restricted_to_domain',
                'type' => 'textarea',
                'label' => __('Bind user accounts to domains (line separated)'),
                'placeholder' => __('Enter a (list of) domain name(s) to enforce when creating users.'),
                'class' => 'input-xxlarge',
            ],
            [
                'type' => 'file',
                'field' => 'logo',
                'error' => array('escape' => false),
                'label' => __('Logo (48×48 PNG or SVG)'),
            ],
            [
                'field' => 'nationality',
                'options' => $countries,
                'class' => 'span4',
                'stayInLine' => 1,
            ],
            [
                'field' => 'sector',
                'placeholder' => __('For example "financial".'),
                'class' => 'span3',
            ],
            [
                'field' => 'type',
                'label' => __('Type of organisation'),
                'placeholder' => __('Freetext description of the org.'),
                'class' => 'input-xxlarge',
            ],
            [
                'field' => 'contacts',
                'type' => 'textarea',
                'label' => __('Contact details'),
                'placeholder' => __('You can add some contact details for the organisation here, if applicable.'),
                'class' => 'input-xxlarge',
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action']
        ]
    ]
]);

echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'admin',
    'menuItem' => $action === 'add' ? 'addOrg' : 'editOrg',
    'orgId' => $action === 'edit' ? $orgId : 0,
]);