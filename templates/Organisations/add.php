<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'data' => array(
            'description' => __('Organisations can be equivalent to legal entities or specific individual teams within such entities.'),
            'model' => 'Organisations',
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
                    'type' => 'uuid',
                    'stayInLine' => true,
                    'class' => 'input-xxlarge'
                ],
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
                    //'label' => __('Logo (48×48 %s)', Configure::read('Security.enable_svg_logos')? 'PNG or SVG' : 'PNG'),
                ],
                [
                    'field' => 'nationality',
                    //'options' => $countries,
                    'options' => ['Luxembourg' => 'Luxembourg', 'Germany' => 'Germany'],
                    'class' => 'span4',
                    'stayInLine' => 1,
                    'type' => 'dropdown'
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
            'submit' => array(
                'action' => $this->request->getParam('action')
            )
        )
    ));
?>
</div>
