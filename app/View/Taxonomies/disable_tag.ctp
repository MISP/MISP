<?php
    $modelForForm = 'Taxonomy';
    echo $this->element('genericElements/Form/genericForm', [
        'form' => $this->Form,
        'data' => [
            'title' => __('Confirm disabling Taxonomy Tag'),
            'description' => __('Tag `%s` will be disabled.', $this->request->data['Taxonomy']['name']),
            'model' => $modelForForm,
            'fields' => [
                [
                    'field' => 'taxonomy_id',
                    'type' => 'hidden',
                    'class' => 'input-xxlarge',
                ],
                [
                    'field' => 'name',
                    'type' => 'hidden',
                    'class' => 'input-xxlarge',
                ],
            ],
            'submit' => [
                'action' => $this->request->params['action'],
            ],
        ]
    ]);
?>
<?php
if (empty($ajax)) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'disableTag'));
}
?>