<?php
    $modelForForm = 'Taxonomy';
    echo $this->element('genericElements/Form/genericForm', [
        'form' => $this->Form,
        'data' => [
            'title' => empty($this->request->params['named']['enable']) ? __('Confirm creation of Taxonomy Tag') : __('Confirm enabling Taxonomy Tag'),
            'description' => __('Tag `%s` will be %s.',
                $this->request->data['Taxonomy']['name'],
                !empty($this->request->params['named']['enable']) ? 
                    __('enabled') : (
                    !empty($this->request->params['named']['update']) ? __('updated') : __('created')
                )
            ),
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'addTag'));
}
?>