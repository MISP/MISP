<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'formOptions' => array(
        'enctype' => 'multipart/form-data',
    ),
    'data' => array(
        'model' => 'Galaxy',
        'title' => __('Import galaxy clusters'),
        'description' => __('Paste a JSON of cluster to import or provide a JSON file below.'),
        'fields' => array(
            array(
                'field' => 'json',
                'type' => 'text',
                'class' => 'input span6',
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Galaxy JSON'),
                'rows' => 18
            ),
            array(
                'field' => 'submittedjson',
                'label' => __('JSON file'),
                'type' => 'file',
            ),
        )
    )
));

echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'import'));
