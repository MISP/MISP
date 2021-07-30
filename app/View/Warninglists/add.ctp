<?php
$action = $this->request->params['action'];
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => $action === 'add' ? __('Add warninglist') : __('Edit warninglist'),
        'model' => 'Warninglist',
        'fields' => array(
            array(
                'field' => 'name',
                'class' => 'input span6',
            ),
            array(
                'field' => 'description',
                'class' => 'input span6',
                'rows' => 1,
            ),
            array(
                'field' => 'type',
                'class' => 'input',
                'options' => $possibleTypes,
                'type' => 'dropdown'
            ),
            array(
                'field' => 'category',
                'class' => 'input',
                'options' => $possibleCategories,
                'type' => 'dropdown'
            ),
            array(
                'label' => __('Accepted attribute types'),
                'field' => 'matching_attributes',
                'type' => 'dropdown',
                'multiple' => 'multiple',
            ),
            array(
                'label' => __('Values (one value per line, for value comment use #)'),
                'field' => 'entries',
                'type' => 'textarea',
                'rows' => 10,
            ),
        ),
        'submit' => array(
            'action' => $action
        )
    )
));
echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'warninglist',
    'menuItem' => $action === 'add' ? 'add' : 'edit',
    'id' => $action === 'add' ? null : $entity['Warninglist']['id'],
    'isDefault' => false,
]);
?>
<script type="text/javascript">
    $('#WarninglistMatchingAttributes').chosen();
</script>
