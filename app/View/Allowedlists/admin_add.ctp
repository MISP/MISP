<?php
    $modelForForm = 'Allowedlist';
    echo $this->element('genericElements/Form/genericForm', [
        'form' => $this->Form,
        'data' => [
            'title' => $action == 'add' ? __('Add Signature Allowedlist') : __('Edit Signature Allowedlist'),
            'model' => $modelForForm,
            'fields' => [
                [
                    'field' => 'name',
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'allowedlist', 'menuItem' => $action));
}
?>