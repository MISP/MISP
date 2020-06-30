<?php
    $modelForForm = 'Server';
    $action = 'eventBlockRule';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Set event block rules'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'value',
                    'label' => __('Rule set (json)'),
                    'class' => 'input span6',
                    'type' => 'textarea',
                    'placeholder' =>
                    '{
    "tags": ["pandemic:covid-19=\"cyber\""]
}',
                    'default' => !empty($setting['AdminSetting']['value']) ? $setting['AdminSetting']['value'] : ''
                )
            ),
            'submit' => array(
                'action' => $action
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlockRule'));
?>
