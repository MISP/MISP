<?php
    $modelForForm = 'Server';
    $action = 'eventBlockRule';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Set event block rules'),
            'description' => __('Event block rules allow you to add a simple tag filter to block events from being added or synced. Events with a tag that matches any of the tags in the rule list will be blocked. It is not possible to add more complex rules with boolean logic (NOT, AND).'),
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
