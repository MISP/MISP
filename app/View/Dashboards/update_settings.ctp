<?php
    $modelForForm = 'Dashboard';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'url' => 'updateSettings',
        'data' => array(
            'title' => __('Add Widget'),
            'model' => 'Dashboard',
            'fields' => array(
                array(
                    'field' => 'value',
                ),
            ),
            'submit' => array(
                'action' => 'updateSettings',
            ),
        )
    ));
?>
