<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Discard User Registrations'),
            'model' => 'User',
            'fields' => array(
            ),
            'description' => __('Are you sure you wish to remove the registration request(s) selected?'),
            'submit' => array(
                'ajaxSubmit' => "$('#UserDiscardRegistrationsForm').submit();"
            )
        )
    ));
?>
