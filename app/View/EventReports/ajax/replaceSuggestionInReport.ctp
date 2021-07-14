<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Replace suggestions in report'),
            'model' => 'EventReport',
            'fields' => array(
                array(
                    'field' => 'suggestions',
                    'type' => 'textarea'
                ),
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => ''
            ),
        )
    ));
?>
