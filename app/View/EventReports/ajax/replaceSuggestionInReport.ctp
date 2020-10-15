<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Replace suggestions in report'),
            'model' => 'EventReport',
            'fields' => array(
                array(
                    'field' => 'suggestions',
                    'class' => 'textarea'
                ),
                // array(
                //     'field' => 'contentWithSuggestions',
                //     'class' => 'textarea'
                // ),
                // array(
                //     'field' => 'suggestionsMapping',
                //     'class' => 'textarea'
                // ),
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => ''
            ),
        )
    ));
?>
