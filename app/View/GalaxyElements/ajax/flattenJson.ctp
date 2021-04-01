<?php
    $modelForForm = 'GalaxyElement';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Convert JSON into galaxy cluster\'s elements'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'jsonData',
                    'label' => __('JSON'),
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear'
                ),
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => sprintf('submitPopoverForm(\'%s\', \'flattenJson\', 0, 1)', h($clusterId))
            ),
        ),
    ));
?>

<?php echo $this->Js->writeBuffer(); // Write cached scripts
