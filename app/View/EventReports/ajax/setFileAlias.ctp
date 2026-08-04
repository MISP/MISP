<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Set File Alias'),
        'model' => 'EventReport',
        'fields' => [
                [
                    'field' => 'filename',
                    'label' =>  __('Filename')
                ],
                [
                    'field' => 'alias',
                    'label' =>  __('Alias')
                ],
            ],
            'submit' => [
                'action' => $this->request->params['action'],
            ]
    )
));
?>
