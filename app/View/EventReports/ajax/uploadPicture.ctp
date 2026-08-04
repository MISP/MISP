<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'formOptions' => [
            'enctype' => 'multipart/form-data',
        ],
        'data' => [
            'title' => __('Upload picture (event-report %s)', h($report_id)),
            'model' => 'EventReport',
            'fields' => [
                [
                    'type' => 'file',
                    'field' => 'picture',
                    'class' => 'input span6',
                    'div' => 'text',
                    'label' =>  __('Picture to be uploaded')
                ],
                [
                    'type' => 'checkbox',
                    'field' => 'save_as_attachment',
                    'label' =>  __('Should the picture added as an Attribute attachment or uploaded to the instance\'s asset folder')
                ],
                [
                    'field' => 'comment',
                    'label' =>  __('The comment of the Attribute')
                ],
                [
                    'field' => 'distribution',
                    'label' =>  __('The distribution of the Attribute'),
                    'options' => $distributionLevels,
                ],
            ],
            'submit' => [
                'action' => $this->request->params['action'],
                'ajaxSubmit' => sprintf('submitPopoverForm(\'%s\', \'uploadPicture\', 0, 1)', h($report_id))
            ]
        ]
    ));
