<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Import from URL (event %s)', h($event_id)),
            'model' => 'EventReport',
            'fields' => array(
                array(
                    'type' => 'textarea',
                    'field' => 'url',
                    'class' => 'input span6',
                    'div' => 'text',
                    'label' =>  sprintf('<b>%s:</b> ', __('URL')) . __('Content for this URL will be downloaded and converted to Markdown')
                ),
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => sprintf('submitPopoverForm(\'%s\', \'addEventReport\', 0, 1)', h($event_id))
            )
        )
    ));
