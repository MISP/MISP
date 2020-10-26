
<?php
echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Automatic entities extraction'),
            'description' => __('Automatically extracting entities from a report will use the freetext import tools to extract and create attributes from the report.'),
            'model' => 'EventReport',
            'fields' => array(
                sprintf('<h5>%s</h5>', __('Post extraction actions:')),
                array(
                    'label' => __('Tag the event with contextual elements found in the report'),
                    'field' => 'tag_event',
                    'type' => 'checkbox',
                    'div' => array('class' => 'checkbox')
                ),
                array(
                    'field' => 'id',
                    'default' => $reportId,
                    'type' => 'hidden'
                )
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => sprintf('submitPopoverForm(\'%s\', \'extractAllFromReport\', 0, 1)', h($reportId))
            ),
        )
    ));
