<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Merge data from event'),
            'description' => __('Merge all objects, attributes and their respective tags from the selected event into event #%s', $this->request->data['Event']['target_id']),
            'model' => 'Event',
            'fields' => array(
                array(
                    'field' => 'source_id',
                    'class' => 'input span6',
                    'type' => 'text',
                    'label' => __('Source event ID or UUID'),
                    'placeholder' => __('ID or UUID of the event to merge from')
                )
            ),
            'submit' => array(
                'action' => 'merge'
            )
        )
    ));
    $event = ['Event' => ['id' => $this->request->data['Event']['target_id']]];
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'merge', 'event' => $event));
