<?php
echo $this->element('genericElements/Form/genericForm', array(
    'form' => $this->Form,
    'data' => array(
        'title' => __('Merge data from event'),
        'description' => __('Merge all objects, attributes and their respective tags from the selected event into event #%s', $target_event['Event']['id']),
        'model' => 'Event',
        'fields' => array(
            array(
                'field' => 'source_id',
                'class' => 'input span6',
                'type' => 'text',
                'label' => __('Source event ID or UUID'),
                'placeholder' => __('ID or UUID of the event to merge from')
            ),
            '<div id="event_preview" style="width:446px;"></div>'
        ),
        'submit' => array(
            'action' => 'merge'
        )
    )
));
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'merge', 'event' => $target_event));
?>
<script type="text/javascript">
    $(function() {
        $("#EventSourceId").keyup(delay(function() {
            previewEventBasedOnUuids($(this).val());
        }, 100));
        previewEventBasedOnUuids($('#EventSourceId').val());
    });
</script>
