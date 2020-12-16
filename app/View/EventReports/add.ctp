<?php
    $modelForForm = 'EventReport';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => $action == 'add' ? __('Add Event Report for Event #%s', h($event_id)) : __('Edit Event Report %s (event #%s)', h($id), h($event_id)),
            'model' => 'EventReport',
            'fields' => array(
                array(
                    'field' => 'name',
                    'class' => 'input',
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'distribution',
                    'class' => 'input',
                    'options' => $distributionLevels,
                    'default' => isset($attribute['Attribute']['distribution']) ? $attribute['Attribute']['distribution'] : $initialDistribution,
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'sharing_group_id',
                    'class' => 'input',
                    'options' => $sharingGroups,
                    'label' => __("Sharing Group")
                ),
                array(
                    'field' => 'content',
                    'class' => 'textarea input span6'
                ),
                array(
                    'field' => 'event_id',
                    'default' => $event_id,
                    'type' => 'hidden'
                )
            ),
            'submit' => array(
                'action' => $this->request->params['action'],
                'ajaxSubmit' => sprintf('submitPopoverForm(\'%s\', \'addEventReport\', 0, 1)', h($event_id))
            ),
        )
    ));
?>
<?php
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'eventReports', 'menuItem' => $this->request->params['action']));
}
?>

<script type="text/javascript">
    $(function() {
        $('#EventReportDistribution').change(function() {
            checkSharingGroup('EventReport');
        });
        checkSharingGroup('EventReport');
    });
</script>
