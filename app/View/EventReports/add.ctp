<?php
    $modelForForm = 'EventReport';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => $action == 'add' ? __('Add Event Report') : __('Edit Event Report'),
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
                    'class' => 'textarea'
                ),
                array(
                    'field' => 'event_id',
                    'default' => $event_id,
                    'type' => 'hidden'
                )
            ),
            'submit' => array(
                'action' => $this->request->params['action']
            )
        )
    ));
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-report', 'menuItem' => $this->request->params['action']));
?>

<script type="text/javascript">
    $(document).ready(function() {
        $('#EventReportDistribution').change(function() {
            checkSharingGroup('EventReport');
        });
        checkSharingGroup('EventReport');
    });
</script>
