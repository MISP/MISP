<?php
    $mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
    $mayPublish = ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id']);
    $modelForForm = 'Event';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Edit Event'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'event_id',
                    'type' => 'text',
                    'hidden' => true
                ),
                array(
                    'field' => 'date',
                    'class' => 'datepicker',
                    'type' => 'text'
                ),
                array(
                    'field' => 'distribution',
                    'class' => 'input',
                    'options' => $distributionLevels,
                    'default' => $event['Event']['distribution']
                ),
                array(
                    'field' => 'sharing_group_id',
                    'class' => 'input',
                    'options' => $sharingGroups,
                    'default' => $event['Event']['sharing_group_id'],
                    'label' => __("Sharing Group")
                ),
                array(
                    'field' => 'threat_level_id',
                    'class' => 'input',
                    'options' => $threatLevels,
                    'default' => $event['Event']['threat_level_id'],
                    'label' => __("Threat Level")
                ),
                array(
                    'field' => 'analysis',
                    'class' => 'input',
                    'options' => $analysisLevels,
                    'default' => $event['Event']['analysis']
                ),
                array(
                    'field' => 'info',
                    'label' => __('Event Info'),
                    'class' => 'input-xxlarge',
                    'type' => 'text',
                    'placeholder' => __('Quick Event Description or Tracking Info')
                ),
                array(
                    'field' => 'extends_uuid',
                    'class' => 'input-xxlarge',
                    'placeholder' => __('Event UUID or ID. Leave blank if not applicable.'),
                    'label' => __("Extends Event")
                )
            ),
            'submit' => array(
                'action' => $this->request->params['action']
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'editEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>

<script type="text/javascript">
    $('#EventDistribution').change(function() {
        checkSharingGroup('Event');
    });

    $("#EventExtendsUuid").keyup(function() {
        previewEventBasedOnUuids();
    });

    $(document).ready(function() {
        checkSharingGroup('Event');
        previewEventBasedOnUuids();
    });
</script>
<?php echo $this->Js->writeBuffer();
