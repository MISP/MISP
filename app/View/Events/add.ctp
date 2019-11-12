<?php
    $modelForForm = 'Event';
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Add Event'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'org_id',
                    'class' => 'org-id-picker-hidden-field',
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
                    'default' => $initialDistribution
                ),
                array(
                    'field' => 'sharing_group_id',
                    'class' => 'input',
                    'options' => $sharingGroups,
                    'label' => __("Sharing Group")
                ),
                array(
                    'field' => 'threat_level_id',
                    'class' => 'input',
                    'options' => $threatLevels,
                    'label' => __("Threat Level")
                ),
                array(
                    'field' => 'analysis',
                    'class' => 'input',
                    'options' => $analysisLevels
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'add'));
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
