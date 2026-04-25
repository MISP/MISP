<?php
    $modelForForm = 'Event';
    $action = $this->request->params['action'];
    $offerTemplateAlternative = (
        $action === 'add'
        && $this->Acl->canAccess('eventTemplates', 'instantiate')
    );
    if ($offerTemplateAlternative):
?>
<div class="event-template-callout"
     style="display:flex; align-items:center; gap:12px;
            background:#eef5fc; border:1px solid #bcd7ee;
            border-left:4px solid #2b8acb; border-radius:4px;
            padding:10px 14px; margin:0 0 14px 0;">
    <i class="fa fa-bolt" style="font-size:18px; color:#2b8acb;"></i>
    <div style="flex:1; line-height:1.35;">
        <div style="font-weight:600; color:#1a4f73;">
            <?php echo __('Have a template for this incident?'); ?>
        </div>
        <div style="color:#3a5a72; font-size:12px;">
            <?php echo __('Skip the blank form and pick a guided event-template walkthrough — pre-filled fields, attached objects, mandatory checks.'); ?>
        </div>
    </div>
    <button type="button" class="btn btn-primary"
            onclick="event.preventDefault(); openEventTemplatePicker();">
        <i class="fa fa-bolt"></i>
        <?php echo __('Create event via template instead'); ?>
    </button>
</div>
<?php
    endif;
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => $action === 'add' ? __('Add Event') : __('Edit Event'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'date',
                    'class' => 'datepicker',
                    'type' => 'text',
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'distribution',
                    'class' => 'input',
                    'options' => $distributionLevels,
                    'default' => isset($event['Event']['distribution']) ? $event['Event']['distribution'] : $initialDistribution,
                    'stayInLine' => 1,
                    'type' => 'dropdown'
                ),
                array(
                    'field' => 'sharing_group_id',
                    'class' => 'input',
                    'options' => $sharingGroups,
                    'label' => __("Sharing Group"),
                    'type' => 'dropdown',
                    'required' => false
                ),
                array(
                    'field' => 'threat_level_id',
                    'class' => 'input',
                    'options' => $threatLevels,
                    'default' => Configure::check('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : '4',
                    'label' => __("Threat Level"),
                    'stayInLine' => 1,
                    'type' => 'dropdown'
                ),
                array(
                    'field' => 'analysis',
                    'class' => 'input',
                    'options' => $analysisLevels,
                    'type' => 'dropdown'
                ),
                array(
                    'field' => 'info',
                    'label' => __('Event Info'),
                    'class' => 'input span6',
                    'type' => 'text',
                    'placeholder' => __('Quick Event Description or Tracking Info')
                ),
                array(
                    'field' => 'extends_uuid',
                    'class' => 'input span6',
                    'placeholder' => __('Event UUID or ID. Leave blank if not applicable.'),
                    'label' => __("Extends Event"),
                    'default' => isset($extends_uuid) ? $extends_uuid : ''
                ),
                array(
                    'type' => 'div',
                    'style' => 'width:446px;',
                    'id' => 'event_preview',
                    'label' => false
                )
            ),
            'submit' => array(
                'action' => $action
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array(
        'menuList' => $action === 'add' ? 'event-collection' : 'event',
        'menuItem' => $action === 'add' ? 'add' : 'editEvent',
        'event' => isset($event) ? $event : null,
    ));
    if ($offerTemplateAlternative) {
        // Cake's theme resolution picks the BS5 partial under
        // Themed/Overmind/Elements/eventTemplates/templatePickerModal.ctp
        // when the Overmind theme is active; otherwise the default
        // BS2 partial. Either way the partial exposes
        // window.openEventTemplatePicker() — the same global the
        // callout button above invokes.
        echo $this->element('eventTemplates/templatePickerModal');
    }
?>

<script type="text/javascript">
    $('#EventDistribution').change(function() {
        checkSharingGroup('Event');
    });

    $(function() {
        checkSharingGroup('Event');
        $("#EventExtendsUuid").keyup(delay(function() {
            previewEventBasedOnUuids($(this).val());
        }, 100));
        previewEventBasedOnUuids($("#EventExtendsUuid").val());
    });
</script>
<?php echo $this->Js->writeBuffer();
