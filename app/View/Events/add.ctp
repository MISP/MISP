<?php
    $modelForForm = 'Event';
    $action = $this->request->params['action'];
    $offerTemplateAlternative = false;
    if ($action === 'add'
        && $this->Acl->canAccess('eventTemplates', 'instantiate')
    ) {
        // Count once, server-side, with the same visibility scope
        // EventTemplatesController::__visibilityConditions enforces:
        // site admins see everything, everyone else sees their own
        // org's templates plus community-distributed (distribution = 1).
        // A single COUNT against an indexed column is cheap; doing this
        // here lets the callout render in its final state on first
        // paint with no fetch/reveal flash.
        App::uses('ClassRegistry', 'Utility');
        $__et = ClassRegistry::init('EventTemplate');
        $__conds = array('EventTemplate.active' => 1);
        if (empty($isSiteAdmin)) {
            $__conds['OR'] = array(
                'EventTemplate.org_id' => (int)$me['org_id'],
                'EventTemplate.distribution' => 1,
            );
        }
        $offerTemplateAlternative = (bool)$__et->find('count', array(
            'recursive' => -1,
            'conditions' => $__conds,
        ));
    }
    if ($offerTemplateAlternative) {
        ob_start();
    }
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
    if ($offerTemplateAlternative) {
        // Capture genericForm's output and splice the callout in
        // just before the wrapper's closing </div>, so the callout
        // ends up inside div.form (or .menuless-form) and shares
        // the form's float column geometry — no JS relocation, no
        // first-paint gap from a node moving after layout.
        $formHtml = ob_get_clean();
        $title = h(__('Have a template for this report?'));
        $hint  = h(__('Skip the manual creation and pick a guided event-template walkthrough — pre-filled fields, attached objects, mandatory checks.'));
        $cta   = h(__('Create event via template instead'));
        $callout = <<<HTML
<div id="event-template-callout" style="max-width:600px; margin:18px 0 0 0; padding:12px 14px; border:1px solid #d0d7de; border-radius:5px; background:#f7f8fa;">
    <div style="display:flex; align-items:center; gap:14px;">
        <div style="flex:1; line-height:1.4;">
            <div style="font-weight:600; color:#243447;">{$title}</div>
            <div style="color:#5a6876; font-size:12px; margin-top:2px;">{$hint}</div>
        </div>
        <button type="button" class="btn btn-primary" style="flex-shrink:0; white-space:nowrap;" onclick="event.preventDefault(); openEventTemplatePicker();"><i class="fa fa-bolt"></i> {$cta}</button>
    </div>
</div>
HTML;
        $insertAt = strrpos($formHtml, '</div>');
        if ($insertAt !== false) {
            $formHtml = substr($formHtml, 0, $insertAt)
                . $callout
                . substr($formHtml, $insertAt);
        } else {
            $formHtml .= $callout;
        }
        echo $formHtml;
    }
    echo $this->element('/genericElements/SideMenu/side_menu', array(
        'menuList' => $action === 'add' ? 'event-collection' : 'event',
        'menuItem' => $action === 'add' ? 'add' : 'editEvent',
        'event' => isset($event) ? $event : null,
    ));
?>
<?php if ($offerTemplateAlternative):
    // Cake's theme resolution picks the BS5 partial under
    // Themed/Overmind/Elements/eventTemplates/templatePickerModal.ctp
    // when the Overmind theme is active; otherwise the default
    // BS2 partial. Either way the partial exposes
    // window.openEventTemplatePicker() — the same global the
    // callout button above invokes.
    echo $this->element('eventTemplates/templatePickerModal');
endif; ?>

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
