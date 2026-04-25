<?php
    $modelForForm = 'Event';
    $action = $this->request->params['action'];
    $offerTemplateAlternative = (
        $action === 'add'
        && $this->Acl->canAccess('eventTemplates', 'instantiate')
    );
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
?>
<?php if ($offerTemplateAlternative): ?>
<!--
    The form (div.form) and the side menu (div.actions) are both
    floated in MISP's classic layout, so anything that follows
    them in the DOM has to clear both floats first or the browser
    squeezes it into the empty sliver between them and overlaps
    the form. clear:both takes care of that; the matching
    margin-left lines the callout up with the form column rather
    than spanning the side-menu gutter too.
-->
<div id="event-template-callout"
     style="display:none; clear:both; margin:18px 18px 24px 220px;
            padding:12px 14px; border:1px solid #d0d7de;
            border-radius:5px; background:#f7f8fa;">
    <div style="display:flex; align-items:center; gap:14px;">
        <div style="flex:1; line-height:1.4;">
            <div style="font-weight:600; color:#243447;">
                <?php echo __('Have a template for this incident?'); ?>
            </div>
            <div style="color:#5a6876; font-size:12px; margin-top:2px;">
                <?php echo __('Skip the blank form and pick a guided event-template walkthrough — pre-filled fields, attached objects, mandatory checks.'); ?>
            </div>
        </div>
        <button type="button" class="btn"
                style="flex-shrink:0; white-space:nowrap;"
                onclick="event.preventDefault(); openEventTemplatePicker();">
            <i class="fa fa-bolt"></i>
            <?php echo __('Create event via template instead'); ?>
        </button>
    </div>
</div>
<?php
    // Cake's theme resolution picks the BS5 partial under
    // Themed/Overmind/Elements/eventTemplates/templatePickerModal.ctp
    // when the Overmind theme is active; otherwise the default
    // BS2 partial. Either way the partial exposes
    // window.openEventTemplatePicker() — the same global the
    // callout button above invokes.
    echo $this->element('eventTemplates/templatePickerModal');
?>
<script>
(function () {
    // Reveal the callout only if at least one active event template
    // is visible to this user — no point dangling the offer if the
    // instance hasn't been seeded with any templates yet.
    fetch('<?php echo h($baseurl); ?>/event_templates/index.json', {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    }).then(function (r) {
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
    }).then(function (rows) {
        var hasActive = (rows || []).some(function (row) {
            var t = row.EventTemplate || {};
            return t.active === true || t.active === 1 || t.active === '1';
        });
        if (hasActive) {
            var $c = document.getElementById('event-template-callout');
            if ($c) { $c.style.display = ''; }
        }
    }).catch(function () { /* silent — no callout, no harm */ });
})();
</script>
<?php endif; ?>

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
