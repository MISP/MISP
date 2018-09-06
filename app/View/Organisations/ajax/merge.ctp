<div class="events">
<?php echo $this->Form->create('Organisation', array(
        'onsubmit' => 'return confirm("' . __('This will remove the selected organisation and hand over all objects belonging to it to the target organisation. This process is irreversible. Are you sure you want to proceed?') . '");',
));?>
    <div class="legend"><?php echo __('Merge Organisation');?></div>
            <p class="red-background white"><?php echo __('Warning: Merging an organisation into another will be transfer all users and data belonging to the organisation to another.');?></p>
    <div class="overlay_spacing bottomGap">
        <div class="row-fluid">
            <div class="span6">
            <?php
                $default_type = 0;
                $default_id = 0;
                if (!empty($target)) {
                    $default_type = ($target['type'] == 'external') ? 1 : 0;
                    $default_id = $target['id'];
                }
                echo $this->Form->input('targetType', array(
                        'options' => array('Local', 'External'),
                        'label' => __('Organisation type'),
                        'style' => 'width:332px;',
                        'class' => 'mergeUpdate',
                        'default' => $default_type,
                        'div' => false,
                ));
            ?>
            </div>
            <div id="orgsLocal" class="span6" <?php echo $default_type == 1 ? 'style="display:none;"' : ''; ?>>
                <?php
                    $types = array('local', 'external');
                    echo $this->Form->input('orgsLocal', array(
                            'options' => $orgOptions['local'],
                            'class' => 'input mergeUpdate',
                            'label' => __('Target Local Organisation'),
                            'style' => 'width:332px;',
                            'default' => $default_id,
                            'div' => 'orgsLocal',
                    ));
                ?>
            </div>
            <div id="orgsExternal" class="span6" <?php echo $default_type == 0 ? 'style="display:none;"' : ''; ?>>
                <?php
                    echo $this->Form->input('orgsExternal', array(
                            'options' => $orgOptions['external'],
                            'class' => 'input mergeUpdate',
                            'label' => __('Target External Organisation'),
                            'style' => 'width:332px;',
                            'default' => $default_id,
                            'div' => 'orgsExternal'
                    ));
                ?>
            </div>
        </div>
        <div class="row-fluid">
            <div class="span6 highlightedBlock">
                <b><?php echo __('Organisation to be merged');?></b><br />
                <b><?php echo __('ID');?>: </b><span class="red"><?php echo h($currentOrg['Organisation']['id']);?></span><br />
                <b><?php echo __('Name');?>: </b><span class="red"><?php echo h($currentOrg['Organisation']['name']);?></span><br />
                <b><?php echo __('Uuid');?>: </b><span class="red"><?php echo h($currentOrg['Organisation']['uuid']);?></span><br />
                <b><?php echo __('Type');?>: </b><span class="red"><?php echo h($currentOrg['Organisation']['local']) ? 'Local' : 'External';?></span>
            </div>
            <div class="span6 highlightedBlock">
                <b><?php echo __('Organisation to be merged into');?></b><br />
                <b><?php echo __('ID');?>: </b><span id="org_id" class="green"></span><br />
                <b><?php echo __('Name');?>: </b><span id="org_name" class="green"></span><br />
                <b><?php echo __('UUID');?>: </b><span id="org_uuid" class="green"></span><br />
                <b><?php echo __('Type');?>: </b><span id="org_local" class="green"></span>
            </div>
        </div>
        <br />
        <?php echo $this->Form->submit(__('Merge'), array('div' => false, 'class' => 'btn btn-primary')); ?>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" onClick="cancelPopoverForm();" style="float:right;"><?php echo __('Cancel');?></span>
        <?php echo $this->Form->end(); ?>
    </div>
</div>
<script type="text/javascript">
var formInfoValues = {};
var orgArray = <?php echo $orgs; ?>;
var types = ['local', 'external'];

$(document).ready(function() {
    mergeOrganisationUpdate();
    $('#OrganisationTargetType').change(function() {
        mergeOrganisationTypeToggle();
    });

    $('.mergeUpdate').change(function() {
        mergeOrganisationUpdate();
    });
});

</script>
<?php echo $this->Js->writeBuffer();
