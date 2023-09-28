<div class="events form">
<?php
    echo $this->Form->create('Event', array('type' => 'file'));
?>
<fieldset>
<legend><?= __('Import STIX %s file', $stix_version); ?></legend>
<?php
    echo $this->Form->input('Event.stix', array(
        'label' => '<b>' . __('%s file', $stix_version) . '</b>',
        'type' => 'file',
    ));
?>
<div class="input clear"></div>
<?php
    $distributionFormInfo = $this->element(
        'genericElements/Form/formInfo',
        [
            'field' => [
                'field' => 'distribution'
            ],
            'modelForForm' => 'Event',
            'fieldDesc' => $fieldDesc['distribution'],
        ]
    );
    echo $this->Form->input('distribution', array(
        'options' => $distributionLevels,
        'label' => __('Distribution ') . $distributionFormInfo,
        'selected' => $initialDistribution,
    ));
?>
<div id="SGContainer" style="display:none;">
<?php
    if (!empty($sharingGroups)) {
        echo $this->Form->input('sharing_group_id', array(
            'options' => array($sharingGroups),
            'label' => __('Sharing Group'),
        ));
    }
?>
</div>
<div class="input clear"></div>
<?php
    echo $this->Form->input('publish', array(
        'checked' => false,
        'label' => __('Publish imported events'),
    ));
?>
<div class="input clear"></div>
<?php
    echo $this->Form->input('original_file', array(
        'checked' => true,
        'label' => __('Include the original imported file as attachment')
    ));
    if ($me['Role']['perm_site_admin'] || $me['Role']['perm_galaxy_editor']) {
        $galaxiesFormInfo = $this-> element(
            'genericElements/Form/formInfo',
            [
                'field' => [
                    'field' => 'galaxies_handling'
                ],
                'modelForForm' => 'Event',
                'fieldDesc' => $fieldDesc['galaxies_handling']
            ]
        );
        echo '<div class="input clear"></div>';
        echo $this->Form->input('galaxies_handling', array(
            'options' => array($galaxiesOptions),
            'label' => __('How to handle Galaxies and Clusters') . $galaxiesFormInfo,
            'selected' => 0
        ));
    }
    if ($me['Role']['perm_site_admin'] && Configure::read('debug') > 0) {
        $debugFormInfo = $this->element(
            'genericElements/Form/formInfo',
            [
                'field' => [
                    'field' => 'debug'
                ],
                'modelForForm' => 'Event',
                'fieldDesc' => $fieldDesc['debug'],
            ]
        );
        echo '<div class="input clear"></div>';
        echo $this->Form->input('debug', array(
            'options' => array($debugOptions),
            'label' => __('Debugging option') . $debugFormInfo,
            'selected' => 0
        ));
    }
?>
</fieldset>
<?php
    echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'import_from'));
?>

<script>
$(function(){
    $('#EventDistribution').change(function() {
        if ($(this).val() == 4) {
            $('#SGContainer').show();
        } else {
            $('#SGContainer').hide();
        }
    }).change();
});
</script>