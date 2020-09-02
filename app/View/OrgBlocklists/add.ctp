<div class="orgBlocklist form">
<?php echo $this->Form->create('OrgBlocklist');?>
    <fieldset>
        <legend><?php echo __('Add Organisation Blocklist Entries');?></legend>
        <p><?php echo __('Simply paste a list of all the organisation UUIDs that you wish to block from being entered.');?></p>
    <?php
        echo $this->Form->input('uuids', array(
                'type' => 'textarea',
                'label' => __('UUIDs'),
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'placeholder' => __('Enter a single or a list of UUIDs')
        ));
        echo $this->Form->input('org_name', array(
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'label' => __('Organisation name'),
                'placeholder' => __('(Optional) The organisation name that the organisation is associated with')
        ));
        echo $this->Form->input('comment', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'placeholder' => __('(Optional) Any comments you would like to add regarding this (or these) entries.')
        ));
    ?>
    </fieldset>
<?php
echo $this->Form->button(__('Add'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'orgBlocklistsAdd'));
?>
