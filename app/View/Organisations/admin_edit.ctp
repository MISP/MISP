<div class="users form">
<?php echo $this->Form->create('Organisation', array('enctype' => 'multipart/form-data'));?>
    <fieldset>
        <legend><?php echo __('Edit Organisation'); ?></legend>
        <p style="font-weight:bold;"><?php echo __('If the organisation should have access to this instance, make sure that the Local organisation setting is checked. <br />If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting.');?></p>
        <div style="float:left;width:345px;">
            <?php echo $this->Form->input('local', array('label' => 'Local organisation'));?>
        </div>
        <div class="clear"></div>
        <hr />
        <p style="font-weight:bold;"><?php echo __('Mandatory fields. Leave the UUID field empty if the organisation doesn\'t have a UUID from another instance.');?></p>
        <div style="float:left;width:345px;">
        <?php
            echo $this->Form->input('name', array('div' => 'clear', 'style' => 'width:320px;','label' => __('Organisation Identifier'), 'placeholder' => __('Brief organisation identifier')));
        ?>
        </div>
        <div id="logoDiv" style="margin-top:40px;"><?php echo __('No image uploaded for this identifier');?></div>
        <div class="clear"></div>
        <div style="float:left;width:425px;">
        <?php
            echo $this->Form->input('uuid', array('div' => 'clear', 'label' => __('UUID'), 'placeholder' => __('Paste UUID or click generate'), 'style' => 'width:405px;'));
        ?>
        </div>
        <span role="button" tabindex="0" aria-label="<?php echo __('Generate a new UUID for the organisation');?>" title="<?php echo __('Generate UUID');?>" class="btn btn-inverse" style="margin-top:25px;" onClick="generateOrgUUID();"><?php echo __('Generate UUID');?></span>
        <?php
            if (!empty($duplicate_org)):
        ?>
            <div class="clear"></div>
            <span class="bold red">
                <?php echo __('An organisation with the above uuid already exists. Would you like to merge this organisation into the existing one?');?>
            </span>
            <a href="#" onClick="getPopup('<?php echo h($id) . '/' . h($duplicate_org); ?>', 'organisations', 'merge', 'admin');"><?php echo __('Click here'); ?></a>
            <div class="clear"></div>
    <?php
        endif;
    ?>
    <?php
        echo $this->Form->input('description', array('label' => __('A brief description of the organisation'), 'div' => 'clear', 'class' => 'input-xxlarge', 'type' => 'textarea', 'placeholder' => __('A description of the organisation that is purely informational.')));
    ?>
    <?php
        echo $this->Form->input('restricted_to_domain', array('label' => __('Bind user accounts to domains (line separated)'), 'div' => 'clear', 'class' => 'input-xxlarge', 'type' => 'textarea', 'placeholder' => __('Enter a (list of) domain name(s) to enforce when creating users.')));
    ?>
        <hr />
        <p style="font-weight:bold;"><?php echo __('The following fields are all optional.');?></p>
    <?php
        echo $this->Form->input('logo', array(
            'error' => array('escape' => false),
            'type' => 'file',
            'label' => __('Logo (48x48 png)')
        ));
    ?>
        <div class="clear"></div>
    <?php
        echo $this->Form->input('nationality', array('options' => $countries));
        echo $this->Form->input('sector', array('placeholder' => __('For example "financial".'), 'style' => 'width:300px;'));
        echo $this->Form->input('type', array('class' => 'input-xxlarge', 'label' => __('Type of organisation'), 'div' => 'clear', 'placeholder' => __('Freetext description of the org.')));
        echo $this->Form->input('contacts', array('class' => 'input-xxlarge', 'type' => 'textarea', 'div' => 'clear', 'placeholder' => __('You can add some contact details for the organisation here, if applicable.')));
    ?>
    </fieldset>
<?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
    echo $this->Form->end();?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'editOrg', 'orgId' => $orgId));
?>
<script type="text/javascript">
    $(document).ready(function() {
        updateOrgCreateImageField($("#OrganisationName").val());
    });

    $("#OrganisationName").on('input propertychange paste focusout ready', function() {
        updateOrgCreateImageField($("#OrganisationName").val());
    });
</script>
