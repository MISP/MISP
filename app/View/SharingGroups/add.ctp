<div class="users form">
    <fieldset>
        <legend><?php echo __('New Sharing Group'); ?></legend>
        <div class="tabMenuFixedContainer">
            <span id="page1_tab" role="button" tabindex="0" aria-label="<?php echo __('General tab');?>" title="<?php echo __('General tab');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer tabMenuActive" onClick="simpleTabPage(1);"><?php echo __('General');?></span>
            <span id="page2_tab" role="button" tabindex="0" aria-label="<?php echo __('Organisations tab');?>" title="<?php echo __('Organisations tab');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="simpleTabPage(2);"><?php echo __('Organisations');?></span>
            <span id="page3_tab" role="button" tabindex="0" aria-label="<?php echo __('MISP instances tab');?>" title="<?php echo __('MISP instances tab');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="simpleTabPage(3);"><?php echo __('MISP Instances');?></span>
            <span id="page4_tab" role="button" tabindex="0" aria-label="<?php echo __('Sharing group summary');?>" title="<?php echo __('Sharing group summary');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="simpleTabPage(4);"><?php echo __('Summary and Save');?></span>
        </div>
        <div id="page1_content" class="multi-page-form-div tabContent" style="width:544px;">
            <label for="SharingGroupName"><?php echo __('Name');?></label>
            <input type="text" class="input-xxlarge" placeholder="<?php echo __('Example: Multinational sharing group');?>" id="SharingGroupName"></input>
            <label for="SharingGroupReleasability"><?php echo __('Releasable to');?></label>
            <input type="text" class="input-xxlarge" placeholder="<?php echo __('Example: Community1, Organisation1, Organisation2');?>" id="SharingGroupReleasability"></input>
            <label for="SharingGroupDescription"><?php echo __('Description');?></label>
            <textarea class="input-xxlarge" placeholder="<?php echo __('A description of the sharing group.');?>" cols="30" rows="6" id="SharingGroupDescription"></textarea>
            <div style="display:block;">
                <input type="checkbox" style="float:left;" title="<?php echo __('Active sharing groups can be selected by users of the local instance when creating events. Generally, sharing groups received through synchronisation will have this disabled until manually enabled.');?>" value="1" id="SharingGroupActive" checked></input>
                <label for="SharingGroupActive" style="padding-left:20px;"><?php echo __('Make the sharing group selectable (active)');?></label>
            </div>
            <span role="button" tabindex="0" aria-label="<?php echo __('Next page');?>" title="<?php echo __('Next page');?>" class="btn btn-inverse" onClick="simpleTabPage(2);"><?php echo __('Next page');?></span>
        </div>
        <div id="page2_content" class="multi-page-form-div tabContent" style="display:none;width:544px;">
            <div class="tabMenuFixedContainer">
                <span role="button" tabindex="0" aria-label="<?php echo __('Add local organisation(s) to the sharing group');?>" title="<?php echo __('Add local organisation(s) to the sharing group');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="sharingGroupAdd('organisation', 'local');"><?php echo __('Add local organisation');?></span>
                <span role="button" tabindex="0" aria-label="<?php echo __('Add remote organisations to the sharing group');?>" title="<?php echo __('Add remote organisations to the sharing group');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="sharingGroupAdd('organisation', 'remote');"><?php echo __('Add remote organisation');?></span>
            </div>
            <table id="organisations_table" class="table table-striped table-hover table-condensed">
                <tr id="organisations_table_header">
                    <th><?php echo __('Type');?></th>
                    <th><?php echo __('Name');?></th>
                    <th><?php echo __('UUID');?></th>
                    <th><?php echo __('Extend');?></th>
                    <th><?php echo __('Actions');?></th>
                </tr>
            </table>
                <span role="button" tabindex="0" aria-label="<?php echo __('Previous page');?>" title="<?php echo __('Previous page');?>" class="btn btn-inverse" onClick="simpleTabPage(1);"><?php echo __('Previous page');?></span>
                <span role="button" tabindex="0" aria-label="<?php echo __('Next page');?>" title="<?php echo __('Next page');?>" class="btn btn-inverse" onClick="simpleTabPage(3);"><?php echo __('Next page');?></span>
        </div>
        <div id="page3_content" class="multi-page-form-div tabContent" style="display:none;width:544px;">
            <div style="display:block;">
                <input type="checkbox" style="float:left;" title="<?php echo __('Enable roaming mode for this sharing group. Roaming mode will allow the sharing group to be passed to any instance where the remote recipient is contained in the organisation list. It is preferred to list the recipient instances instead.');?>" value="1" id="SharingGroupRoaming"></input>
                <label for="SharingGroupRoaming" style="padding-left:20px;"><?php echo __('<b>Enable roaming mode</b> for this sharing group (pass the event to any connected instance where the sync connection is tied to an organisation contained in the SG organisation list).');?></label>
            </div>
            <div id="serverList">
                <div class="tabMenuFixedContainer">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Add instance');?>" title="<?php echo __('Add instance');?>" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="sharingGroupAdd('server');"><?php echo __('Add instance');?></span>
                </div>
                <table id="servers_table" class="table table-striped table-hover table-condensed">
                    <tr>
                        <th><?php echo __('Name');?></th>
                        <th><?php echo __('URL');?></th>
                        <th><?php echo __('All orgs');?></th>
                        <th><?php echo __('Actions');?></th>
                    </tr>
                </table>
            </div>
                <span role="button" tabindex="0" aria-label="<?php echo __('Previous page');?>" title="<?php echo __('Previous page');?>" class="btn btn-inverse" onClick="simpleTabPage(2);"><?php echo __('Previous page');?></span>
                <span role="button" tabindex="0" aria-label="<?php echo __('Next page');?>" title="<?php echo __('Next page');?>" class="btn btn-inverse" onClick="simpleTabPage(4);"><?php echo __('Next page');?></span>
        </div>
    </fieldset>
    <div id="page4_content" class="multi-page-form-div tabContent" style="display:none;width:544px;">
        <p><?php echo __('<span class="bold">General: </span>You are about to create the <span id="summarytitle" class="red bold"></span> sharing group, which is intended to be releasable to <span id="summaryreleasable" class="red bold"></span>.');?> </p>
        <p id="localText"><span class="bold"><?php echo __('Local organisations: </span>It will be visible to <span id="summarylocal" class="red bold"></span>, from which <span id="summarylocalextend" class="red bold"></span> can extend the sharing group.');?> </p>
        <p id="externalText"><span class="bold"><?php echo __('External organisations: </span>It will also be visible to <span id="summaryexternal" class="red bold"></span>, out of which <span id="summaryexternalextend" class="red bold"></span> can extend the sharing group.');?></p>
        <p id="synchronisationText"><?php echo __('<span class="bold">Synchronisation: </span>Furthermore, events are automatically pushed to: <span id="summaryservers" class="red bold"></span>');?></p>
        <p><?php echo __('You can edit this information by going back to one of the previous pages, or if you agree with the above mentioned information, click Submit to create the Sharing group.');?></p>
        <?php
            echo $this->Form->create('SharingGroup');
            echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
            //echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
            echo $this->Form->end();
        ?>
        <span role="button" tabindex="0" aria-label="<?php echo __('Previous page');?>" title="<?php echo __('Previous page');?>" class="btn btn-inverse" onClick="simpleTabPage(3);"><?php echo __('Previous page');?></span>
        <span role="button" tabindex="0" aria-label="<?php echo __('Submit and create sharing group');?>" title="<?php echo __('Submit and create sharing group');?>" class="btn btn-primary" onClick="sgSubmitForm('Add');"><?php echo __('Submit');?></span>
    </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'addSG'));
?>
<script type="text/javascript">
    var lastPage = 4;
    var roaming = false;
    var organisations = [{
        id: '<?php echo h($user['Organisation']['id'])?>',
        type: 'local',
        name: '<?php echo h($user['Organisation']['name'])?>',
        extend: true,
        uuid: '',
        removable: 0
    }];
    var orgids = ['<?php echo h($user['Organisation']['id'])?>'];
    var servers = [{
        id: '0',
        name: '<?php echo __('Local instance');?>',
        url: '<?php echo h($localInstance); ?>',
        all_orgs: false,
        removable: 0
    }];
    var serverids = [0];
    $(function() {
        if ($('#SharingGroupJson').val()) sharingGroupPopulateFromJson();
        sharingGroupPopulateOrganisations();
        sharingGroupPopulateServers();
    });
    $('#SharingGroupRoaming').change(function() {
        if ($(this).is(":checked")) {
            $('#serverList').hide();
        } else {
            $('#serverList').show();
        }
    });

</script>
