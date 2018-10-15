<div class="servers form">
<?php echo $this->Form->create('Server', array('type' => 'file'));?>
    <fieldset>
        <legend><?php echo __('Add Server');?></legend>
    <?php
        echo $this->Form->input('url', array(
            'label' => __('Base URL'),
        ));
        echo $this->Form->input('name', array(
                'label' => __('Instance name'),
        ));
        if (!empty($host_org_id)):
    ?>
            <div id="InternalDiv" class = "input clear hidden" style="width:100%;">
            <hr />
                <p class="red" style="width:50%;"><?php echo __('You can set this instance up as an internal instance by checking the checkbox below. This means that any synchronisation between this instance and the remote will not be automatically degraded as it would in a normal synchronisation scenario. Please make sure that you own both instances and that you are OK with this otherwise dangerous change.');?></p>
    <?php
                echo $this->Form->input('internal', array(
                        'label' => __('Internal instance'),
                        'type' => 'checkbox',
                ));
    ?>
            </div>
    <?php
        endif;
    ?>
        <div class="input clear" style="width:100%;">
        <hr />
        <p class="red"><?php echo __('Information about the organisation that will receive the events, typically the remote instance\'s host organisation.');?></p>
        </div>
        <div class = "input clear"></div>
    <?php
        if ($isSiteAdmin):
        echo $this->Form->input('organisation_type', array(
                'label' => __('Remote Sync Organisation Type'),
                'options' => $organisationOptions,
        ));
    ?>
        <div id="ServerExternalContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerExternal"><?php echo __('External Organisation');?></label>
            <select id="ServerExternal">
                <?php foreach ($externalOrganisations as $k => $v) echo '<option value="' . $k . '">' . h($v) . '</option>'; ?>
            </select>
        </div>
        <div id="ServerLocalContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerLocal"><?php echo __('Local Organisation');?></label>
            <select id="ServerLocal">
                <?php foreach ($localOrganisations as $k => $v) echo '<option value="' . $k . '">' . h($v) . '</option>'; ?>
            </select>
        </div>
        <div id="ServerExternalNameContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerExternalName"><?php echo __('Remote Organisation\'s Name');?></label>
            <input type="text" id="ServerExternalName" <?php if (isset($this->request->data['Server']['external_name'])) echo 'value="' . $this->request->data['Server']['external_name'] . '"';?>>
        </div>
        <div id="ServerExternalUuidContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerExternalUuid"><?php echo __('Remote Organisation\'s Uuid');?></label>
            <input type="text" id="ServerExternalUuid" <?php if (isset($this->request->data['Server']['external_uuid'])) echo 'value="' . $this->request->data['Server']['external_uuid'] . '"';?>>
        </div>
        <div class = "input clear"></div>
    <?php
        endif;
        echo $this->Form->input('authkey', array(
        ));
    ?>
        <div class = "input clear" style="width:100%;"><hr /></div>
        <div class = "input clear"></div>
    <?php
        echo $this->Form->input('push', array(
        ));

        echo $this->Form->input('pull', array(
        ));
    ?>
        <div class = "input clear"></div>
    <?php
        echo $this->Form->input('unpublish_event', array(
            'type' => 'checkbox',
        ));
    ?>
        <div class = "input clear"></div>
    <?php
        echo $this->Form->input('publish_without_email', array(
            'type' => 'checkbox',
        ));
    ?>
        <div class = "input clear"></div>
    <?php
        echo $this->Form->input('self_signed', array(
            'type' => 'checkbox',
        ));
        ?>
            <div class = "input clear"></div>
        <?php
        echo $this->Form->input('skip_proxy', array('type' => 'checkbox', 'label' => 'Skip proxy (if applicable)'));

        echo $this->Form->input('Server.submitted_cert', array(
            'label' => '<b>' . __('Server certificate file') . '</b>',
            'type' => 'file',
            'div' => 'clear'
        ));

        echo $this->Form->input('Server.submitted_client_cert', array(
            'label' => '<b>' . __('Client certificate file') . '</b>',
            'type' => 'file',
            'div' => 'clear'
        ));
    ?>
        <br /><b><?php echo __('Push rules:');?></b><br />
        <span id="push_tags_OR" style="display:none;"><?php echo __('Events with the following tags allowed: ');?><span id="push_tags_OR_text" style="color:green;"></span><br /></span>
        <span id="push_tags_NOT" style="display:none;"><?php echo __('Events with the following tags blocked: ');?><span id="push_tags_NOT_text" style="color:red;"></span><br /></span>
        <span id="push_orgs_OR" style="display:none;"><?php echo __('Events with the following organisations allowed: ');?><span id="push_orgs_OR_text" style="color:green;"></span><br /></span>
        <span id="push_orgs_NOT" style="display:none;"><?php echo __('Events with the following organisations blocked: ');?><span id="push_orgs_NOT_text" style="color:red;"></span><br /></span>
        <span id="push_modify" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Modify');?></span><br /><br />
        <b><?php echo __('Pull rules:');?></b><br />
        <span id="pull_tags_OR" style="display:none;"><?php echo __('Events with the following tags allowed: ');?><span id="pull_tags_OR_text" style="color:green;"></span><br /></span>
        <span id="pull_tags_NOT" style="display:none;"><?php echo __('Events with the following tags blocked: ');?><span id="pull_tags_NOT_text" style="color:red;"></span><br /></span>
        <span id="pull_orgs_OR" style="display:none;"><?php echo __('Events with the following organisations allowed: ');?><span id="pull_orgs_OR_text" style="color:green;"></span><br /></span>
        <span id="pull_orgs_NOT" style="display:none;"><?php echo __('Events with the following organisations blocked: ');?><span id="pull_orgs_NOT_text" style="color:red;"></span><br /></span>
        <span id="pull_modify"  class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Modify</span><br /><br />
    <?php
        echo $this->Form->input('push_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
    ?>
    </fieldset>
    <span role="button" tabindex="0" aria-label="<?php echo __('Submit');?>" title="<?php echo __('Submit');?>" class="btn btn-primary" onClick="serverSubmitForm('Add');"><?php echo __('Submit');?></span>
<?php
echo $this->Form->end();
?>
</div>
<div id="hiddenRuleForms">
    <?php echo $this->element('serverRuleElements/push'); ?>
    <?php echo $this->element('serverRuleElements/pull'); ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'add'));
?>

<script type="text/javascript">
//
var formInfoValues = {
        'ServerUrl' : "<?php echo __('The base-url to the external server you want to sync with. Example: https://foo.sig.mil.be');?>",
        'ServerName' : "<?php echo __('A name that will make it clear to your users what this instance is. For example: Organisation A\'s instance');?>",
        'ServerOrganization' : "<?php echo __('The organization having the external server you want to sync with. Example: BE');?>",
        'ServerAuthkey' : "<?php echo __('You can find the authentication key on your profile on the external server.');?>",
        'ServerPush' : "<?php echo __('Allow the upload of events and their attributes.');?>",
        'ServerPull' : "<?php echo __('Allow the download of events and their attributes from the server.');?>",
        'ServerUnpublishEvent' : '<?php echo __('Unpublish new event (working with Pull event).');?>',
        'ServerPublishWithoutEmail' : '<?php echo __('Publish new event without email (working with Push event).');?>',
        'ServerSubmittedCert' : "<?php echo __('You can also upload a certificate file if the instance you are trying to connect to has its own signing authority.  (*.pem)');?>",
        'ServerSelfSigned' : "<?php echo __('Click this, if you would like to allow a connection despite the other instance using a self-signed certificate (not recommended).');?>"
};


var rules = {"push": {"tags": {"OR":[], "NOT":[]}, "orgs": {"OR":[], "NOT":[]}}, "pull": {"tags": {"OR":[], "NOT":[]}, "orgs": {"OR":[], "NOT":[]}}};
var validOptions = ['pull', 'push'];
var validFields = ['tags', 'orgs'];
var tags = <?php echo json_encode($allTags); ?>;
var orgs = <?php echo json_encode($allOrganisations); ?>;
var host_org_id = "<?php echo h($host_org_id); ?>";
var modelContext = 'Server';

$(document).ready(function() {
    serverOrgTypeChange();
    $('#ServerOrganisationType').change(function() {
        serverOrgTypeChange();
    });
    <?php
        if (!empty($host_org_id)):
    ?>
            serverOwnerOrganisationChange(host_org_id);
            $('#ServerOrganisationType, #ServerLocal').change(function() {
                serverOwnerOrganisationChange(host_org_id);
            });
    <?php
        endif;
    ?>

    $("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerUnpublishEvent, #ServerPublishWithoutEmail, #ServerSubmittedCert, #ServerSelfSigned").on('mouseleave', function(e) {
        $('#'+e.currentTarget.id).popover('destroy');
    });

    $("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerUnpublishEvent, #ServerPublishWithoutEmail, #ServerSubmittedCert, #ServerSelfSigned").on('mouseover', function(e) {
        var $e = $(e.target);
            $('#'+e.currentTarget.id).popover('destroy');
            $('#'+e.currentTarget.id).popover({
                trigger: 'focus',
                placement: 'right',
                content: formInfoValues[e.currentTarget.id],
            }).popover('show');
    });

    serverRulePopulateTagPicklist();
    $("#push_modify").click(function() {
        serverRuleFormActivate('push');
    });
    $("#pull_modify").click(function() {
        serverRuleFormActivate('pull');
    });
});
</script>
