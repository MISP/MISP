<div class="servers form">
<?php
    echo $this->Form->create('Server', array('type' => 'file', 'novalidate' => true));
    echo '<fieldset>';
    echo sprintf('<legend>%s</legend>', $this->action === 'add' ? __('Add Server') : __('Edit Server'));
    echo '<h4 class="input clear">' . __('Instance identification') . '</h4>';
    echo $this->Form->input('url', array(
        'label' => __('Base URL'),
    ));
    echo $this->Form->input('name', array(
        'label' => __('Instance name'),
    ));
    echo sprintf(
        '<div id="InternalDiv" class="input clear" style="width:100%%;"><hr /><p class="red" style="width:50%%;">%s</p>%s</div>',
        __('You can set this instance up as an internal instance by checking the checkbox below. This means that any synchronisation between this instance and the remote will not be automatically degraded as it would in a normal synchronisation scenario. Please make sure that you own both instances and that you are OK with this otherwise dangerous change. This also requires that the current instance\'s host organisation and the remote sync organisation are the same.'),
        $this->Form->input('internal', array(
            'label' => __('Internal instance'),
            'type' => 'checkbox',
        ))
    );
    ?>
        <div class="input clear"></div>
        <div class="input clear" style="width:100%;">
            <hr />
            <h4><?php echo __('Instance ownership and credentials'); ?></h4>
            <p class="red"><?php echo __('Information about the organisation that will receive the events, typically the remote instance\'s host organisation.');?></p>
        </div>
        <div class="input clear"></div>
    <?php
        $org_type_form = array(
            'label' => __('Organisation Type'),
            'options' => $organisationOptions
        );
        if (!empty($oldRemoteSetting)) {
            $org_type_form['default'] = $oldRemoteSetting;
        }
        echo $this->Form->input('organisation_type', $org_type_form);
    ?>
        <div id="ServerExternalContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerExternal"><?php echo __('External Organisation');?></label>
            <select id="ServerExternal">
                <?php
                    foreach ($externalOrganisations as $k => $v) {
                        if (isset($oldRemoteOrg)) {
                            if ($k == $oldRemoteOrg) echo '<option value="' . h($k) . '" selected="selected">' . h($v) . '</option>';
                            else echo '<option value="' . h($k) . '">' . h($v) . '</option>';
                        } else {
                            echo '<option value="' . h($k) . '">' . h($v) . '</option>';
                        }
                    }
                ?>
            </select>
        </div>
        <div id="ServerLocalContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerLocal"><?php echo __('Local Organisation');?></label>
            <select id="ServerLocal">
                <?php
                    foreach ($localOrganisations as $k => $v) {
                        if (isset($oldRemoteOrg)) {
                            if ($k == $oldRemoteOrg) echo '<option value="' . h($k) . '" selected="selected">' . h($v) . '</option>';
                            else echo '<option value="' . h($k) . '">' . h($v) . '</option>';
                        } else {
                            echo '<option value="' . h($k) . '">' . h($v) . '</option>';
                        }
                    }
                ?>
            </select>
        </div>
        <div id="ServerExternalNameContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerExternalName"><?php echo __('Remote Organisation\'s Name');?></label>
            <input type="text" id="ServerExternalName" <?php if (isset($this->request->data['Server']['external_name'])) echo 'value="' . h($this->request->data['Server']['external_name']) . '"';?>>
        </div>
        <div id="ServerExternalUuidContainer" class="input select hiddenField" style="display:none;">
            <label for="ServerExternalUuid"><?php echo __('Remote Organisation\'s UUID');?></label>
            <input type="text" id="ServerExternalUuid" <?php if (isset($this->request->data['Server']['external_uuid'])) echo 'value="' . h($this->request->data['Server']['external_uuid']) . '"';?>>
        </div>
    <?php
        echo '<div class="input clear" style="width:100%;"><hr /></div>';
        echo sprintf(
            '<div id="AuthkeyContainer"><p class="red clear" style="width:50%%;">%s</p>%s</div>',
            __('Ask the owner of the remote instance for a sync account on their instance, log into their MISP using the sync user\'s credentials and retrieve your API key by navigating to Global actions -> My profile. This key is used to authenticate with the remote instance.'),
            $this->Form->input('authkey', [
                'type' => 'text',
                'placeholder' => __('Leave empty to use current key'),
                'autocomplete' => 'off',
            ])
        );
        echo '<div class="input clear" style="width:100%;"><hr></div>';
        echo '<h4 class="input clear">' . __('Enabled synchronisation methods') . '</h4>';
        echo $this->Form->input('push', array());
        echo $this->Form->input('pull', array());
        echo $this->Form->input('push_sightings', array());
        echo $this->Form->input('caching_enabled', array());
        echo $this->Form->input('push_galaxy_clusters', array());
        echo $this->Form->input('pull_galaxy_clusters', array());
        echo $this->Form->input('push_analyst_data', array());
        echo $this->Form->input('pull_analyst_data', array());
        echo '<div class="input clear" style="width:100%;"><hr><h4>' . __('Misc settings') . '</h4></div>';
        echo $this->Form->input('unpublish_event', array(
            'type' => 'checkbox',
            'label' => __('Unpublish event when pushing to remote server')
        ));
        echo '<div class="input clear"></div>';
        echo $this->Form->input('publish_without_email', array(
            'type' => 'checkbox',
        ));
        echo '<div class="input clear"></div>';
        echo $this->Form->input('self_signed', array(
            'type' => 'checkbox',
            'label' => 'Allow self signed certificates (unsecure)'
        ));
        echo '<div class="input clear"></div>';
        echo $this->Form->input('skip_proxy', array('type' => 'checkbox', 'label' => 'Skip proxy (if applicable)'));
        echo '<div class="input clear"></div>';
        echo $this->Form->input('remove_missing_tags', array(
            'type' => 'checkbox',
            'label' => __('Remove Missing Attribute Tags (not recommended)'),
        ));
    ?>
    <div class="clear">
        <p>
            <span class="bold"><?php echo __('Server certificate file (*.pem): ');?></span>
            <span id="serverEditCertValue">
                <?php
                    if (isset($server['Server']['cert_file']) && !empty($server['Server']['cert_file'])) echo h($server['Server']['cert_file']);
                    else echo '<span class="green bold">Not set.</span>';
                ?>
            </span>
            <br />
            <span id="add_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Add certificate file');?></span>
            <span id="remove_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Remove certificate file');?></span>
        </p>
        <div style="width: 0px;height: 0px;overflow: hidden;">
        <?php
            echo $this->Form->input('Server.submitted_cert', array(
                'label' => 'submitted_cert',
                'type' => 'file',
                'div' => false
            ));
        ?>
        </div>
    <div class="clear">
        <p>
            <span class="bold"><?php echo __('Client certificate file: ');?></span>
            <span id="serverEditClientCertValue">
                <?php
                    if (isset($server['Server']['client_cert_file']) && !empty($server['Server']['client_cert_file'])) echo h($server['Server']['client_cert_file']);
                    else echo '<span class="green bold">Not set.</span>';
                ?>
            </span>
            <br />
            <span id="add_client_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Add certificate file');?></span>
            <span id="remove_client_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Remove certificate file');?></span>
        </p>
        <div style="width: 0px;height: 0px;overflow: hidden;">
        <?php
            echo $this->Form->input('Server.submitted_client_cert', array(
                'label' => 'submitted_client_cert',
                'type' => 'file',
                'div' => false
            ));
        ?>
        </div>
    </div>
        <b><?php echo __('Push rules:');?></b><br />
        <span id="push_tags_OR" style="display:none;"><?php echo __('Events with the following tags allowed: ');?><span id="push_tags_OR_text" style="color:green;"></span><br /></span>
        <span id="push_tags_NOT" style="display:none;"><?php echo __('Events with the following tags blocked: ');?><span id="push_tags_NOT_text" style="color:red;"></span><br /></span>
        <span id="push_orgs_OR" style="display:none;"><?php echo __('Events with the following organisations allowed: ');?><span id="push_orgs_OR_text" style="color:green;"></span><br /></span>
        <span id="push_orgs_NOT" style="display:none;"><?php echo __('Events with the following organisations blocked: ');?><span id="push_orgs_NOT_text" style="color:red;"></span><br /></span>
        <?php if(!empty(Configure::read('MISP.enable_synchronisation_filtering_on_type'))): ?>
        <span id="push_type_attributes_NOT" style="display:none;"><?php echo __('Attributes of the following types blocked: ');?><span id="push_type_attributes_NOT_text" style="color:red;"></span><br /></span>
        <span id="push_type_objects_NOT" style="display:none;"><?php echo __('Objects of the following uuids blocked: ');?><span id="push_type_objects_NOT_text" style="color:red;"></span><br /></span>
        <?php endif; ?>
        <span id="push_modify" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Modify');?></span><br /><br />
        <b><?php echo __('Pull rules:');?></b><br />
        <span id="pull_tags_OR" style="display:none;"><?php echo __('Events with the following tags allowed: ');?><span id="pull_tags_OR_text" style="color:green;"></span><br /></span>
        <span id="pull_tags_NOT" style="display:none;"><?php echo __('Events with the following tags blocked: ');?><span id="pull_tags_NOT_text" style="color:red;"></span><br /></span>
        <span id="pull_orgs_OR" style="display:none;"><?php echo __('Events with the following organisations allowed: ');?><span id="pull_orgs_OR_text" style="color:green;"></span><br /></span>
        <span id="pull_orgs_NOT" style="display:none;"><?php echo __('Events with the following organisations blocked: ');?><span id="pull_orgs_NOT_text" style="color:red;"></span><br /></span>
        <?php if(!empty(Configure::read('MISP.enable_synchronisation_filtering_on_type'))): ?>
        <span id="pull_type_attributes_NOT" style="display:none;"><?php echo __('Attributes of the following types blocked: ');?><span id="pull_type_attributes_NOT_text" style="color:red;"></span><br /></span>
        <span id="pull_type_objects_NOT" style="display:none;"><?php echo __('Objects of the following uuids blocked: ');?><span id="pull_type_objects_NOT_text" style="color:red;"></span><br /></span>
        <?php endif; ?>
        <span id="pull_url_params" style="display:none;"><?php echo __('Additional parameters: ');?><span id="pull_url_params_text" style="color:green;"></span><br /></span>
        <span id="pull_modify" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Modify');?></span><br /><br />
    <?php
        echo $this->Form->input('push_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->checkbox('delete_cert', array('style' => 'display:none;', 'label' => false, 'div' => false));
        echo $this->Form->checkbox('delete_client_cert', array('style' => 'display:none;', 'label' => false, 'div' => false));
    ?>
    </fieldset>
    <span role="button" tabindex="0" aria-label="<?php echo __('Submit');?>" title="<?php echo __('Submit');?>" class="btn btn-primary" onClick="serverSubmitForm('<?php echo Inflector::humanize($this->action);?>');"><?php echo __('Submit');?></span>
<?php
    echo $this->Form->end();
?>
</div>
<div id="hiddenRuleForms">
    <?php
        $pushRules = $pullRules = [];
        if (!empty($server)) {
            $pushRules = json_decode($server['Server']['push_rules'], true);
            $pullRules = json_decode($server['Server']['pull_rules'], true);
            $pullRules['url_params'] = isset($pullRules['url_params']) ? json_decode($pullRules['url_params'], true) : '';
        }
        $modalData = [
            'data' => [
                'title' => __('Set PUSH rules'),
                'content' => [
                    [
                        'html' => sprintf('<h5 style="font-weight: normal;"><i>%s</i></h5>', __('Configure the rules to be applied when PUSHing data to the server'))
                    ],
                    [
                        'html' => $this->element('serverRuleElements/push', [
                            'allTags' => $allTags,
                            'allOrganisations' => $allOrganisations,
                            'ruleObject' => $pushRules
                        ])
                    ]
                ],
            ],
            'type' => 'xl',
            'class' => 'push-rule-modal',
            'confirm' => [
                'title' => __('Update'),
                'onclick' => "serverRulesUpdateState('push');"
            ]
        ];
        echo $this->element('genericElements/infoModal', $modalData);
        $modalData['data']['title'] = __('Set PULL rules');
        $modalData['data']['content'][0]['html'] = sprintf('<h5 style="font-weight: normal;"><i>%s</i></h5>', __('Configure the rules to be applied when PULLing data from the server'));
        $modalData['data']['content'][1]['html'] = $this->element('serverRuleElements/pull', [
            'context' => 'servers',
            'ruleObject' => $pullRules
        ]);
        $modalData['class'] = 'pull-rule-modal';
        $modalData['confirm']['onclick'] = "serverRulesUpdateState('pull');";
        echo $this->element('genericElements/infoModal', $modalData);
    ?>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => $this->action)); ?>
<script>
var formInfoValues = {
    'ServerUrl' : "<?php echo __('The base-url to the external server you want to sync with. Example: https://foo.sig.mil.be');?>",
    'ServerOrganization' : "<?php echo __('The organization having the external server you want to sync with. Example: BE');?>",
    'ServerName' : "<?php echo __('A name that will make it clear to your users what this instance is. For example: Organisation A\'s instance');?>",
    'ServerAuthkey' : "<?php echo __('You can find the authentication key on your profile on the external server.');?>",
    'ServerPush' : "<?php echo __('Allow the upload of events and their attributes.');?>",
    'ServerPull' : "<?php echo __('Allow the download of events and their attributes from the server.');?>",
    'ServerUnpublishEvent' : '<?php echo __('When publishing event to remote server, it will be not published on remote server.');?>',
    'ServerPublishWithoutEmail' : '<?php echo __('Publish new event without sending e-mail notification when pulling event from remote server.');?>',
    'ServerSubmittedCert' : "<?php echo __('You can also upload a certificate file if the instance you are trying to connect to has its own signing authority.');?>",
    'ServerSubmittedClientCert' : "<?php echo __('You can also upload a client certificate file if the instance you are trying to connect requires this.');?>",
    'ServerSelfSigned' : "<?php echo __('Click this, if you would like to allow a connection despite the other instance using a self-signed certificate (not recommended).');?>",
    'ServerRemoveMissingTags': "<?php echo __('Remove any global tags from attributes on local instance that are not present on an updated event being received from the server. Any missing global tags will be removed, local tags are unaffected as is pushing events (working with Pull event).');?>"
};

var rules = {
    "push": {
        "tags": {"OR":[], "NOT":[]},
        "orgs": {"OR":[], "NOT":[]},
        "type_attributes": {"NOT":[]},
        "type_objects": {"NOT":[]},
    },
    "pull": {
        "tags": {"OR":[], "NOT":[]},
        "orgs": {"OR":[], "NOT":[]},
        "type_attributes": {"NOT":[]},
        "type_objects": {"NOT":[]},
        "url_params": ""
    }
};
var validOptions = ['pull', 'push'];
var validFields = ['tags', 'orgs', 'type_attributes', 'type_objects'];
var tags = <?php echo json_encode($allTags); ?>;
var orgs = <?php echo json_encode($allOrganisations); ?>;
var type_objects = <?php echo json_encode($allObjectTypes); ?>;
var delete_cert = false;
var delete_client_cert = false;
var host_org_id = "<?php echo h($host_org_id); ?>";
var modelContext = 'Server';
$(function() {
    serverOrgTypeChange();
    $('#ServerOrganisationType').change(function() {
        serverOrgTypeChange();
    });

    $("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerUnpublishEvent, #ServerPublishWithoutEmail, #ServerSubmittedCert, #ServerSubmittedClientCert, #ServerSelfSigned, #ServerRemoveMissingTags")
        .on('mouseleave', function() {
        $(this).popover('destroy');
    }).on('mouseover', function(e) {
        $(this).popover('destroy').popover({
            trigger: 'focus',
            placement: 'right',
            content: formInfoValues[e.currentTarget.id],
        }).popover('show');
    });
    rules = convertServerFilterRules(rules);
    $("#push_modify").click(function() {
        $('#genericModal.push-rule-modal').modal()
            .on('shown', function () {
                var $containers = $(this).find('.rules-widget-container')
                $containers.each(function() {
                    var initFun = $(this).data('funname');
                    if (typeof window[initFun] === 'function') {
                        window[initFun]()
                    }
                })
            })
            .on('hidden', function () {
                var $containers = $(this).find('.rules-widget-container')
                $containers.each(function() {
                    if ($(this).data('resetrulesfun') !== undefined) {
                        $(this).data('resetrulesfun')()
                    }
                })
            });
    });
    $("#pull_modify").click(function() {
        $('#genericModal.pull-rule-modal').modal()
            .on('shown', function () {
                var $containers = $(this).find('.rules-widget-container')
                $containers.each(function() {
                    var initFun = $(this).data('funname');
                    if (typeof window[initFun] === 'function') {
                        window[initFun]()
                    }
                })
                if (typeof window['cm'] === "object") {
                    window['cm'].refresh()
                }
            })
            .on('hidden', function () {
                var $containers = $(this).find('.rules-widget-container')
                $containers.each(function() {
                    if ($(this).data('resetrulesfun') !== undefined) {
                        $(this).data('resetrulesfun')()
                    }
                })
            });
    });

    $('#add_cert_file').click(function() {
        $('#ServerSubmittedCert').trigger('click');
    });
    $('#add_client_cert_file').click(function() {
        $('#ServerSubmittedClientCert').trigger('click');
    });
    $('input[label=submitted_cert]').change(function() {
        $('#serverEditCertValue').text($('input[label=submitted_cert]').val());
        $('#ServerDeleteCert').prop('checked', false);
    });
    $('input[label=submitted_client_cert]').change(function() {
        $('#serverEditClientCertValue').text($('input[label=submitted_client_cert]').val());
        $('#ServerDeleteClientCert').prop('checked', false);
    });
    $('#remove_cert_file').click(function() {
        $('#serverEditCertValue').html('<span class="green bold"><?php echo __('Not set.');?></span>');
        $('#ServerDeleteCert').prop('checked', true);
    });
    $('#remove_client_cert_file').click(function() {
        $('#serverEditClientCertValue').html('<span class="green bold"><?php echo __('Not set.');?></span>');
        $('#ServerDeleteClientCert').prop('checked', true);
    });

    $('#ServerOrganisationType, #ServerLocal').change(function() {
        serverOwnerOrganisationChange(host_org_id);
    });
    serverOwnerOrganisationChange(host_org_id);
});
</script>
