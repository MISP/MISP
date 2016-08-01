<div class="servers form">
<?php echo $this->Form->create('Server', array('type' => 'file', 'novalidate'=>true)); ?>
	<fieldset>
		<legend>Edit Server</legend>
	<?php
		echo $this->Form->input('url', array(
			'label' => 'Base URL',
		));
		echo $this->Form->input('name', array(
				'label' => 'Instance name',
		));
	?>
		<div class="input clear"></div>

	<?php
		echo $this->Form->input('organisation_type', array(
				'label' => 'Organisation Type',
				'options' => $organisationOptions,
				'default' => $oldRemoteSetting
		));
	?>
		<div id="ServerExternalContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerExternal">External Organisation</label>
			<select id="ServerExternal">
				<?php
					foreach ($externalOrganisations as $k => $v) {
						if ($k == $oldRemoteOrg) echo '<option value="' . $k . '" selected="selected">' . h($v) . '</option>';
						else echo '<option value="' . $k . '">' . h($v) . '</option>';
					}
				?>
			</select>
		</div>
		<div id="ServerLocalContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerLocal">Local Organisation</label>
			<select id="ServerLocal">
				<?php
					foreach ($localOrganisations as $k => $v) {
						if ($k == $oldRemoteOrg) echo '<option value="' . $k . '" selected="selected">' . h($v) . '</option>';
						else echo '<option value="' . $k . '">' . h($v) . '</option>';
					}
				?>
			</select>
		</div>
		<div id="ServerExternalNameContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerExternalName">Remote Organisation's Name</label>
			<input type="text" id="ServerExternalName" <?php if (isset($this->request->data['Server']['external_name'])) echo 'value="' . $this->request->data['Server']['external_name'] . '"';?>>
		</div>
		<div id="ServerExternalUuidContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerExternalUuid">Remote Organisation's Uuid</label>
			<input type="text" id="ServerExternalUuid" <?php if (isset($this->request->data['Server']['external_uuid'])) echo 'value="' . $this->request->data['Server']['external_uuid'] . '"';?>>
		</div>
		<div class = "input clear"></div>
	<?php
		echo $this->Form->input('authkey', array(
		));
	?>
		<div class = "input clear"></div>
	<?php
		echo $this->Form->input('push', array(
		));

		echo $this->Form->input('pull', array(
		));
	?>
		<div class = "input clear"></div>
	<?php
		echo $this->Form->input('self_signed', array(
			'type' => 'checkbox',
		));
	?>
	<div class="clear">
		<p>
			<span class="bold">Server ceritificate file: </span>
			<span id="serverEditCertValue">
				<?php
					if (isset($server['Server']['cert_file']) && !empty($server['Server']['cert_file'])) echo h($server['Server']['cert_file']);
					else echo '<span class="green bold">Not set.</span>';
				?>
			</span>
			<br />
			<span id="add_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Add certificate file</span>
			<span id="remove_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Remove certificate file</span>
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
			<span class="bold">Client ceritificate file: </span>
			<span id="serverEditClientCertValue">
				<?php
					if (isset($server['Server']['client_cert_file']) && !empty($server['Server']['client_cert_file'])) echo h($server['Server']['client_cert_file']);
					else echo '<span class="green bold">Not set.</span>';
				?>
			</span>
			<br />
			<span id="add_client_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Add certificate file</span>
			<span id="remove_client_cert_file" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Remove certificate file</span>
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
	    <b>Push rules:</b><br />
	    <span id="push_tags_OR" style="display:none;">Events with the following tags allowed: <span id="push_tags_OR_text" style="color:green;"></span><br /></span>
	    <span id="push_tags_NOT" style="display:none;">Events with the following tags blocked: <span id="push_tags_NOT_text" style="color:red;"></span><br /></span>
	    <span id="push_orgs_OR" style="display:none;">Events with the following organisations allowed: <span id="push_orgs_OR_text" style="color:green;"></span><br /></span>
	    <span id="push_orgs_NOT" style="display:none;">Events with the following organisations blocked: <span id="push_orgs_NOT_text" style="color:red;"></span><br /></span>
		<span id="push_modify" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Modify</span><br /><br />
	    <b>Pull rules:</b><br />
	    <span id="pull_tags_OR" style="display:none;">Events with the following tags allowed: <span id="pull_tags_OR_text" style="color:green;"></span><br /></span>
	    <span id="pull_tags_NOT" style="display:none;">Events with the following tags blocked: <span id="pull_tags_NOT_text" style="color:red;"></span><br /></span>
	    <span id="pull_orgs_OR" style="display:none;">Events with the following organisations allowed: <span id="pull_orgs_OR_text" style="color:green;"></span><br /></span>
	    <span id="pull_orgs_NOT" style="display:none;">Events with the following organisations blocked: <span id="pull_orgs_NOT_text" style="color:red;"></span><br /></span>
		<span id="pull_modify" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Modify</span><br /><br />
	<?php
		echo $this->Form->input('push_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
		echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
		echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
		echo $this->Form->checkbox('delete_cert', array('style' => 'display:none;', 'label' => false, 'div' => false));
	?>
	</fieldset>
	<span class="btn btn-primary" onClick="serverSubmitForm('Edit');">Submit</span>
<?php
	echo $this->Form->end();
?>
</div>
<div id="hiddenRuleForms">
	<?php echo $this->element('serverRuleElements/push'); ?>
	<?php echo $this->element('serverRuleElements/pull'); ?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'edit'));
?>


<script type="text/javascript">
//
var formInfoValues = {
		'ServerUrl' : "The base-url to the external server you want to sync with. Example: https://foo.sig.mil.be",
		'ServerOrganization' : "The organization having the external server you want to sync with. Example: BE",
		'ServerName' : "A name that will make it clear to your users what this instance is. For example: Organisation A's instance",
		'ServerAuthkey' : "You can find the authentication key on your profile on the external server.",
		'ServerPush' : "Allow the upload of events and their attributes.",
		'ServerPull' : "Allow the download of events and their attributes from the server.",
		'ServerSubmittedCert' : "You can also upload a certificate file if the instance you are trying to connect to has its own signing authority.",
		'ServerSubmittedClientCert' : "You can also upload a client certificate file if the instance you are trying to connect requires this.",
		'ServerSelfSigned' : "Click this, if you would like to allow a connection despite the other instance using a self-signed certificate (not recommended)."
};

var rules = {"push": {"tags": {"OR":[], "NOT":[]}, "orgs": {"OR":[], "NOT":[]}}, "pull": {"tags": {"OR":[], "NOT":[]}, "orgs": {"OR":[], "NOT":[]}}};
var validOptions = ['pull', 'push'];
var validFields = ['tags', 'orgs'];
var tags = <?php echo json_encode($allTags); ?>;
var orgs = <?php echo json_encode($allOrganisations); ?>;
var delete_cert = false;
var modelContext = 'Server';

$(document).ready(function() {
	serverOrgTypeChange();
	$('#ServerOrganisationType').change(function() {
		serverOrgTypeChange();
	});

	$("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerSubmittedCert, #ServerSubmittedClientCert, #ServerSelfSigned").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerSubmittedCert, #ServerSubmittedClientCert, #ServerSelfSigned").on('mouseover', function(e) {
	    var $e = $(e.target);
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'focus',
	            placement: 'right',
	            content: formInfoValues[e.currentTarget.id],
	        }).popover('show');
	});
	rules = convertServerFilterRules(rules);
	serverRulePopulateTagPicklist();
	$("#push_modify").click(function() {
		serverRuleFormActivate('push');
	});
	$("#pull_modify").click(function() {
		serverRuleFormActivate('pull');
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
		$('#serverEditCertValue').html('<span class="green bold">Not set.</span>');
		$('#ServerDeleteCert').prop('checked', true);
	});
	$('#remove_client_cert_file').click(function() {
		$('#serverEditClientCertValue').html('<span class="green bold">Not set.</span>');
		$('#ServerDeleteClientCert').prop('checked', true);
	});
});
</script>
