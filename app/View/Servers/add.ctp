<div class="servers form">
<?php echo $this->Form->create('Server', array('type' => 'file'));?>
	<fieldset>
		<legend>Add Server</legend>
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
		));
	?>
		<div id="ServerExternalContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerExternal">External Organisation</label>
			<select id="ServerExternal">
				<?php foreach ($externalOrganisations as $k => $v) echo '<option value="' . $k . '">' . h($v) . '</option>'; ?>
			</select>
		</div>
		<div id="ServerLocalContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerLocal">Local Organisation</label>
			<select id="ServerLocal">
				<?php foreach ($localOrganisations as $k => $v) echo '<option value="' . $k . '">' . h($v) . '</option>'; ?>
			</select>
		</div>
		<div id="ServerExternalNameContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerExternalName">Remote Organisation's Name</label>
			<input type="text" id="ServerExternalName">
		</div>
		<div id="ServerExternalUuidContainer" class="input select hiddenField" style="display:none;">
			<label for="ServerExternalUuid">Remote Organisation's Uuid</label>
			<input type="text" id="ServerExternalUuid">
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

		echo $this->Form->input('Server.submitted_cert', array(
			'label' => '<b>Certificate file</b>',
			'type' => 'file',
			'div' => 'clear'
		));
		echo $this->Form->input('push_rules', array('type' => 'textarea', 'label' => 'Push filters (in JSON format)', 'div' => 'clear', 'class' => 'input-xxlarge'));
		echo $this->Form->input('pull_rules', array('type' => 'textarea', 'label' => 'Pull filters (in JSON format)', 'div' => 'clear', 'class' => 'input-xxlarge'));
		echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
	?>
	</fieldset>
	<span class="btn btn-primary" onClick="serverSubmitForm('Add');">Submit</span>
<?php
echo $this->Form->end();
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'add'));
?>

<script type="text/javascript">
//
var formInfoValues = {
		'ServerUrl' : "The base-url to the external server you want to sync with. Example: https://foo.sig.mil.be",
		'ServerName' : "A name that will make it clear to your users what this instance is. For example: Organisation A's instance",
		'ServerOrganization' : "The organization having the external server you want to sync with. Example: BE",
		'ServerAuthkey' : "You can find the authentication key on your profile on the external server.",
		'ServerPush' : "Allow the upload of events and their attributes.",
		'ServerPull' : "Allow the download of events and their attributes from the server.",
		'ServerSubmittedCert' : "You can also upload a certificate file if the instance you are trying to connect to has its own signing authority.",
		'ServerSelfSigned' : "Click this, if you would like to allow a connection despite the other instance using a self-signed certificate (not recommended)."
};

$(document).ready(function() {
	serverOrgTypeChange();
	$('#ServerOrganisationType').change(function() {
		serverOrgTypeChange();
	});

	$("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerSubmittedCert, #ServerSelfSigned").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#ServerUrl, #ServerOrganization, #ServerName, #ServerAuthkey, #ServerPush, #ServerPull, #ServerSubmittedCert, #ServerSelfSigned").on('mouseover', function(e) {
	    var $e = $(e.target);
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'focus',
	            placement: 'right',
	            content: formInfoValues[e.currentTarget.id],
	        }).popover('show');
	});
});
</script>
