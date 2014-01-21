<div class="servers form">
<?php echo $this->Form->create('Server', array('type' => 'file', 'novalidate'=>true));?>
	<fieldset>
		<legend>Add Server</legend>
	<?php
		echo $this->Form->input('url', array(
				'label' => 'Base URL',
			));
		
		echo $this->Form->input('organization', array(
				'label' => 'Organization',
			));

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
	?>
	</fieldset>
<?php
echo $this->Form->button('Edit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
$id = $this->Form->value('Server.id');
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'edit'));
?>


<script type="text/javascript">
//
var formInfoValues = {
		'ServerUrl' : "The base-url to the external server you want to sync with. Example: https://foo.sig.mil.be",
		'ServerOrganization' : "The organization having the external server you want to sync with. Example: BE",
		'ServerAuthkey' : "You can find the authentication key on your profile on the external server.",
		'ServerPush' : "Allow the upload of events and their attributes.",
		'ServerPull' : "Allow the download of events and their attributes from the server.",
};

$(document).ready(function() {

	$("#ServerUrl, #ServerOrganization, #ServerAuthkey, #ServerPush, #ServerPull").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#ServerUrl, #ServerOrganization, #ServerAuthkey, #ServerPush, #ServerPull").on('mouseover', function(e) {
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
