
<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Add Attribute'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category', array(
		        'between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeCategoryDiv')),
		        ));
		echo $this->Form->input('type', array(
		        'between' => $this->Html->div('forminfo', '', array('id'=> 'AttributeTypeDiv')),
		        ));
		if ('true' == Configure::read('CyDefSIG.sync')) {
		    echo $this->Form->input('private', array(
		            'before' => $this->Html->div('forminfo', 'Prevent upload of this <em>single Attribute</em> to other CyDefSIG servers.<br/>Only use when the Event is NOT set as Private.'),
		    ));
		}
		echo $this->Form->input('to_ids', array(
		    		'checked' => true,
		    		'before' => $this->Html->div('forminfo', 'Can we make an IDS signature based on this attribute ?'),
		        	'label' => 'IDS Signature?'
		));
		echo $this->Form->input('value', array(
		            'type' => 'textarea',
					'error' => array('escape' => false),
		));
		echo $this->Form->input('batch_import', array(
				    'type' => 'checkbox',
					'after' => ' <i>When selected each line in the value field will be an attribute.</i>',
		));

		// link an onchange event to the form elements
		$this->Js->get('#AttributeType')->event('change', 'showFormInfo("#AttributeType")');
		$this->Js->get('#AttributeCategory')->event('change', 'showFormInfo("#AttributeCategory")');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
    </ul>
</div>
<script type="text/javascript">

var formInfoValues = new Array();
formInfoValues['md5'] = "You are encouraged to use filename|md5 instead. <br/>A checksum in md5 format, only use this if you don't know the correct filename.";
formInfoValues['sha1'] = "You are encouraged to use filename|sha1 instead. <br/>A checksum in sha1 format, only use this if you don't know the correct filename.";
formInfoValues['filename'] = "filename";
formInfoValues['filename|md5'] = "A filename and an md5 hash separated by a | (no spaces).";
formInfoValues['filename|sha1'] = "A filename and an sha1 hash separated by a | (no spaces).";
formInfoValues['ip-src'] = "A source IP address from an attacker.";
formInfoValues['ip-dst'] = "A destination IP address of an attacker or C&C server. <br/>Also set the IDS flag on when this IP is hardcoded in malware.";
formInfoValues['hostname'] = "A full host/dnsname of an attacker. <br/>Also set the IDS flag on when this hostname is hardcoded in malware.";
formInfoValues['domain'] = "A domain name used in the malware. <br/>Use this instead of hostname when the upper domain is <br/>important or can be used to create links between events.";
formInfoValues['email-src'] = "The email address (or domainname) used to send the malware.";
formInfoValues['email-dst'] = "A recipient email address that is not related to your constituency.";
formInfoValues['email-subject'] = "The subject of the email.";
formInfoValues['email-attachment'] = "File name of the email attachment.";
formInfoValues['url'] = "url";
formInfoValues['user-agent'] = "The user-agent used by the malware.";
formInfoValues['regkey'] = "regkey";
formInfoValues['regkey|value'] = "regkey|value";
formInfoValues['AS'] = "The autonomous system";
formInfoValues['snort'] = "An IDS rule in Snort rule-format. <br/>This rule will be automatically rewritten in the NIDS exports.";
formInfoValues['pattern-in-file'] = "pattern-in-file";
formInfoValues['pattern-in-memory'] = "pattern-in-memory";
formInfoValues['vulnerability'] = "A reference to a vulnerability.";
formInfoValues['attachment'] = "Please upload files using the <em>Upload Attachment</em> button.";
formInfoValues['malware-sample'] = "Please upload files using the <em>Upload Attachment</em> button.";
formInfoValues['other'] = "other";

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table

	// show it again
	$(idDiv).fadeIn('slow');
}

// hide the formInfo things
$('#AttributeTypeDiv').hide();
$('#AttributeCategoryDiv').hide();


</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts ?>
