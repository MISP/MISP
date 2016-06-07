<div class="feed form">
<?php echo $this->Form->create('Feed');?>
	<fieldset>
		<legend>Add MISP Feed</legend>
		<p>Add a new MISP feed source.</p>
	<?php
		echo $this->Form->input('enabled', array());
		echo $this->Form->input('name', array(
				'div' => 'input clear',
				'placeholder' => 'Feed name',
				'class' => 'form-control span6',
		));
		echo $this->Form->input('provider', array(
				'div' => 'input clear',
				'placeholder' => 'Name of the content provider',
				'class' => 'form-control span6'
		));
		echo $this->Form->input('url', array(
				'div' => 'input clear',
				'placeholder' => 'URL of the feed',
				'class' => 'form-control span6'
		));
		echo $this->Form->input('distribution', array(
				'options' => array($distributionLevels),
				'div' => 'input clear',
				'label' => 'Distribution',
				'selected' => 3,
		));
	?>
		<div id="SGContainer" style="display:none;">
	<?php
		if (!empty($sharingGroups)) {
			echo $this->Form->input('sharing_group_id', array(
					'options' => array($sharingGroups),
					'label' => 'Sharing Group',
			));
		}
	?>
		</div>
		<div class="input clear"></div>
	<?php
		echo $this->Form->input('tag_id', array(
				'options' => $tags,
				'label' => 'Default Tag',
				'selected' => 0,
		));
		echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
	?>
	</fieldset>
    <b>Filter rules:</b><br />
    <span id="pull_tags_OR" style="display:none;">Events with the following tags allowed: <span id="pull_tags_OR_text" style="color:green;"></span><br /></span>
    <span id="pull_tags_NOT" style="display:none;">Events with the following tags blocked: <span id="pull_tags_NOT_text" style="color:red;"></span><br /></span>
    <span id="pull_orgs_OR" style="display:none;">Events with the following organisations allowed: <span id="pull_orgs_OR_text" style="color:green;"></span><br /></span>
    <span id="pull_orgs_NOT" style="display:none;">Events with the following organisations blocked: <span id="pull_orgs_NOT_text" style="color:red;"></span><br /></span>
	<span id="pull_modify"  class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;">Modify</span><br /><br />
	<?php
	echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
	?>
	<div id="hiddenRuleForms">
		<?php echo $this->element('serverRuleElements/pull'); ?>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'add'));
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


var rules = {"pull": {"tags": {"OR":[], "NOT":[]}, "orgs": {"OR":[], "NOT":[]}}};
var validOptions = ['pull'];
var validFields = ['tags', 'orgs'];
var modelContext = 'Feed';

$(document).ready(function() {
	feedDistributionChange();
	$("#pull_modify").click(function() {
		serverRuleFormActivate('pull');
	});
	$("#FeedDistribution").change(function() {
		feedDistributionChange();
	});
});
</script>
