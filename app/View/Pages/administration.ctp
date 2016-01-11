<?php
if (!$isSiteAdmin) exit();
?>
<div class="actions">
	<ol class="nav nav-list">

	</ol>
</div>
<div class="index">
<h2>Administrative actions</h2>
<ul>
<li><a href="<?php echo $baseurl;?>/events/reportValidationIssuesEvents">reportValidationIssuesEvents</a></li>
<li><a href="<?php echo $baseurl;?>/attributes/reportValidationIssuesAttributes">reportValidationIssuesAttributes</a></li>
<li><?php echo $this->Form->postLink('generateCount', $baseurl . '/events/generateCount');?> (Events need to have no validation issues)</li>
<li><?php echo $this->Form->postLink('generateCorrelation', $baseurl . '/attributes/generateCorrelation');?></li>
<li><a href="<?php echo $baseurl;?>/users/verifyGPG">Verify GPG keys</a> (Check whether every user's GPG key is usable)</li>
<li><?php echo $this->Form->postLink('Extend Organization length', $baseurl . '/servers/updateDatabase/extendServerOrganizationLength');?> (Hotfix 2.3.57: Increase the max length of the organization field when adding a new server connection.)</li>
<li><?php echo $this->Form->postLink('Convert log fields to text', $baseurl . '/servers/updateDatabase/convertLogFieldsToText');?> (Hotfix 2.3.78: Some of the log fields that were varchar(255) ended up truncating the data. This function will change them to "text")</li>
<li><?php echo $this->Form->postLink('Fix duplicate UUIDs', $baseurl . '/servers/pruneDuplicateUUIDs');?> (Hotfix 2.3.107: it was previously possible to get duplicate attribute UUIDs in the database, this script will remove all duplicates and ensure that duplicates will not be entered into the database in the future.)</li>
<li><?php echo $this->Form->postLink('Remove dupicate events (with the same UUID)', $baseurl . '/servers/removeDuplicateEvents');?> (Hotfix 2.3.115: In some rare situations it could occur that a duplicate of an event was created on an instance, with the exact same uuid. This action will remove any such duplicates and make sure that this cannot happen again.)</li>
<li><?php echo $this->Form->postLink('Prune orphaned attributes', $baseurl . '/attributes/pruneOrphanedAttributes');?> (In some rare occasions it can happen that you end up with some attributes in your database that do not belong to an event - for example during a race condition between an event insert and a delete. This tool will collect and delete any such orphaned attributes. If you ever run into an issue where you cannot add an attribute with a specific valid value, this is probably the reason.)</li>
<li><?php echo $this->Form->postLink('Clean regex table of potentially malicious entries', $baseurl . '/regexp/cleanRegexModifiers');?> (Hotfix 2.3.160: Prior to this version it was possible for a user/admin with Regex permission to create a malicious regular expression that could be used to execute arbitrary code. Since this version it is no longer possible to input such expressions, but already existing malicious entries still have to be cleaned using this tool.)</li>
<li><?php echo $this->Form->postLink('Remove url type attribute sanitisation', $baseurl . '/attributes/updateAttributeValues/urlSanitisation');?> (Hotfix 2.3.173: Sanitised URLs can cause issues with the NIDS exports and as of this version attributes will be modified on entry to correct this. To correct existing entries, run this script.)</li>
<li><?php echo $this->Form->postLink('Upgrade to 2.4', $baseurl . '/servers/upgrade2324');?> (This script will make the final changes to the database to bring it up to speed with 2.4)</li>
<li><?php echo $this->Form->postLink('BETA UPDATES', $baseurl . '/servers/updateDatabase/24betaupdates');?> (This script will update your db from an earlier version of the beta)</li>
<li><?php echo $this->Form->postLink('Index tables', $baseurl . '/servers/updateDatabase/indexTables');?> (This script will create indeces for all of the tables in MISP (other than primary keys))</li>
<li><?php echo $this->Form->postLink('Fix non-empty sharing group IDs', $baseurl . '/servers/updateDatabase/fixNonEmptySharingGroupID');?> (This script will change the sharing_group_id to 0 in all non sharing group setting events and attributes))</li>
</ul>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>