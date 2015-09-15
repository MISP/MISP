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
<li><a href="/events/reportValidationIssuesEvents">reportValidationIssuesEvents</a></li>
<li><a href="/attributes/reportValidationIssuesAttributes">reportValidationIssuesAttributes</a></li>
<li><a href="/events/generateCount">generateCount</a> (Events need to have no validation issues)</li>
<li><a href="/attributes/generateCorrelation">generateCorrelation</a></li>
<li><a href="/events/generateLocked">generateLocked</a> (This is for upgrading to hotfix 2.1.8 or later, all events that were created by an organisation that doesn't have users on this instance, or only has a single sync user will have their locked setting set to 1)</li>
<li><a href="/users/verifyGPG">Verify GPG keys</a> (Check whether every user's GPG key is usable)</li>
<li><a href="/events/generateThreatLevelFromRisk">Upgrade Risk to Threat Level</a> (As of version 2.2 the risk field is replaced by Threat Level. This script will convert all values in risk to threat level.)</li>
<li><a href="/servers/updateDatabase/extendServerOrganizationLength">Extend Organization length</a> (Hotfix 2.3.57: Increase the max length of the organization field when adding a new server connection.)</li>
<li><a href="/servers/updateDatabase/convertLogFieldsToText">Convert log fields to text</a> (Hotfix 2.3.78: Some of the log fields that were varchar(255) ended up truncating the data. This function will change them to "text")</li>
<li><a href="/servers/pruneDuplicateUUIDs">Fix duplicate UUIDs</a> (Hotfix 2.3.107: it was previously possible to get duplicate attribute UUIDs in the database, this script will remove all duplicates and ensure that duplicates will not be entered into the database in the future.)</li>
<li><a href="/servers/removeDuplicateEvents">Remove dupicate events (with the same UUID)</a> (Hotfix 2.3.115: In some rare situations it could occur that a duplicate of an event was created on an instance, with the exact same uuid. This action will remove any such duplicates and make sure that this cannot happen again.)</li>
<li><a href="/attributes/pruneOrphanedAttributes">Prune orphaned attributes</a> (In some rare occasions it can happen that you end up with some attributes in your database that do not belong to an event - for example during a race condition between an event insert and a delete. This tool will collect and delete any such orphaned attributes. If you ever run into an issue where you cannot add an attribute with a specific valid value, this is probably the reason.)</li>
</ul>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>