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
<li><a href="/events/reportValidationIssuesAttributes">reportValidationIssuesAttributes</a></li>
<li><a href="/events/generateCount">generateCount</a> (Events need to have no validation issues)</li>
<li><a href="/events/generateCorrelation">generateCorrelation</a></li>
<li><a href="/events/generateLocked">generateLocked</a> (This is for upgrading to hotfix 2.1.8 or later, all events that were created by an organisation that doesn't have users on this instance, or only has a single sync user will have their locked setting set to 1)</li>
</ul>
</div>