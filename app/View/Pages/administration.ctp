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
</ul>
</div>