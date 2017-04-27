<div class="confirmation">
<legend>ZeroMQ Server Status</legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
	<?php if (isset($time)): ?>
		<p><b>Start time</b>: <?php echo h($time); ?><br />
		<b>Settings read at</b>: <?php echo h($time2); ?><br />
		<b>Events processed</b>: <?php echo h($events); ?></p>
	<?php else: ?>
		<p>The ZeroMQ server is unreachable.</p>
	<?php endif; ?>
		<span role="button" tabindex="0" aria-label="Cancel prompt" title="Cancel prompt" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">OK</span>
	</div>
</div>
