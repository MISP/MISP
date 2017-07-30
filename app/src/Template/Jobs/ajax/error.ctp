<div class="confirmation">
	<legend>Background Job Error Browser</legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<div>
			<?php
				if (!empty($response)):
					$stackTrace = "";
					if (isset($response['backtrace']) && !empty($response['backtrace'])) {
						foreach ($response['backtrace'] as $line) {
							$stackTrace .= h($line) . '</br>';
						}
					}
					foreach ($fields as $name => $content):
						if (isset($response[$content])):
			?>
							<span class="bold red"><?php echo h($name); ?></span>: <?php echo h($response[$content]); ?><br />
			<?php
						endif;
					endforeach;
			?>
					<a href="#" id="show_stacktrace">(Click to show stack trace)</a>
					<a href="#" id="hide_stacktrace" class="hidden">(Click to hide stack trace)</a>
					<div id="stacktrace" class="hidden">
						<?php echo $stackTrace; ?>
					</div>
			<?php
				else:
			?>
				<p>No error data found. Generally job error data is purged from Redis after 24 hours, however, you can still view the errors in the log files in "/app/tmp/logs".</p>
			<?php
				endif;
			?>
		</div>
		<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPopoverForm();">Close</span>
	</div>
</div>
<script type="text/javascript">
	$("#show_stacktrace").click(function() {
		$("#show_stacktrace").hide();
		$("#hide_stacktrace").show();
		$("#stacktrace").show();
	});
	$("#hide_stacktrace").click(function() {
		$("#hide_stacktrace").hide();
		$("#show_stacktrace").show();
		$("#stacktrace").hide();
	});
	$(document).ready(function() {
		resizePopoverBody();
	});

	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
