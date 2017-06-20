<div class="popover_choice">
	<legend><?php echo __('Choose the key that you would like to use'); ?></legend>
	<div class="popover_choice_main" id ="popover_choice_main">
		<table style="width:100%;">
			<tr>
				<th style="padding-left:10px; text-align:left;">Key ID</th>
				<th style="text-align:left;">Creation date</th>
				<th style="padding-right:10px; text-align:left;">Associated E-mail addresses</th>
			</tr>
		<?php foreach ($keys as $k => $key): ?>
			<tr style="border-bottom:1px solid black;" class="templateChoiceButton">
				<td role="button" tabindex="0" aria-label="Select pgp key" style="padding-left:10px; text-align:left;width:20%;" title="<?php echo h($key['fingerprint']); ?>" onClick="pgpChoiceSelect('<?php echo h($key['uri']); ?>')"><?php echo h($key['key_id']); ?></td>
				<td style="text-align:left;width:20%;" title="<?php echo h($key['fingerprint']); ?>" onClick="pgpChoiceSelect('<?php echo h($key['uri']); ?>')"><?php echo h($key['date']); ?></td>
				<td style="padding-right:10px; text-align:left;width:60%;" title="<?php echo h($key['fingerprint']); ?>" onClick="pgpChoiceSelect('<?php echo h($key['uri']); ?>')">
					<span class="bold">
						<?php echo h($key['fingerprint']); ?>
					</span><br />
				<?php echo nl2br(h($key['address'])); ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</table>
	</div>
	<div role="button" tabindex="0" aria-label="Cancel" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
<script type="text/javascript">
	$(document).ready(function() {
		resizePopoverBody();
	});

	$(window).resize(function() {
		resizePopoverBody();
	});
</script>
