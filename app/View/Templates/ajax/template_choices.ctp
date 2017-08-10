<div class="popover_choice">
	<legend><?php echo __('Choose element type'); ?></legend>
	<div class="popover_choice_main" id ="popover_choice_main">
		<?php foreach ($templates as $k => $template): ?>
			<div role="button" tabindex="0" aria-label="<?php echo h($template['Template']['description']); ?>" class="templateChoiceButton" style="width:100%;" title="<?php echo h($template['Template']['description']); ?>" onClick="document.location.href ='<?php echo $baseurl;?>/templates/populateEventFromTemplate/<?php echo h($template['Template']['id']);?>/<?php echo h($id); ?>'">
				<div style="float:left;">
				<?php
					$imgRelativePath = 'orgs' . DS . h($template['Template']['org']) . '.png';
					$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
					if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($template['Template']['org']) . '.png', array('alt' => h($template['Template']['org']), 'title' => h($template['Template']['org']), 'style' => 'width:24px; height:24px'));
					else echo $this->Html->tag('span', h($template['Template']['org']), array('class' => 'welcome', 'style' => 'float:left;'));
				?>
				</div>
				<div><span style="position:relative;left:-12px;"><?php echo h($template['Template']['name']);?>&nbsp;</span></div>
			</div>
		<?php endforeach; ?>
	</div>
	<div role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();">Cancel</div>
</div>
<script type="text/javascript">
$(document).ready(function() {
	resizePopoverBody();
});

$(window).resize(function() {
	resizePopoverBody();
});
</script>
