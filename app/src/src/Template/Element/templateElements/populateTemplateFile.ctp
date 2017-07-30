<div id="populate_template_info">
	<div id="populate_template_info_body" class="populate_template_div_body">
		<div class="left-inverse">Field:</div>
		<div class="right-inverse">
		<?php echo h($element['name']);
		if ($element['mandatory']): ?>
		<span class="template_mandatory">(*)</span>
		<?php endif;?>
		</div><br />
		<div class="left">Description:</div>
		<div class="right"><?php echo h($element['description']); ?></div><br />
		<div class="left" style="height:26px;">File<?php if ($element['batch']) echo 's'?>:</div>
		<div class="right" id ="filenames_<?php echo $element_id; ?>" style="height:26px;">
			&nbsp;
		</div><br />
		<div class="input file" id="file_container_<?php echo $element_id;?>">
		</div>
		<iframe id="iframe_<?php echo $element_id; ?>" src="/templates/uploadFile/<?php echo $element_id; ?>/<?php echo ($element['batch'] ? 'yes' : 'no'); ?>" style="border:0px;height:30px;width:100%;overflow:hidden;" scrolling="no"></iframe>
		<div class="error-message populateTemplateErrorField" <?php if (!isset($errors[$element_id])) echo 'style="display:none;"';?>>
			<?php echo 'Error: ' . $errors[$element_id]; ?>
		</div>
	</div>
</div>
<script type="text/javascript">
	var i_<?php echo h($element_id); ?> = 0;
	var element_id_<?php echo h($element_id); ?> = <?php echo h($element_id); ?>;
	var batch_<?php echo h($element_id); ?> = "<?php echo ($element['batch'] ? 'yes' : 'no'); ?>";
</script>
