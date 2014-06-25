<?php //debug($element_id); ?>
<div id="populate_template_info" class="templateTableRow templateTableRow80">
	<div class="templateElementHeader" style="width:100%; position:relative;">
		<div class="templateGlass"></div>
		<div class ="templateElementHeaderText"><?php echo h($element['name']); ?></div>
	</div>
	<div id="populate_template_info_body" class="populate_template_div_body">
		<div class="left">Description:</div>
		<div class="right"><?php echo h($element['description']); ?></div><br />
		<div class="left">File<?php if ($element['batch']) echo 's'?>:</div>
		<div class="right" id ="filenames_<?php echo $element_id; ?>">&nbsp;</div><br />
		<div class="input file" id="file_container_<?php echo $element_id;?>">
		</div>
	</div>
</div>
<script type="text/javascript">
var i_<?php echo $element_id; ?> = 0;
var element_id_<?php echo $element_id; ?> = <?php echo $element_id; ?>;
var batch_<?php echo $element_id; ?> = "<?php echo ($element['batch'] ? 'yes' : 'no'); ?>"; 

$(document).ready(function() {
	populateTemplateCreateFileUpload(element_id_<?php echo $element_id; ?>, i_<?php echo $element_id; ?>, batch_<?php echo $element_id; ?>);
}); 

</script>