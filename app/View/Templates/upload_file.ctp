<?php
if ($batch == 'yes') {
	$buttonText = 'Upload Files';
	$multiple = true;
} else {
	$multiple = false;
	if (isset($filenames)) {
		$buttonText = 'Replace File';
	} else {
		$buttonText = 'Upload File';
	}
}
?>
<div style="display:none;">
	<?php
		echo $this->Form->create('', array('id' => 'upload_' . $element_id, 'type' => 'file'));
		echo $this->Form->input('file.', array('id' => 'upload_' . $element_id . '_file', 'type' => 'file', 'label' => false, 'multiple' => $multiple, 'onChange' => 'this.form.submit()'));
		echo $this->Form->end();
	?>
</div>
<span id="fileUploadButton_<?php echo $element_id; ?>"  role="button" tabindex="0" aria-label="<?php echo $buttonText; ?>" title="<?php echo $buttonText; ?>" class="btn btn-primary" onClick="templateFileUploadTriggerBrowse('<?php echo $element_id; ?>');"><?php echo $buttonText; ?></span>
<script type="text/javascript">
$(document).ready(function() {
	<?php if (isset($filenames)): ?>
	var fileArray = JSON.parse('<?php echo $fileArray;?>');
	templateFileHiddenAdd(fileArray, '<?php echo $element_id; ?>', '<?php echo $batch; ?>');
	showMessage('<?php echo $upload_error ? 'fail' : 'success'; ?>', '<?php echo $result; ?>', 'iframe');
	<?php endif; ?>
});

</script>
