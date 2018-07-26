<div class="events form">
<?php
  echo $this->Form->create('Event', array('type' => 'file'));
?>
	<fieldset>
		<legend><?php echo __('Import analysis file'); ?></legend>
<?php
	echo $this->Form->input('analysis_file', array(
			'label' => '<b>Analysis file</b>',
			'type' => 'file',
	));
	?>
		<div class="input clear"></div>
	<?php
	// echo $this->Form->input('publish', array(
	// 		'checked' => false,
	// 		'label' => __('Publish imported events'),
	// ));
?>
	</fieldset>
<?php
	echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
<div id="afterUpload" style="display:none;">
	<button id="graspSelectedText" class="actions" style="display:none;">Add Selected Text</button>
	<button id="clearSelectedText" class="actions" style="display:none;">Clear Selected Text</button>
	<div style="clear:both;"></div>
	<div id="textToSelect" class="raisedbox" onmouseup="GetSelectedText ()" style="width:40%; height:100%;float:left;">	
			<?php
				if($file_uploaded == "1")
				{
					echo nl2br($file_content);
				}
			?>
	</div>
	<div id="selectedText" class="raisedbox" style="width:45%; height:100%;float:right;">
		
	</div>
	<div style="clear:both;"></div>
	</div>
</div>


<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addSTIX'));
?>
<script>
var afterUpload = "<?php echo $file_uploaded; ?>";
var selText = '';
if(afterUpload == 1)
{
	$('#afterUpload').show();
}
function GetSelectedText () {
	selText = '';
	if (window.getSelection) {
		if (document.activeElement && 
				(document.activeElement.tagName.toLowerCase () == "textarea" || 
				 document.activeElement.tagName.toLowerCase () == "input")) 
		{
			var text = document.activeElement.value;
			selText = text.substring (document.activeElement.selectionStart, 
									  document.activeElement.selectionEnd);
		}
		else {
			var selRange = window.getSelection ();
			selText = selRange.toString ();
		}
	}
	else {
		if (document.selection.createRange) {
			var range = document.selection.createRange ();
			selText = range.text;
		}
	}
	if (selText !== "") {
		$('#graspSelectedText').show();
		$('#clearSelectedText').show();
	}
	else
	{
		$('#graspSelectedText').hide();
		$('#clearSelectedText').hide();
	}
}
$('#graspSelectedText').on('click',function(){
	$('#selectedText').append(selText.replace(/(?:\r\n|\r|\n)/g, '<br>'));
	$('#selectedText').append('<br>')
})
$('#clearSelectedText').on('click',function(){
	$('#selectedText').empty();
})
</script>
<style>
	.raisedbox { 
	padding: 10px;
    border: 1px solid #77aaff;
	box-shadow:  -1px 1px #77aaff,
		 -2px 2px #77aaff,
		 -3px 3px #77aaff,
		 -4px 4px #77aaff,
		 -5px 5px #77aaff;
	}

</style>