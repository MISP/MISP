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
	
	<div style="clear:both;"></div>
	<div id="accordion1" style="width:50%;float:left;">
		<h3>Select text for further analysis <button id="graspSelectedText" class="btn btn-primary" style="display:none;margin-left:5px;">Add Selected Text</button></h3>
		<div id="textToSelect" class="raisedbox" onmouseup="GetSelectedText ()">
			<div id="fileContent" style="display:none;">
				<p>	
				<?php
					if($file_uploaded == "1")
					{
						echo h(nl2br($file_content));
					}
				?>
			</p>
			</div>
			
			<table id="individualLines"><tbody></tbody></table>
		</div>
	</div>
	
	<div id="accordion2" style="width:50%;float:right;">
		<h3>Selected Text<button id="clearSelectedText" class="btn btn-primary" style="display:none;margin-left:5px;">Clear Selected Text</button><button id="saveText" class="btn btn-primary" style="display:none;margin-left:5px;">Process Selected Text</button></h3>
		<div id="selectedText" class="raisedbox" ></div>
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
var linesArray = [];
$("#accordion1").accordion({
	heightStyle: "content" 
    })
$("#accordion2").accordion({
	  heightStyle: "content" 
    })
if(afterUpload == 1)
{
	$('#afterUpload').show();
	linesArray = $("#fileContent").text().trim().split("<br />");
	$("#fileContent").empty();
	for(var i=0; i<linesArray.length;i++)
	{
		$('#individualLines').append('<tr><td>'+encodeHTML(linesArray[i])+'</td></tr>');
	}
}
$('#individualLines tr').click(function(e){
        var cell = $(e.target).get(0);
        var tr = $(this);
        selText = tr.text();
		if(!this.hilite){
			//unhighlight();
			this.origColor=this.style.backgroundColor;
			this.style.backgroundColor='#BCD4EC';
			this.hilite = true;
		   }
		   else{
			this.style.backgroundColor=this.origColor;
			this.hilite = false;
		   }
		   if (selText !== "") {
				$('#graspSelectedText').show();
				$('#clearSelectedText').show();
				$('#saveText').show();
			}
			else
			{
				$('#graspSelectedText').hide();
				$('#clearSelectedText').hide();
				$('#saveText').hide()
			}
    });
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
	
}
$('#graspSelectedText').on('click',function(){
	$('#selectedText').append(selText.replace(/(?:\r\n|\r|\n)/g, '<br>'));
	$('#selectedText').append('<br>')
})
$('#clearSelectedText').on('click',function(){
	$('#selectedText').empty();
})
function encodeHTML(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}
</script>
