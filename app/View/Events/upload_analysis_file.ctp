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
	<div id="accordion1" style="width:40%;float:left;padding:5px;">
		<h3>Select text for further analysis <button id="graspSelectedText" class="btn btn-primary" style="display:none;margin-left:5px;">Add Selected Text</button></h3>
		<div id="textToSelect" class="raisedbox">
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
	
	<div id="accordion2" style="width:55%;float:right;">
		<h3>Selected Text<button id="clearSelectedText" class="btn btn-primary" style="display:none;margin-left:5px;">Clear Selected Text</button><button id="saveText" class="btn btn-primary" style="display:none;margin-left:5px;">Process Selected Text</button></h3>
		<div id="selectedText" class="" >
		<table id="individualSelectedLines" class="selectedLines">
			<tbody>
					<thead>
						<th>Filepath</th>
						<th>File Size</th>
						<th>Activity Type</th>
						<th>Time Accessed</th>
						<th>Permissions</th>
						<th>Clear</th>
					</thead>
			</tbody>
		</table>
		</div>
	</div>
	
	<div style="clear:both;"></div>
	</div>
</div>


<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addSTIX'));
?>
<style>
	.selectedLines td, 
	.selectedLines th {
		border:solid 2px #0044cc;
	}
	.selectedLines
	{
		width: 100%;
	}
</style>
<script>
var afterUpload = "<?php echo $file_uploaded; ?>";
var selText = clearText= '';
var linesArray = [];
var rowSelected;
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
        rowSelected = $(this);
        selText = rowSelected.text();
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

$('#graspSelectedText').on('click',function(){
	
	processString(selText)
	// $('#selectedText').append(selText.replace(/(?:\r\n|\r|\n)/g, '<br>'));
	// $('#selectedText').append('<br>')
})
$('#clearSelectedText').on('click',function(){
	$('#selectedText').empty();
})
function encodeHTML(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}
function processString(text)
{
	var time_accessed = "";
	var size =activity_type = permissions = file_path = activity = time_accessed = "";
	//full date and time expression
	var Regx1 = /(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s(\d\d?).+?(\d\d\d\d)\s([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]/;
	//time expressions
	var Regx2 = new RegExp("([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]");
	var arr = Regx1.exec(text);
	if(arr != null)
	{
		time_accessed = arr[0];
		text = text.replace(arr[0],'').trim();
	}
	
	text = text.replace(/[\n\r]/g, '').trim();
	seperate_analysis = text.split(/[  ]+/);
	size = seperate_analysis[0];
	activity_type = seperate_analysis[1];
	if(activity_type.includes('a'))
	{
		activity = "Accessed";
	}
	if(activity_type.includes('b'))
	{
		activity += (activity != '')?',':'';
		activity += "Created";
	}
	if(activity_type.includes('c'))
	{
		activity += (activity != '')?',':'';
		activity += "Changed";
	}
	if(activity_type.includes('m'))
	{
		activity += (activity != '')?',':'';
		activity += "Modified";
	}
	
	permissions = seperate_analysis[2];
	filepath = seperate_analysis[6]
	if(seperate_analysis[7])
	{
		filepath += seperate_analysis[7];
	}
	$('#individualSelectedLines').append('<tr><td>'+filepath+'</td><td>'+size+'</td><td>'+activity+'</td><td>'+time_accessed+'</td><td>'+permissions+'</td><td><span class="icon-trash clearRow" style="cursor:pointer;"></span></td></tr>');		
}
$(document).on('click', '.clearRow' ,function(e) { 
	$(this).closest('tr').remove() 
});
</script>
