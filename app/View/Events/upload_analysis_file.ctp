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
		<div id="accordion1" style="">
			<h3>Select text for further analysis <button id="graspSelectedText" class="btn btn-primary" style="margin-left:5px;">Process Selected Entries</button></h3>
			<div id="textToSelect" class="raisedbox noselect">
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
				<table id="individualLines" class="selectedLines">
					<thead>
						<th>Select</th>
						<th>Filepath</th>
						<th>File Size</th>
						<th>Activity Type</th>
						<th>Time Accessed</th>
						<th>Permissions</th>
						
					</thead>
					<tbody></tbody>
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
	.noselect {
    cursor: default;
    -webkit-touch-callout: none;
    -webkit-user-select: none;
    -khtml-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    user-select: none;
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
		processString(linesArray[i]);
		
	}
}

$('#graspSelectedText').on('click',function(){
	$('#individualLines').find('tr').each(function () {
        var row = $(this);
			if (row.find('input[type="checkbox"]').is(':checked')) {
			row.find("td:first").remove();
            $('#individualSelectedLines').append(row);	
        }
		$(this).remove();
    });
		processString(selText)
})


function processString(text)
{
	console.log(text)
	var time_accessed = "";
	var size =activity_type = permissions = file_path = activity = time_accessed = "";
	//full date and time expression
	var Regx1 = /(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s(\d\d?).+?(\d\d\d\d)\s([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]/;
	//time expressions
	var Regx2 = new RegExp("([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]");
	var arr = Regx1.exec(text);
	if(Regx2.exec(text) != null)
	{
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
		$("#individualLines").find('tbody')
			.append($('<tr>')
				.append($('<td>').html('<input type="checkbox" class="select"></input>'))
				.append($('<td>').text(filepath))
				.append($('<td>').text(size))
				.append($('<td>').text(activity))
				.append($('<td>').text(time_accessed))
				.append($('<td>').text(permissions))
				
				
		);
	}
	
		
}
function unhighlight(){
 var fileTable = document.getElementById('individualLines');
 for (var i=0;i < fileTable.rows.length;i++){
   var row = fileTable.rows[i];
   row.style.backgroundColor='transparent';
   row.hilite = false;
 }
}


</script>
